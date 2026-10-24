//! Message classification shared by every log-line source (auth.log, syslog,
//! cron logs, journald). Given a program name and message text it recovers
//! the normalized [`EventKind`], the acting user and structured fields.
//!
//! Dispatch is by program first, so at most a handful of regexes run per line.

use std::sync::LazyLock;

use regex::Regex;

use crate::event::EventKind;

/// The meaning recovered from one log message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    /// Normalized kind.
    pub kind: EventKind,
    /// Acting user, if any.
    pub user: Option<String>,
    /// Human-readable description.
    pub description: String,
    /// Structured fields.
    pub fields: Vec<(&'static str, String)>,
}

impl Classified {
    fn new(kind: EventKind, user: Option<&str>, description: String) -> Self {
        Classified {
            kind,
            user: user.filter(|u| !u.is_empty()).map(str::to_string),
            description,
            fields: Vec::new(),
        }
    }

    fn field(mut self, key: &'static str, value: impl Into<String>) -> Self {
        let v = value.into();
        if !v.is_empty() {
            self.fields.push((key, v));
        }
        self
    }
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("built-in regex must compile")
}

static SSH_ACCEPTED: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?::\s*(?P<key>.+))?$",
    )
});
static SSH_FAILED: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)",
    )
});
static SSH_INVALID: LazyLock<Regex> =
    LazyLock::new(|| re(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+?)(?: port (?P<port>\d+))?$"));
static SSH_DISCONNECT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^(?:Disconnected from|Received disconnect from|Connection closed by)(?: (?:invalid |authenticating )?user (?P<user>\S*))? (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)",
    )
});
static PAM_SESSION: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^pam_unix\((?P<svc>[^:)]+):session\): session (?P<state>opened|closed) for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?",
    )
});
static PAM_AUTH_FAIL: LazyLock<Regex> = LazyLock::new(|| {
    re(r"^pam_unix\((?P<svc>[^:)]+):auth\): authentication failure;(?P<rest>.*)$")
});
static PAM_PASSWD: LazyLock<Regex> = LazyLock::new(|| {
    re(r"^pam_unix\((?P<svc>[^:)]+):chauthtok\): password changed for (?P<user>\S+)")
});
static PASSWD_CHANGED_BY: LazyLock<Regex> =
    LazyLock::new(|| re(r"^password for '(?P<user>[^']+)' changed by '(?P<by>[^']*)'"));
static NEW_USER: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>[^,]+)(?:, from=(?P<from>\S+))?",
    )
});
static NEW_GROUP: LazyLock<Regex> = LazyLock::new(|| {
    re(r"^(?:new group|group added to /etc/group): name=(?P<name>[^,]+), GID=(?P<gid>\d+)")
});
static ADD_TO_GROUP: LazyLock<Regex> =
    LazyLock::new(|| re(r"^add '(?P<user>[^']+)' to (?P<shadow>shadow )?group '(?P<group>[^']+)'"));
static DELETE_USER: LazyLock<Regex> = LazyLock::new(|| re(r"^delete user '(?P<user>[^']+)'"));
static CHANGE_USER: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(?:change|lock|unlock) user '(?P<user>[^']+)'"));
static SU_TO: LazyLock<Regex> = LazyLock::new(|| {
    re(r"^(?P<failed>FAILED SU )?\(to (?P<target>[^)]+)\) (?P<user>\S+) on (?P<tty>\S+)")
});
static SU_SUCCESS: LazyLock<Regex> =
    LazyLock::new(|| re(r"^Successful su for (?P<target>\S+) by (?P<user>\S+)"));
static LOGIND_NEW: LazyLock<Regex> =
    LazyLock::new(|| re(r"^New session (?P<id>\S+) of user (?P<user>[^\s.]+)\.?"));
static LOGIND_REMOVED: LazyLock<Regex> =
    LazyLock::new(|| re(r"^Removed session (?P<id>[^\s.]+)\.?"));
static CRON_CMD: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)$"));
static CRON_RELOAD: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\((?P<user>[^)]+)\) RELOAD \((?P<target>[^)]*)\)"));
static CRONTAB_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^\((?P<user>[^)]+)\) (?P<action>REPLACE|BEGIN EDIT|END EDIT|DELETE|LIST) \((?P<target>[^)]*)\)",
    )
});
static SYSTEMD_UNIT: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(?P<verb>Started|Stopped) (?P<unit>.+?)\.?$"));
static FAILED_LOGIN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^FAILED LOGIN \(\d+\) on '(?P<tty>[^']*)'(?: from '(?P<host>[^']*)')? FOR '(?P<user>[^']*)'",
    )
});

/// Normalizes a syslog tag: strips a path prefix and lowercases.
pub fn normalize_program(program: &str) -> String {
    program
        .rsplit('/')
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase()
}

/// Classifies one message. `program` is the syslog tag / journald identifier.
pub fn classify(program: Option<&str>, message: &str) -> Classified {
    let message = message.trim();
    let prog = program.map(normalize_program).unwrap_or_default();
    let specific = match prog.as_str() {
        "sshd" | "sshd-session" | "sshd-auth" => classify_sshd(message),
        "sudo" => classify_sudo(message),
        "su" => classify_su(message),
        "useradd" | "usermod" | "userdel" | "groupadd" | "groupmod" | "groupdel" | "passwd"
        | "chpasswd" | "gpasswd" | "chage" | "adduser" => classify_account(&prog, message),
        "systemd-logind" => classify_logind(message),
        "cron" | "crond" => classify_cron(message),
        "crontab" => classify_crontab(message),
        "systemd" => classify_systemd(message),
        "kernel" if message.starts_with("Linux version") => Some(Classified::new(
            EventKind::Boot,
            None,
            format!("kernel booted: {}", first_words(message, 3)),
        )),
        "login" => classify_login(message),
        _ => None,
    };
    specific
        .or_else(|| classify_pam(message))
        .unwrap_or_else(|| {
            let description = match program {
                Some(p) => format!("{p}: {message}"),
                None => message.to_string(),
            };
            Classified::new(EventKind::LogMessage, None, description)
                .field("program", program.unwrap_or_default())
        })
}

fn first_words(s: &str, n: usize) -> String {
    s.split_whitespace().take(n).collect::<Vec<_>>().join(" ")
}

fn cap<'a>(c: &'a regex::Captures<'_>, name: &str) -> &'a str {
    c.name(name).map_or("", |m| m.as_str())
}

fn classify_sshd(m: &str) -> Option<Classified> {
    if let Some(c) = SSH_ACCEPTED.captures(m) {
        let (user, ip, port, method) = (
            cap(&c, "user"),
            cap(&c, "ip"),
            cap(&c, "port"),
            cap(&c, "method"),
        );
        return Some(
            Classified::new(
                EventKind::SshLoginSuccess,
                Some(user),
                format!("SSH login accepted for {user} from {ip} port {port} ({method})"),
            )
            .field("src_ip", ip)
            .field("src_port", port)
            .field("auth_method", method)
            .field("key", cap(&c, "key")),
        );
    }
    if let Some(c) = SSH_FAILED.captures(m) {
        let (user, ip, method) = (cap(&c, "user"), cap(&c, "ip"), cap(&c, "method"));
        let invalid = c.name("invalid").is_some();
        let who = if invalid {
            format!("invalid user {user}")
        } else {
            user.to_string()
        };
        return Some(
            Classified::new(
                EventKind::SshLoginFailure,
                Some(user),
                format!("SSH {method} authentication failed for {who} from {ip}"),
            )
            .field("src_ip", ip)
            .field("src_port", cap(&c, "port"))
            .field("auth_method", method)
            .field("invalid_user", if invalid { "true" } else { "" }),
        );
    }
    if let Some(c) = SSH_INVALID.captures(m) {
        let (user, ip) = (cap(&c, "user"), cap(&c, "ip"));
        return Some(
            Classified::new(
                EventKind::SshInvalidUser,
                Some(user),
                format!("SSH connection for invalid user {user} from {ip}"),
            )
            .field("src_ip", ip)
            .field("src_port", cap(&c, "port")),
        );
    }
    if let Some(c) = SSH_DISCONNECT.captures(m) {
        let (user, ip, port) = (cap(&c, "user"), cap(&c, "ip"), cap(&c, "port"));
        let suffix = if user.is_empty() {
            String::new()
        } else {
            format!(" (user {user})")
        };
        return Some(
            Classified::new(
                EventKind::SshDisconnect,
                Some(user),
                format!("SSH disconnect from {ip} port {port}{suffix}"),
            )
            .field("src_ip", ip)
            .field("src_port", port),
        );
    }
    None
}

/// Parses `user : [reason ; ]TTY=.. ; PWD=.. ; USER=.. ; COMMAND=..`.
fn classify_sudo(m: &str) -> Option<Classified> {
    let (user, rest) = m.split_once(" : ")?;
    let user = user.trim();
    if user.contains(' ') {
        return None;
    }
    let (prefix, command) = match rest.find("COMMAND=") {
        Some(i) => (&rest[..i], rest[i + "COMMAND=".len()..].trim()),
        None => (rest, ""),
    };
    let mut reason = Vec::new();
    let mut tty = "";
    let mut pwd = "";
    let mut target = "";
    let mut group = "";
    for part in prefix.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('=') {
            Some(("TTY", v)) => tty = v,
            Some(("PWD", v)) => pwd = v,
            Some(("USER", v)) => target = v,
            Some(("GROUP", v)) => group = v,
            Some(("ENV", _)) => {}
            _ => reason.push(part),
        }
    }
    if target.is_empty() && command.is_empty() {
        return None;
    }
    let base = |kind, description| {
        Classified::new(kind, Some(user), description)
            .field("target_user", target)
            .field("tty", tty)
            .field("pwd", pwd)
            .field("command", command)
            .field("target_group", group)
    };
    if reason.is_empty() {
        Some(base(
            EventKind::SudoCommand,
            format!("sudo by {user} as {target}: {command}"),
        ))
    } else {
        let reason = reason.join("; ");
        Some(
            base(
                EventKind::SudoFailure,
                format!("sudo failure for {user} ({reason}): {command}"),
            )
            .field("reason", reason),
        )
    }
}

fn classify_su(m: &str) -> Option<Classified> {
    if let Some(c) = SU_TO.captures(m) {
        let (user, target, tty) = (cap(&c, "user"), cap(&c, "target"), cap(&c, "tty"));
        let failed = c.name("failed").is_some();
        let (kind, verb) = if failed {
            (EventKind::AuthFailure, "failed su")
        } else {
            (EventKind::SuSession, "su")
        };
        return Some(
            Classified::new(
                kind,
                Some(user),
                format!("{verb} from {user} to {target} on {tty}"),
            )
            .field("target_user", target)
            .field("tty", tty)
            .field("service", "su"),
        );
    }
    SU_SUCCESS.captures(m).map(|c| {
        let (user, target) = (cap(&c, "user"), cap(&c, "target"));
        Classified::new(
            EventKind::SuSession,
            Some(user),
            format!("su from {user} to {target}"),
        )
        .field("target_user", target)
        .field("service", "su")
    })
}

fn classify_account(prog: &str, m: &str) -> Option<Classified> {
    if let Some(c) = NEW_USER.captures(m) {
        let name = cap(&c, "name");
        return Some(
            Classified::new(
                EventKind::UserCreated,
                None,
                format!(
                    "user account created: {name} (uid {}, home {}, shell {})",
                    cap(&c, "uid"),
                    cap(&c, "home"),
                    cap(&c, "shell")
                ),
            )
            .field("account", name)
            .field("uid", cap(&c, "uid"))
            .field("gid", cap(&c, "gid"))
            .field("home", cap(&c, "home"))
            .field("shell", cap(&c, "shell"))
            .field("tty", cap(&c, "from")),
        );
    }
    if let Some(c) = NEW_GROUP.captures(m) {
        let name = cap(&c, "name");
        return Some(
            Classified::new(
                EventKind::GroupCreated,
                None,
                format!("group created: {name} (gid {})", cap(&c, "gid")),
            )
            .field("group", name)
            .field("gid", cap(&c, "gid")),
        );
    }
    if let Some(c) = ADD_TO_GROUP.captures(m) {
        let (user, group) = (cap(&c, "user"), cap(&c, "group"));
        let shadow = if c.name("shadow").is_some() {
            "shadow "
        } else {
            ""
        };
        return Some(
            Classified::new(
                EventKind::UserModified,
                None,
                format!("account {user} added to {shadow}group {group}"),
            )
            .field("account", user)
            .field("group", group)
            .field("change", "group_add"),
        );
    }
    if let Some(c) = DELETE_USER.captures(m) {
        let user = cap(&c, "user");
        return Some(
            Classified::new(
                EventKind::UserDeleted,
                None,
                format!("user account deleted: {user}"),
            )
            .field("account", user),
        );
    }
    if let Some(c) = CHANGE_USER.captures(m) {
        let user = cap(&c, "user");
        return Some(
            Classified::new(EventKind::UserModified, None, format!("{prog}: {m}"))
                .field("account", user)
                .field("change", "attributes"),
        );
    }
    if let Some(c) = PASSWD_CHANGED_BY.captures(m) {
        let user = cap(&c, "user");
        return Some(
            Classified::new(
                EventKind::PasswordChanged,
                Some(cap(&c, "by")),
                format!("password changed for {user}"),
            )
            .field("account", user),
        );
    }
    None
}

fn classify_pam(m: &str) -> Option<Classified> {
    if let Some(c) = PAM_SESSION.captures(m) {
        let (svc, user, by) = (cap(&c, "svc"), cap(&c, "user"), cap(&c, "by"));
        let opened = cap(&c, "state") == "opened";
        let kind = if opened {
            EventKind::SessionOpened
        } else {
            EventKind::SessionClosed
        };
        let verb = if opened { "opened" } else { "closed" };
        return Some(
            Classified::new(kind, Some(user), format!("{svc} session {verb} for {user}"))
                .field("service", svc)
                .field("uid", cap(&c, "uid"))
                .field("by", by),
        );
    }
    if let Some(c) = PAM_AUTH_FAIL.captures(m) {
        let svc = cap(&c, "svc");
        let mut user = "";
        let mut rhost = "";
        let mut ruser = "";
        for kv in cap(&c, "rest").split_whitespace() {
            match kv.split_once('=') {
                Some(("user", v)) => user = v,
                Some(("rhost", v)) => rhost = v,
                Some(("ruser", v)) => ruser = v,
                _ => {}
            }
        }
        let from = if rhost.is_empty() {
            String::new()
        } else {
            format!(" from {rhost}")
        };
        return Some(
            Classified::new(
                EventKind::AuthFailure,
                Some(if user.is_empty() { ruser } else { user }),
                format!("PAM authentication failure ({svc}) for {user}{from}"),
            )
            .field("service", svc)
            .field("src_ip", rhost),
        );
    }
    if let Some(c) = PAM_PASSWD.captures(m) {
        let user = cap(&c, "user");
        return Some(
            Classified::new(
                EventKind::PasswordChanged,
                None,
                format!("password changed for {user}"),
            )
            .field("account", user)
            .field("service", cap(&c, "svc")),
        );
    }
    None
}

fn classify_logind(m: &str) -> Option<Classified> {
    if let Some(c) = LOGIND_NEW.captures(m) {
        let user = cap(&c, "user");
        let id = cap(&c, "id");
        return Some(
            Classified::new(
                EventKind::SessionOpened,
                Some(user),
                format!("logind session {id} opened for {user}"),
            )
            .field("service", "logind")
            .field("session", id),
        );
    }
    LOGIND_REMOVED.captures(m).map(|c| {
        let id = cap(&c, "id");
        Classified::new(
            EventKind::SessionClosed,
            None,
            format!("logind session {id} removed"),
        )
        .field("service", "logind")
        .field("session", id)
    })
}

fn classify_cron(m: &str) -> Option<Classified> {
    if let Some(c) = CRON_CMD.captures(m) {
        let (user, cmd) = (cap(&c, "user"), cap(&c, "cmd"));
        return Some(
            Classified::new(
                EventKind::CronCommand,
                Some(user),
                format!("cron ran for {user}: {cmd}"),
            )
            .field("command", cmd),
        );
    }
    CRON_RELOAD.captures(m).map(|c| {
        let (user, target) = (cap(&c, "user"), cap(&c, "target"));
        Classified::new(
            EventKind::CrontabChange,
            Some(user),
            format!("cron reloaded {target}"),
        )
        .field("action", "reload")
        .field("crontab", target)
    })
}

fn classify_crontab(m: &str) -> Option<Classified> {
    let c = CRONTAB_ACTION.captures(m)?;
    let (user, action, target) = (cap(&c, "user"), cap(&c, "action"), cap(&c, "target"));
    let kind = if action == "LIST" {
        EventKind::LogMessage
    } else {
        EventKind::CrontabChange
    };
    Some(
        Classified::new(
            kind,
            Some(user),
            format!(
                "crontab {} by {user} (crontab of {target})",
                action.to_ascii_lowercase()
            ),
        )
        .field("action", action.to_ascii_lowercase())
        .field("crontab", target),
    )
}

fn classify_systemd(m: &str) -> Option<Classified> {
    let c = SYSTEMD_UNIT.captures(m)?;
    let unit = cap(&c, "unit");
    let (kind, verb) = if cap(&c, "verb") == "Started" {
        (EventKind::ServiceStarted, "started")
    } else {
        (EventKind::ServiceStopped, "stopped")
    };
    Some(Classified::new(kind, None, format!("systemd {verb} {unit}")).field("unit", unit))
}

fn classify_login(m: &str) -> Option<Classified> {
    let c = FAILED_LOGIN.captures(m)?;
    let user = cap(&c, "user");
    Some(
        Classified::new(
            EventKind::LoginFailure,
            Some(user),
            format!("failed console login for {user} on {}", cap(&c, "tty")),
        )
        .field("tty", cap(&c, "tty"))
        .field("src_host", cap(&c, "host")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f<'a>(c: &'a Classified, k: &str) -> &'a str {
        c.fields
            .iter()
            .find(|(key, _)| *key == k)
            .map_or("", |(_, v)| v.as_str())
    }

    #[test]
    fn sshd_messages() {
        let c = classify(
            Some("sshd"),
            "Accepted publickey for sysbackup from 192.0.2.99 port 40022 ssh2: ED25519 SHA256:abc",
        );
        assert_eq!(c.kind, EventKind::SshLoginSuccess);
        assert_eq!(c.user.as_deref(), Some("sysbackup"));
        assert_eq!(f(&c, "src_ip"), "192.0.2.99");
        assert_eq!(f(&c, "key"), "ED25519 SHA256:abc");

        let c = classify(
            Some("sshd"),
            "Failed password for invalid user admin from 203.0.113.45 port 1 ssh2",
        );
        assert_eq!(c.kind, EventKind::SshLoginFailure);
        assert_eq!(f(&c, "invalid_user"), "true");
        assert_eq!(c.user.as_deref(), Some("admin"));

        let c = classify(Some("sshd"), "Invalid user test from 203.0.113.45 port 2");
        assert_eq!(c.kind, EventKind::SshInvalidUser);
        let c = classify(Some("sshd"), "Invalid user  from 203.0.113.45");
        assert_eq!(c.kind, EventKind::SshInvalidUser);
        assert_eq!(c.user, None);

        let c = classify(
            Some("sshd"),
            "Disconnected from user deploy 203.0.113.45 port 50122",
        );
        assert_eq!(c.kind, EventKind::SshDisconnect);
        assert_eq!(c.user.as_deref(), Some("deploy"));
        let c = classify(
            Some("sshd-session"),
            "Connection closed by authenticating user root 203.0.113.45 port 3 [preauth]",
        );
        assert_eq!(c.kind, EventKind::SshDisconnect);
        let c = classify(
            Some("sshd"),
            "Received disconnect from 10.0.0.1 port 22:11: bye",
        );
        assert_eq!(f(&c, "src_ip"), "10.0.0.1");
        let c = classify(
            Some("sshd"),
            "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
        );
        assert_eq!(c.kind, EventKind::SessionOpened);
        assert_eq!(f(&c, "service"), "sshd");
        assert_eq!(f(&c, "uid"), "1001");
        let c = classify(Some("sshd"), "Server listening on 0.0.0.0 port 22.");
        assert_eq!(c.kind, EventKind::LogMessage);
        assert_eq!(c.description, "sshd: Server listening on 0.0.0.0 port 22.");
    }

    #[test]
    fn sudo_messages() {
        let c = classify(
            Some("sudo"),
            "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
        );
        assert_eq!(c.kind, EventKind::SudoCommand);
        assert_eq!(c.user.as_deref(), Some("deploy"));
        assert_eq!(f(&c, "target_user"), "root");
        assert_eq!(f(&c, "command"), "/bin/bash");
        assert_eq!(c.description, "sudo by deploy as root: /bin/bash");

        let c = classify(
            Some("sudo"),
            "eve : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
        );
        assert_eq!(c.kind, EventKind::SudoFailure);
        assert_eq!(f(&c, "reason"), "3 incorrect password attempts");

        let c = classify(
            Some("sudo"),
            "eve : user NOT in sudoers ; TTY=pts/2 ; PWD=/ ; USER=root ; GROUP=adm ; ENV=A=b ; COMMAND=/bin/sh -c 'a ; b'",
        );
        assert_eq!(c.kind, EventKind::SudoFailure);
        assert_eq!(f(&c, "command"), "/bin/sh -c 'a ; b'");
        assert_eq!(f(&c, "target_group"), "adm");

        let c = classify(
            Some("sudo"),
            "pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1001)",
        );
        assert_eq!(c.kind, EventKind::SessionOpened);
        assert_eq!(f(&c, "by"), "deploy");
        let c = classify(
            Some("sudo"),
            "pam_unix(sudo:auth): authentication failure; logname=eve uid=1003 euid=0 tty=/dev/pts/2 ruser=eve rhost=  user=eve",
        );
        assert_eq!(c.kind, EventKind::AuthFailure);
        assert_eq!(c.user.as_deref(), Some("eve"));
        assert_eq!(
            classify(Some("sudo"), "a b : c").kind,
            EventKind::LogMessage
        );
        assert_eq!(classify(Some("sudo"), "x : y").kind, EventKind::LogMessage);
    }

    #[test]
    fn su_messages() {
        let c = classify(Some("su"), "(to root) alice on pts/0");
        assert_eq!(c.kind, EventKind::SuSession);
        assert_eq!(f(&c, "target_user"), "root");
        let c = classify(Some("su"), "FAILED SU (to root) alice on pts/0");
        assert_eq!(c.kind, EventKind::AuthFailure);
        let c = classify(Some("su"), "Successful su for root by alice");
        assert_eq!(c.user.as_deref(), Some("alice"));
    }

    #[test]
    fn account_messages() {
        let c = classify(
            Some("useradd"),
            "new user: name=sysbackup, UID=1002, GID=1002, home=/home/sysbackup, shell=/bin/bash, from=/dev/pts/1",
        );
        assert_eq!(c.kind, EventKind::UserCreated);
        assert_eq!(f(&c, "account"), "sysbackup");
        assert_eq!(f(&c, "tty"), "/dev/pts/1");
        let c = classify(
            Some("groupadd"),
            "group added to /etc/group: name=ops, GID=1005",
        );
        assert_eq!(c.kind, EventKind::GroupCreated);
        let c = classify(Some("useradd"), "new group: name=sysbackup, GID=1002");
        assert_eq!(f(&c, "group"), "sysbackup");
        let c = classify(Some("usermod"), "add 'sysbackup' to group 'sudo'");
        assert_eq!(c.kind, EventKind::UserModified);
        assert_eq!(f(&c, "group"), "sudo");
        let c = classify(Some("usermod"), "add 'sysbackup' to shadow group 'sudo'");
        assert!(c.description.contains("shadow group"));
        let c = classify(
            Some("usermod"),
            "change user 'x' shell from '/bin/sh' to '/bin/bash'",
        );
        assert_eq!(c.kind, EventKind::UserModified);
        let c = classify(Some("userdel"), "delete user 'x'");
        assert_eq!(c.kind, EventKind::UserDeleted);
        let c = classify(
            Some("passwd"),
            "pam_unix(passwd:chauthtok): password changed for sysbackup",
        );
        assert_eq!(c.kind, EventKind::PasswordChanged);
        assert_eq!(f(&c, "account"), "sysbackup");
        let c = classify(Some("passwd"), "password for 'bob' changed by 'root'");
        assert_eq!(c.user.as_deref(), Some("root"));
        assert_eq!(
            classify(Some("/usr/sbin/useradd"), "huh").kind,
            EventKind::LogMessage
        );
    }

    #[test]
    fn cron_logind_systemd_kernel_login() {
        let c = classify(Some("CRON"), "(root) CMD (/tmp/.x.sh >/dev/null 2>&1 (x))");
        assert_eq!(c.kind, EventKind::CronCommand);
        assert_eq!(f(&c, "command"), "/tmp/.x.sh >/dev/null 2>&1 (x)");
        let c = classify(Some("cron"), "(root) RELOAD (crontabs/root)");
        assert_eq!(c.kind, EventKind::CrontabChange);
        let c = classify(Some("crontab"), "(root) REPLACE (root)");
        assert_eq!(c.kind, EventKind::CrontabChange);
        assert_eq!(f(&c, "action"), "replace");
        let c = classify(Some("crontab"), "(alice) LIST (alice)");
        assert_eq!(c.kind, EventKind::LogMessage);
        let c = classify(Some("systemd-logind"), "New session 7 of user deploy.");
        assert_eq!(c.kind, EventKind::SessionOpened);
        assert_eq!(f(&c, "session"), "7");
        let c = classify(Some("systemd-logind"), "Removed session 7.");
        assert_eq!(c.kind, EventKind::SessionClosed);
        let c = classify(
            Some("systemd"),
            "Started ssh.service - OpenBSD Secure Shell server.",
        );
        assert_eq!(c.kind, EventKind::ServiceStarted);
        let c = classify(Some("systemd"), "Stopped cron.service.");
        assert_eq!(f(&c, "unit"), "cron.service");
        let c = classify(
            Some("kernel"),
            "Linux version 6.8.0-31-generic (buildd@x) #31",
        );
        assert_eq!(c.kind, EventKind::Boot);
        let c = classify(
            Some("login"),
            "FAILED LOGIN (1) on '/dev/tty1' FOR 'root', Authentication failure",
        );
        assert_eq!(c.kind, EventKind::LoginFailure);
        let c = classify(None, "plain message");
        assert_eq!(c.description, "plain message");
    }
}
