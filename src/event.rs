//! The unified event model every parser produces.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Declares a fieldless enum with a canonical snake_case string form that is
/// used for serialization, parsing (`FromStr`) and display.
macro_rules! str_enum {
    ($(#[$meta:meta])* pub enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// Canonical snake_case name.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text),+
                }
            }
        }

        impl std::str::FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, String> {
                match s {
                    $($text => Ok($name::$variant),)+
                    other => Err(format!("unknown {} `{}`", stringify!($name), other)),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

str_enum! {
    /// Which kind of artifact an event was recovered from.
    pub enum SourceKind {
        /// `/var/log/auth.log` / `/var/log/secure`.
        AuthLog => "auth_log",
        /// `/var/log/syslog` / `/var/log/messages`.
        Syslog => "syslog",
        /// `/var/log/cron` / `/var/log/cron.log`.
        Cron => "cron",
        /// bash / zsh / fish history files.
        ShellHistory => "shell_history",
        /// `/var/log/wtmp` login records.
        Wtmp => "wtmp",
        /// `/var/log/btmp` failed-login records.
        Btmp => "btmp",
        /// `/run/utmp` current-session records.
        Utmp => "utmp",
        /// `journalctl -o export` output.
        Journal => "journal",
        /// Sleuth Kit bodyfile (`fls -m`, `ils -m`).
        Bodyfile => "bodyfile",
        /// `/var/log/dpkg.log`.
        Dpkg => "dpkg",
        /// `/var/log/apt/history.log`.
        AptHistory => "apt_history",
    }
}

impl SourceKind {
    /// Long human-readable name (used as the l2tcsv `sourcetype` column).
    pub fn long_name(self) -> &'static str {
        match self {
            SourceKind::AuthLog => "Auth Log",
            SourceKind::Syslog => "Syslog",
            SourceKind::Cron => "Cron Log",
            SourceKind::ShellHistory => "Shell History",
            SourceKind::Wtmp => "WTMP Login Record",
            SourceKind::Btmp => "BTMP Failed Login",
            SourceKind::Utmp => "UTMP Session",
            SourceKind::Journal => "Systemd Journal",
            SourceKind::Bodyfile => "File System (bodyfile)",
            SourceKind::Dpkg => "Dpkg Log",
            SourceKind::AptHistory => "APT History",
        }
    }

    /// Short l2tcsv `source` code.
    pub fn l2t_short(self) -> &'static str {
        match self {
            SourceKind::Bodyfile => "FILE",
            SourceKind::ShellHistory => "HIST",
            _ => "LOG",
        }
    }
}

str_enum! {
    /// Normalized meaning of an event, independent of the artifact format.
    pub enum EventKind {
        /// Successful SSH authentication.
        SshLoginSuccess => "ssh_login_success",
        /// Failed SSH authentication for an existing or invalid user.
        SshLoginFailure => "ssh_login_failure",
        /// SSH connection attempt naming a non-existent user.
        SshInvalidUser => "ssh_invalid_user",
        /// SSH connection closed / disconnected.
        SshDisconnect => "ssh_disconnect",
        /// PAM authentication failure (any service).
        AuthFailure => "auth_failure",
        /// Command run through sudo.
        SudoCommand => "sudo_command",
        /// sudo refused or password failures.
        SudoFailure => "sudo_failure",
        /// `su` to another account.
        SuSession => "su_session",
        /// PAM / logind session opened.
        SessionOpened => "session_opened",
        /// PAM / logind session closed.
        SessionClosed => "session_closed",
        /// Local account created.
        UserCreated => "user_created",
        /// Local account deleted.
        UserDeleted => "user_deleted",
        /// Local account modified (group membership, shell, lock...).
        UserModified => "user_modified",
        /// Local group created.
        GroupCreated => "group_created",
        /// Account password changed.
        PasswordChanged => "password_changed",
        /// Interactive login (wtmp/utmp USER_PROCESS).
        Login => "login",
        /// Logout (wtmp DEAD_PROCESS).
        Logout => "logout",
        /// Failed login (btmp).
        LoginFailure => "login_failure",
        /// System boot.
        Boot => "boot",
        /// System shutdown.
        Shutdown => "shutdown",
        /// Runlevel change.
        RunlevelChange => "runlevel_change",
        /// System clock was changed.
        ClockChange => "clock_change",
        /// Command recorded in a shell history file.
        ShellCommand => "shell_command",
        /// Command executed by cron.
        CronCommand => "cron_command",
        /// A crontab was replaced, edited, deleted or reloaded.
        CrontabChange => "crontab_change",
        /// Package installed.
        PackageInstall => "package_install",
        /// Package upgraded.
        PackageUpgrade => "package_upgrade",
        /// Package removed or purged.
        PackageRemove => "package_remove",
        /// One APT transaction (a `Start-Date` block in history.log).
        PackageTransaction => "package_transaction",
        /// File-system timestamp (one or more of M/A/C/B).
        FileActivity => "file_activity",
        /// systemd unit started.
        ServiceStarted => "service_started",
        /// systemd unit stopped.
        ServiceStopped => "service_stopped",
        /// Any other log line.
        LogMessage => "log_message",
    }
}

/// Facts about how an event's timestamp was derived.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeFlags {
    /// The artifact stored no year; it was inferred (see `time::year`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub year_inferred: bool,
    /// The artifact stored local wall-clock time that was converted to UTC.
    #[serde(default, skip_serializing_if = "is_false")]
    pub local_time: bool,
    /// The local time occurred twice (DST fall-back); the earlier instant was used.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tz_ambiguous: bool,
    /// The local time does not exist (DST spring-forward gap); it was shifted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tz_gap: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl TimeFlags {
    /// True when no flag is set.
    pub fn is_empty(&self) -> bool {
        *self == TimeFlags::default()
    }

    /// Short labels for every flag that is set.
    pub fn labels(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.year_inferred {
            out.push("year_inferred");
        }
        if self.local_time {
            out.push("local_time");
        }
        if self.tz_ambiguous {
            out.push("tz_ambiguous");
        }
        if self.tz_gap {
            out.push("tz_gap");
        }
        out
    }
}

/// Where a (possibly merged) observation came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Artifact type.
    pub source: SourceKind,
    /// Artifact display path.
    pub artifact: String,
    /// 1-based line (text) or 0-based record index (binary).
    pub location: u64,
}

/// A rule hit attached to an event by the tagging engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHit {
    /// Rule identifier.
    pub rule: String,
    /// Severity copied from the rule.
    pub severity: Severity,
}

str_enum! {
    /// Severity of a tagging rule.
    pub enum Severity {
        /// Informational.
        Info => "info",
        /// Low.
        Low => "low",
        /// Medium.
        Medium => "medium",
        /// High.
        High => "high",
        /// Critical.
        Critical => "critical",
    }
}

/// One normalized timeline event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Event time in UTC.
    #[serde(serialize_with = "ser_ts", deserialize_with = "de_ts")]
    pub ts: DateTime<Utc>,
    /// Artifact type the event came from.
    pub source: SourceKind,
    /// Normalized meaning.
    pub kind: EventKind,
    /// Host name, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Acting account, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// One-line human-readable description.
    pub description: String,
    /// Structured attributes (`src_ip`, `command`, `path`, `macb`, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    /// Tags applied by rules (sorted, unique).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Rules that fired on this event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_hits: Vec<RuleHit>,
    /// How the timestamp was derived.
    #[serde(default, skip_serializing_if = "TimeFlags::is_empty")]
    pub time_flags: TimeFlags,
    /// Artifact display path.
    pub artifact: String,
    /// 1-based line (text) or 0-based record index (binary).
    pub location: u64,
    /// Other artifacts that recorded the same event (filled by deduplication).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_seen: Vec<Provenance>,
    /// Original line / record rendering (may be truncated).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

/// Maximum number of bytes of the original record kept in [`Event::raw`].
pub const RAW_LIMIT: usize = 512;

impl Event {
    /// Creates an event with the mandatory attributes; everything else is empty.
    pub fn new(
        ts: DateTime<Utc>,
        source: SourceKind,
        kind: EventKind,
        artifact: &str,
        location: u64,
        description: impl Into<String>,
    ) -> Self {
        Event {
            ts,
            source,
            kind,
            host: None,
            user: None,
            description: description.into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            rule_hits: Vec::new(),
            time_flags: TimeFlags::default(),
            artifact: artifact.to_string(),
            location,
            also_seen: Vec::new(),
            raw: String::new(),
        }
    }

    /// Sets the user (empty strings are ignored).
    pub fn with_user(mut self, user: Option<impl Into<String>>) -> Self {
        self.user = user.map(Into::into).filter(|u: &String| !u.is_empty());
        self
    }

    /// Sets the host (empty strings are ignored).
    pub fn with_host(mut self, host: Option<impl Into<String>>) -> Self {
        self.host = host.map(Into::into).filter(|h: &String| !h.is_empty());
        self
    }

    /// Adds a structured field (empty values are ignored).
    pub fn with_field(mut self, key: &str, value: impl Into<String>) -> Self {
        let value = value.into();
        if !value.is_empty() {
            self.fields.insert(key.to_string(), value);
        }
        self
    }

    /// Stores the original record text, truncated to [`RAW_LIMIT`] bytes.
    pub fn with_raw(mut self, raw: &str) -> Self {
        self.raw = truncate_utf8(raw, RAW_LIMIT).to_string();
        self
    }

    /// Sets the time flags.
    pub fn with_time_flags(mut self, flags: TimeFlags) -> Self {
        self.time_flags = flags;
        self
    }

    /// Looks up a field by rule/field name: built-in attributes first, then `fields`.
    pub fn get(&self, name: &str) -> Option<&str> {
        match name {
            "kind" => Some(self.kind.as_str()),
            "source" => Some(self.source.as_str()),
            "host" => self.host.as_deref(),
            "user" => self.user.as_deref(),
            "description" => Some(&self.description),
            "artifact" => Some(&self.artifact),
            "raw" => Some(&self.raw),
            other => {
                let key = other.strip_prefix("fields.").unwrap_or(other);
                self.fields.get(key).map(String::as_str)
            }
        }
    }

    /// Adds a tag, keeping `tags` sorted and unique.
    pub fn add_tag(&mut self, tag: &str) {
        if let Err(pos) = self.tags.binary_search_by(|t| t.as_str().cmp(tag)) {
            self.tags.insert(pos, tag.to_string());
        }
    }

    /// Highest severity among rule hits, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.rule_hits.iter().map(|h| h.severity).max()
    }

    /// Provenance of this event's primary observation.
    pub fn provenance(&self) -> Provenance {
        Provenance {
            source: self.source,
            artifact: self.artifact.clone(),
            location: self.location,
        }
    }
}

/// Formats a timestamp as RFC 3339 UTC with microsecond precision.
pub fn format_ts(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn ser_ts<S: Serializer>(ts: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format_ts(ts))
}

fn de_ts<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let s = String::deserialize(d)?;
    DateTime::parse_from_rfc3339(&s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(serde::de::Error::custom)
}

/// Truncates `s` to at most `max` bytes on a character boundary.
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample() -> Event {
        Event::new(
            Utc.with_ymd_and_hms(2025, 1, 1, 4, 7, 12).unwrap(),
            SourceKind::AuthLog,
            EventKind::SshLoginSuccess,
            "var/log/auth.log",
            42,
            "ssh login",
        )
        .with_user(Some("deploy"))
        .with_host(Some(""))
        .with_field("src_ip", "203.0.113.45")
        .with_field("empty", "")
    }

    #[test]
    fn builder_skips_empty_values() {
        let e = sample();
        assert_eq!(e.user.as_deref(), Some("deploy"));
        assert!(e.host.is_none());
        assert!(!e.fields.contains_key("empty"));
        assert_eq!(e.get("src_ip"), Some("203.0.113.45"));
        assert_eq!(e.get("fields.src_ip"), Some("203.0.113.45"));
        assert_eq!(e.get("kind"), Some("ssh_login_success"));
        assert_eq!(e.get("source"), Some("auth_log"));
        assert_eq!(e.get("missing"), None);
    }

    #[test]
    fn tags_stay_sorted_and_unique() {
        let mut e = sample();
        e.add_tag("b");
        e.add_tag("a");
        e.add_tag("b");
        assert_eq!(e.tags, vec!["a", "b"]);
    }

    #[test]
    fn json_roundtrip() {
        let mut e = sample();
        e.time_flags.year_inferred = true;
        e.rule_hits.push(RuleHit {
            rule: "r".into(),
            severity: Severity::High,
        });
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"ts\":\"2025-01-01T04:07:12.000000Z\""));
        assert!(json.contains("\"year_inferred\":true"));
        assert!(!json.contains("tz_gap"));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.max_severity(), Some(Severity::High));
    }

    #[test]
    fn enums_parse_and_display() {
        for k in EventKind::ALL {
            assert_eq!(k.as_str().parse::<EventKind>().unwrap(), *k);
        }
        for s in SourceKind::ALL {
            assert_eq!(s.to_string().parse::<SourceKind>().unwrap(), *s);
            assert!(!s.long_name().is_empty());
            assert!(!s.l2t_short().is_empty());
        }
        assert!("nope".parse::<Severity>().is_err());
        assert!(Severity::Critical > Severity::High);
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate_utf8("héllo", 2), "h");
        assert_eq!(truncate_utf8("abc", 10), "abc");
        let e = sample().with_raw(&"x".repeat(RAW_LIMIT + 10));
        assert_eq!(e.raw.len(), RAW_LIMIT);
    }

    #[test]
    fn time_flag_labels() {
        let f = TimeFlags {
            year_inferred: true,
            local_time: true,
            tz_ambiguous: true,
            tz_gap: true,
        };
        assert_eq!(f.labels().len(), 4);
        assert!(TimeFlags::default().is_empty());
    }
}
