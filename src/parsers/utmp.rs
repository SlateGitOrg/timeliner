//! Linux `struct utmp` records (glibc, x86-64 / aarch64 layout, 384 bytes,
//! little-endian) as found in `/var/log/wtmp`, `/var/log/btmp` and `/run/utmp`.
//!
//! ```text
//! off size field
//!   0    2 ut_type (+2 padding)      44  32 ut_user
//!   4    4 ut_pid                    76 256 ut_host
//!   8   32 ut_line                  332   4 ut_exit (termination, exit)
//!  40    4 ut_id                    336   4 ut_session
//!                                   340   8 ut_tv (int32 sec, int32 usec)
//!                                   348  16 ut_addr_v6 (network order)
//!                                   364  20 unused
//! ```
//!
//! `DEAD_PROCESS` records carry no user name; the parser pairs them with the
//! preceding `USER_PROCESS` on the same `ut_line` (like `last(1)`) to recover
//! the user and the session duration.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};

use super::{ParseContext, ParseOutput, epoch_to_utc};
use crate::event::{Event, EventKind, SourceKind};

/// Size of one record.
pub const RECORD_SIZE: usize = 384;

/// `ut_type` values.
pub mod ut_type {
    /// Unused slot.
    pub const EMPTY: i16 = 0;
    /// Runlevel change.
    pub const RUN_LVL: i16 = 1;
    /// System boot.
    pub const BOOT_TIME: i16 = 2;
    /// Time after a clock change.
    pub const NEW_TIME: i16 = 3;
    /// Time before a clock change.
    pub const OLD_TIME: i16 = 4;
    /// Process spawned by init.
    pub const INIT_PROCESS: i16 = 5;
    /// getty waiting for a login.
    pub const LOGIN_PROCESS: i16 = 6;
    /// Interactive user session.
    pub const USER_PROCESS: i16 = 7;
    /// Session ended.
    pub const DEAD_PROCESS: i16 = 8;
    /// Accounting (unused on Linux).
    pub const ACCOUNTING: i16 = 9;
}

/// A decoded record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UtmpRecord {
    /// Record type (see [`ut_type`]).
    pub ut_type: i16,
    /// Process id.
    pub pid: i32,
    /// Terminal (`pts/1`, `tty1`, `~`).
    pub line: String,
    /// inittab id / terminal suffix.
    pub id: String,
    /// User name.
    pub user: String,
    /// Remote host or kernel version.
    pub host: String,
    /// Exit termination status.
    pub exit_termination: i16,
    /// Exit status.
    pub exit_status: i16,
    /// Session id.
    pub session: i32,
    /// Seconds since the epoch.
    pub tv_sec: i32,
    /// Microseconds.
    pub tv_usec: i32,
    /// Remote address, network byte order (IPv4 uses the first 4 bytes).
    pub addr: [u8; 16],
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn le_i16(b: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([b[off], b[off + 1]])
}

fn le_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl UtmpRecord {
    /// Decodes one record.
    pub fn decode(b: &[u8; RECORD_SIZE]) -> Self {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&b[348..364]);
        UtmpRecord {
            ut_type: le_i16(b, 0),
            pid: le_i32(b, 4),
            line: cstr(&b[8..40]),
            id: cstr(&b[40..44]),
            user: cstr(&b[44..76]),
            host: cstr(&b[76..332]),
            exit_termination: le_i16(b, 332),
            exit_status: le_i16(b, 334),
            session: le_i32(b, 336),
            tv_sec: le_i32(b, 340),
            tv_usec: le_i32(b, 344),
            addr,
        }
    }

    /// Encodes the record (strings are truncated to their field width).
    pub fn encode(&self) -> [u8; RECORD_SIZE] {
        let mut b = [0u8; RECORD_SIZE];
        let put = |b: &mut [u8; RECORD_SIZE], off: usize, len: usize, s: &str| {
            let bytes = s.as_bytes();
            let n = bytes.len().min(len);
            b[off..off + n].copy_from_slice(&bytes[..n]);
        };
        b[0..2].copy_from_slice(&self.ut_type.to_le_bytes());
        b[4..8].copy_from_slice(&self.pid.to_le_bytes());
        put(&mut b, 8, 32, &self.line);
        put(&mut b, 40, 4, &self.id);
        put(&mut b, 44, 32, &self.user);
        put(&mut b, 76, 256, &self.host);
        b[332..334].copy_from_slice(&self.exit_termination.to_le_bytes());
        b[334..336].copy_from_slice(&self.exit_status.to_le_bytes());
        b[336..340].copy_from_slice(&self.session.to_le_bytes());
        b[340..344].copy_from_slice(&self.tv_sec.to_le_bytes());
        b[344..348].copy_from_slice(&self.tv_usec.to_le_bytes());
        b[348..364].copy_from_slice(&self.addr);
        b
    }

    /// Remote address as text, if set.
    pub fn address(&self) -> Option<String> {
        if self.addr.iter().all(|&b| b == 0) {
            return None;
        }
        if self.addr[4..].iter().all(|&b| b == 0) {
            let a = Ipv4Addr::new(self.addr[0], self.addr[1], self.addr[2], self.addr[3]);
            return Some(a.to_string());
        }
        Some(Ipv6Addr::from(self.addr).to_string())
    }

    /// Sets the address from text (used by the fixture generator).
    pub fn set_address(&mut self, ip: &str) {
        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
            self.addr = [0; 16];
            self.addr[..4].copy_from_slice(&v4.octets());
        } else if let Ok(v6) = ip.parse::<Ipv6Addr>() {
            self.addr = v6.octets();
        }
    }
}

fn format_duration(secs: i64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}")
}

/// Parses a wtmp/btmp/utmp file.
pub fn parse(data: &[u8], ctx: &ParseContext, source: SourceKind) -> ParseOutput {
    let mut out = ParseOutput::default();
    let mut open: HashMap<String, (String, DateTime<Utc>)> = HashMap::new();
    let rem = data.len() % RECORD_SIZE;
    for (i, chunk) in data.chunks_exact(RECORD_SIZE).enumerate() {
        out.records += 1;
        let idx = i as u64;
        let mut buf = [0u8; RECORD_SIZE];
        buf.copy_from_slice(chunk);
        let r = UtmpRecord::decode(&buf);
        if !(ut_type::EMPTY..=ut_type::ACCOUNTING).contains(&r.ut_type) {
            out.warn(
                ctx,
                idx,
                format!("invalid ut_type {} (record skipped)", r.ut_type),
            );
            continue;
        }
        if matches!(
            r.ut_type,
            ut_type::EMPTY | ut_type::ACCOUNTING | ut_type::INIT_PROCESS
        ) || (r.ut_type == ut_type::LOGIN_PROCESS && source != SourceKind::Btmp)
        {
            continue;
        }
        let usec = if (0..1_000_000).contains(&r.tv_usec) {
            r.tv_usec as u32
        } else {
            out.warn(ctx, idx, format!("invalid tv_usec {}", r.tv_usec));
            0
        };
        let Some(ts) = epoch_to_utc(i64::from(r.tv_sec), usec * 1000) else {
            out.warn(ctx, idx, format!("implausible timestamp {}", r.tv_sec));
            continue;
        };
        if let Some(ev) = record_event(&r, ts, ctx, source, idx, &mut open) {
            out.events.push(ev);
        }
    }
    if rem != 0 {
        out.warn(
            ctx,
            (data.len() / RECORD_SIZE) as u64,
            format!("trailing {rem} bytes do not form a full {RECORD_SIZE}-byte record"),
        );
    }
    out
}

fn record_event(
    r: &UtmpRecord,
    ts: DateTime<Utc>,
    ctx: &ParseContext,
    source: SourceKind,
    idx: u64,
    open: &mut HashMap<String, (String, DateTime<Utc>)>,
) -> Option<Event> {
    let mk = |kind, desc: String| {
        Event::new(ts, source, kind, &ctx.artifact, idx, desc)
            .with_host(ctx.host.clone())
            .with_field("tty", r.line.clone())
            .with_field("pid", r.pid.to_string())
            .with_field("ut_type", r.ut_type.to_string())
    };
    let src_ip = r.address().or_else(|| {
        r.host
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|a| a.to_string())
    });
    let from = if r.host.is_empty() {
        String::new()
    } else {
        format!(" from {}", r.host)
    };
    let raw = format!(
        "type={} pid={} line={} id={} user={} host={} sec={} usec={}",
        r.ut_type, r.pid, r.line, r.id, r.user, r.host, r.tv_sec, r.tv_usec
    );
    let ev = match (source, r.ut_type) {
        (SourceKind::Btmp, ut_type::USER_PROCESS | ut_type::LOGIN_PROCESS) => mk(
            EventKind::LoginFailure,
            format!("failed login for {} on {}{from}", r.user, r.line),
        )
        .with_user(Some(r.user.clone()))
        .with_field("src_host", r.host.clone())
        .with_field("src_ip", src_ip.unwrap_or_default()),
        (_, ut_type::USER_PROCESS) => {
            open.insert(r.line.clone(), (r.user.clone(), ts));
            mk(
                EventKind::Login,
                format!("login: {} on {}{from}", r.user, r.line),
            )
            .with_user(Some(r.user.clone()))
            .with_field("src_host", r.host.clone())
            .with_field("src_ip", src_ip.unwrap_or_default())
            .with_field("session", r.session.to_string())
        }
        (_, ut_type::DEAD_PROCESS) => {
            let (user, desc, dur) = match open.remove(&r.line) {
                Some((user, start)) => {
                    let secs = (ts - start).num_seconds().max(0);
                    let d = format!(
                        "logout: {user} on {} (session {})",
                        r.line,
                        format_duration(secs)
                    );
                    (Some(user), d, secs.to_string())
                }
                None => (None, format!("logout on {}", r.line), String::new()),
            };
            mk(EventKind::Logout, desc)
                .with_user(user)
                .with_field("duration_secs", dur)
        }
        (_, ut_type::BOOT_TIME) => {
            open.clear();
            mk(EventKind::Boot, format!("system boot (kernel {})", r.host))
                .with_field("kernel", r.host.clone())
        }
        (_, ut_type::RUN_LVL) => {
            let level = char::from((r.pid & 0xff) as u8);
            if level == '0' || r.user == "shutdown" {
                mk(EventKind::Shutdown, "system shutdown".to_string())
            } else {
                mk(
                    EventKind::RunlevelChange,
                    format!("runlevel changed to {level}"),
                )
                .with_field("runlevel", level.to_string())
            }
        }
        (_, ut_type::NEW_TIME | ut_type::OLD_TIME) => {
            let which = if r.ut_type == ut_type::NEW_TIME {
                "new"
            } else {
                "old"
            };
            mk(
                EventKind::ClockChange,
                format!("system clock changed ({which} time record)"),
            )
            .with_field("clock", which)
        }
        _ => return None,
    };
    Some(ev.with_raw(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_util::ctx;

    fn rec(t: i16, line: &str, user: &str, host: &str, sec: i32) -> UtmpRecord {
        let mut r = UtmpRecord {
            ut_type: t,
            pid: 4242,
            line: line.into(),
            id: "ts/1".into(),
            user: user.into(),
            host: host.into(),
            session: 7,
            tv_sec: sec,
            tv_usec: 250_000,
            ..Default::default()
        };
        r.set_address(host);
        r
    }

    fn file(records: &[UtmpRecord]) -> Vec<u8> {
        records.iter().flat_map(|r| r.encode()).collect()
    }

    #[test]
    fn encode_decode_roundtrip() {
        let r = rec(
            ut_type::USER_PROCESS,
            "pts/1",
            "deploy",
            "2001:db8::1",
            1_735_704_433,
        );
        let back = UtmpRecord::decode(&r.encode());
        assert_eq!(back, r);
        assert_eq!(back.address().as_deref(), Some("2001:db8::1"));
        let mut long = r.clone();
        long.user = "x".repeat(40);
        assert_eq!(UtmpRecord::decode(&long.encode()).user.len(), 32);
        assert_eq!(UtmpRecord::default().address(), None);
    }

    #[test]
    fn wtmp_session_pairing() {
        let mut boot = rec(
            ut_type::BOOT_TIME,
            "~",
            "reboot",
            "6.8.0-31-generic",
            1_735_700_000,
        );
        boot.addr = [0; 16];
        let mut runlvl = rec(ut_type::RUN_LVL, "~", "runlevel", "", 1_735_700_001);
        runlvl.pid = i32::from(b'5') + 256 * i32::from(b'N');
        let data = file(&[
            boot,
            runlvl,
            rec(ut_type::LOGIN_PROCESS, "tty1", "LOGIN", "", 1_735_700_002),
            rec(
                ut_type::USER_PROCESS,
                "pts/1",
                "deploy",
                "203.0.113.45",
                1_735_704_433,
            ),
            rec(ut_type::DEAD_PROCESS, "pts/1", "", "", 1_735_706_200),
            rec(ut_type::DEAD_PROCESS, "pts/9", "", "", 1_735_706_201),
            rec(ut_type::NEW_TIME, "|", "", "", 1_735_706_300),
            rec(ut_type::EMPTY, "", "", "", 0),
        ]);
        let out = parse(&data, &ctx("var/log/wtmp"), SourceKind::Wtmp);
        assert_eq!(out.records, 8);
        let kinds: Vec<_> = out.events.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                EventKind::Boot,
                EventKind::RunlevelChange,
                EventKind::Login,
                EventKind::Logout,
                EventKind::Logout,
                EventKind::ClockChange
            ]
        );
        let login = &out.events[2];
        assert_eq!(login.get("src_ip"), Some("203.0.113.45"));
        assert_eq!(login.ts.timestamp_subsec_micros(), 250_000);
        assert_eq!(login.location, 3);
        let logout = &out.events[3];
        assert_eq!(logout.user.as_deref(), Some("deploy"));
        assert_eq!(logout.get("duration_secs"), Some("1767"));
        assert!(logout.description.contains("00:29:27"));
        assert_eq!(out.events[4].user, None);
        assert_eq!(out.events[1].get("runlevel"), Some("5"));
    }

    #[test]
    fn btmp_and_corruption() {
        let mut bad_type = rec(77, "pts/0", "x", "", 1_735_700_000);
        bad_type.tv_usec = 0;
        let mut bad_usec = rec(
            ut_type::LOGIN_PROCESS,
            "ssh:notty",
            "admin",
            "203.0.113.45",
            1_735_704_000,
        );
        bad_usec.tv_usec = 5_000_000;
        let mut data = file(&[
            bad_type,
            bad_usec,
            rec(
                ut_type::USER_PROCESS,
                "ssh:notty",
                "root",
                "203.0.113.45",
                -5,
            ),
            rec(ut_type::RUN_LVL, "~", "shutdown", "", 1_735_704_001),
        ]);
        data.extend_from_slice(&[1, 2, 3]);
        let out = parse(&data, &ctx("var/log/btmp"), SourceKind::Btmp);
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[0].kind, EventKind::LoginFailure);
        assert_eq!(out.events[0].user.as_deref(), Some("admin"));
        assert_eq!(out.events[1].kind, EventKind::Shutdown);
        assert_eq!(out.warning_count, 4);
    }
}
