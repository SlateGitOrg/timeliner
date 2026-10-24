//! Syslog-family text logs: auth.log/secure, syslog/messages, cron logs.
//!
//! Two passes: (1) parse every header and collect the year-less stamps,
//! (2) infer years for those stamps in one O(n) pass, convert local time to
//! UTC, and classify each message with [`semantics::classify`].
//!
//! Cron logs additionally accept the legacy Vixie-cron line format
//! `user (MM/DD-HH:MM:SS-PID) ACTION (detail)`.

use std::borrow::Cow;

use chrono::{DateTime, Utc};

use super::semantics::{self, Classified};
use super::syslog_line::{self, Stamp};
use super::{ParseContext, ParseOutput, lines};
use crate::event::{Event, SourceKind, TimeFlags};
use crate::time::year::{PartialStamp, infer_years};

/// One line that parsed, with owned-or-borrowed text so the second pass can
/// reference it.
struct Parsed<'a> {
    line_no: u64,
    raw: &'a str,
    stamp: Stamp,
    host: &'a str,
    program: Option<Cow<'a, str>>,
    pid: Option<u32>,
    message: Cow<'a, str>,
}

/// Parses a legacy cron line: `root (01/01-00:05:01-1234) CMD (/tmp/x)`.
fn parse_legacy_cron(line: &str) -> Option<(PartialStamp, u32, String)> {
    let (user, rest) = line.split_once(" (")?;
    if user.is_empty() || user.contains(' ') {
        return None;
    }
    let (stamp, rest) = rest.split_once(") ")?;
    let b = stamp.as_bytes();
    let mut pos = 0;
    let num = |pos: &mut usize, n: usize| -> Option<u32> {
        let s = stamp.get(*pos..*pos + n)?;
        *pos += n;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let month = num(&mut pos, 2)?;
    (b.get(pos) == Some(&b'/')).then_some(())?;
    pos += 1;
    let day = num(&mut pos, 2)?;
    (b.get(pos) == Some(&b'-')).then_some(())?;
    pos += 1;
    let (hour, minute, second, _) = syslog_line::parse_hms(b, &mut pos)?;
    (b.get(pos) == Some(&b'-')).then_some(())?;
    let pid: u32 = stamp.get(pos + 1..)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((
        PartialStamp {
            month,
            day,
            hour,
            minute,
            second,
            nanos: 0,
        },
        pid,
        format!("({user}) {rest}"),
    ))
}

/// Parses a syslog-family artifact.
pub fn parse(data: &[u8], ctx: &ParseContext, source: SourceKind) -> ParseOutput {
    let mut out = ParseOutput::default();
    let all: Vec<(u64, Cow<'_, str>)> = lines(data).collect();
    let mut parsed: Vec<Parsed<'_>> = Vec::with_capacity(all.len());
    for (line_no, text) in &all {
        out.records += 1;
        let text: &str = text;
        if text.trim().is_empty() {
            continue;
        }
        if let Some(sl) = syslog_line::parse_line(text) {
            parsed.push(Parsed {
                line_no: *line_no,
                raw: text,
                stamp: sl.stamp,
                host: sl.host,
                program: sl.program.map(Cow::Borrowed),
                pid: sl.pid,
                message: Cow::Borrowed(sl.message),
            });
        } else if source == SourceKind::Cron
            && let Some((stamp, pid, message)) = parse_legacy_cron(text)
        {
            parsed.push(Parsed {
                line_no: *line_no,
                raw: text,
                stamp: Stamp::Partial(stamp),
                host: "",
                program: Some(Cow::Borrowed("cron")),
                pid: Some(pid),
                message: Cow::Owned(message),
            });
        } else {
            out.warn(ctx, *line_no, "unrecognized line format");
        }
    }

    let partials: Vec<PartialStamp> = parsed
        .iter()
        .filter_map(|p| match p.stamp {
            Stamp::Partial(s) => Some(s),
            _ => None,
        })
        .collect();
    let years = infer_years(&partials, ctx.year_anchor);
    let mut year_iter = years.into_iter();

    out.events.reserve(parsed.len());
    for p in parsed {
        let mut flags = TimeFlags::default();
        let ts: Option<DateTime<Utc>> = match p.stamp {
            Stamp::Partial(s) => {
                let year = year_iter.next().unwrap_or(0);
                flags.year_inferred = true;
                s.with_year(year).map(|local| {
                    let c = ctx.tz.local_to_utc(local);
                    flags.local_time = true;
                    flags.tz_ambiguous = c.ambiguous;
                    flags.tz_gap = c.gap;
                    c.utc
                })
            }
            Stamp::Local(local) => {
                let c = ctx.tz.local_to_utc(local);
                flags.local_time = true;
                flags.tz_ambiguous = c.ambiguous;
                flags.tz_gap = c.gap;
                Some(c.utc)
            }
            Stamp::Absolute(t) => Some(t.with_timezone(&Utc)),
        };
        let Some(ts) = ts else {
            out.warn(ctx, p.line_no, "date does not exist in the inferred year");
            continue;
        };
        let Classified {
            kind,
            user,
            description,
            fields,
        } = semantics::classify(p.program.as_deref(), &p.message);
        let host = if p.host.is_empty() || p.host == "-" {
            ctx.host.clone()
        } else {
            Some(p.host.to_string())
        };
        let mut ev = Event::new(ts, source, kind, &ctx.artifact, p.line_no, description)
            .with_host(host)
            .with_user(user)
            .with_raw(p.raw)
            .with_time_flags(flags);
        if let Some(program) = p.program.as_deref() {
            ev = ev.with_field("program", program);
        }
        if let Some(pid) = p.pid {
            ev = ev.with_field("pid", pid.to_string());
        }
        for (k, v) in fields {
            ev.fields.insert(k.to_string(), v);
        }
        out.events.push(ev);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;
    use crate::parsers::test_util::ctx;
    use crate::time::TimeZone;
    use crate::time::year::YearAnchor;
    use chrono::TimeZone as _;

    #[test]
    fn auth_log_with_year_rollover_and_tz() {
        let data = b"Dec 31 23:07:12 web01 sshd[4242]: Accepted password for deploy from 203.0.113.45 port 50122 ssh2\n\
garbage line\n\
\n\
Jan  1 00:05:01 web01 CRON[99]: (root) CMD (/tmp/.x.sh)\n";
        let mut c = ctx("var/log/auth.log");
        c.tz = TimeZone::fixed(-5 * 3600).unwrap();
        c.year_anchor = YearAnchor::Explicit(2025);
        let out = parse(data, &c, SourceKind::AuthLog);
        assert_eq!(out.records, 4);
        assert_eq!(out.warning_count, 1);
        assert_eq!(out.warnings[0].location, 2);
        assert_eq!(out.events.len(), 2);
        let e = &out.events[0];
        assert_eq!(e.ts, Utc.with_ymd_and_hms(2025, 1, 1, 4, 7, 12).unwrap());
        assert_eq!(e.kind, EventKind::SshLoginSuccess);
        assert_eq!(e.host.as_deref(), Some("web01"));
        assert_eq!(e.get("pid"), Some("4242"));
        assert!(e.time_flags.year_inferred && e.time_flags.local_time);
        let e = &out.events[1];
        assert_eq!(e.ts, Utc.with_ymd_and_hms(2025, 1, 1, 5, 5, 1).unwrap());
        assert_eq!(e.location, 4);
        assert_eq!(e.user.as_deref(), Some("root"));
    }

    #[test]
    fn iso_and_rfc5424_lines_are_absolute() {
        let data = b"2025-01-01T04:07:12.5+00:00 web01 systemd[1]: Started cron.service.\n\
<38>1 2025-01-01T04:07:13Z - sshd 7 - - Invalid user x from 1.2.3.4\n\
2025-01-01T04:07:14 web01 app: local iso\n";
        let mut c = ctx("var/log/syslog");
        c.tz = TimeZone::fixed(3600).unwrap();
        let out = parse(data, &c, SourceKind::Syslog);
        assert_eq!(out.events.len(), 3);
        assert!(!out.events[0].time_flags.year_inferred);
        assert_eq!(out.events[0].ts.timestamp_subsec_millis(), 500);
        assert_eq!(out.events[1].kind, EventKind::SshInvalidUser);
        assert_eq!(out.events[1].host.as_deref(), Some("web01"));
        assert_eq!(
            out.events[2].ts,
            Utc.with_ymd_and_hms(2025, 1, 1, 3, 7, 14).unwrap()
        );
        assert!(out.events[2].time_flags.local_time);
    }

    #[test]
    fn legacy_cron_format() {
        let data = b"root (01/01-00:05:01-1234) CMD (/tmp/.x.sh)\n\
alice (12/31-23:59:00-1) BEGIN EDIT (alice)\n\
bad (13/01-00:00:00-1) CMD (x)\n";
        let out = parse(data, &ctx("var/log/cron"), SourceKind::Cron);
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[0].kind, EventKind::CronCommand);
        assert_eq!(out.events[0].get("pid"), Some("1234"));
        assert_eq!(out.warning_count, 1);
        // Not accepted outside cron logs.
        let out = parse(data, &ctx("var/log/syslog"), SourceKind::Syslog);
        assert_eq!(out.events.len(), 0);
        assert!(parse_legacy_cron("root (01/01-00:05-1) CMD (x)").is_none());
        assert!(parse_legacy_cron(" (01/01-00:05:01-1) CMD (x)").is_none());
    }

    #[test]
    fn invalid_leap_day_is_a_warning() {
        let out = parse(
            b"Feb 29 10:00:00 h app: x\n",
            &ctx("var/log/syslog"),
            SourceKind::Syslog,
        );
        assert!(out.events.is_empty());
        assert_eq!(out.warning_count, 1);
    }
}
