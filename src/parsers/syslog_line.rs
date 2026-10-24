//! Zero-copy parser for one syslog-style text line.
//!
//! Accepted header forms (an optional `<PRI>` prefix is skipped):
//!
//! * RFC 3164 / BSD: `Mar  1 12:00:00[.ffffff] host tag[pid]: message`
//! * RFC 3339 (rsyslog high precision): `2024-03-01T12:00:00.123456+01:00 host tag[pid]: message`
//! * RFC 5424: `<34>1 2024-03-01T12:00:00Z host app procid msgid [sd] message`
//!
//! The parser is hand-written (no regex) because it sits on the hot path of
//! the lines/s benchmark.

use chrono::{DateTime, FixedOffset, NaiveDateTime};

use crate::time::year::PartialStamp;

/// The timestamp found in a syslog header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stamp {
    /// RFC 3164: local time without a year.
    Partial(PartialStamp),
    /// ISO time without an offset: local time with a year.
    Local(NaiveDateTime),
    /// Time with an explicit UTC offset.
    Absolute(DateTime<FixedOffset>),
}

/// A parsed syslog line; all strings borrow from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogLine<'a> {
    /// Header timestamp.
    pub stamp: Stamp,
    /// Host name field.
    pub host: &'a str,
    /// Program / tag (`sshd`, `CRON`, `kernel`), when present.
    pub program: Option<&'a str>,
    /// Process id from `tag[pid]`.
    pub pid: Option<u32>,
    /// Message body.
    pub message: &'a str,
}

const MONTHS: [&[u8; 3]; 12] = [
    b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov", b"dec",
];

/// Parses a three-letter English month abbreviation (case-insensitive).
pub fn month_from_abbr(b: &[u8]) -> Option<u32> {
    if b.len() < 3 {
        return None;
    }
    let lower = [
        b[0].to_ascii_lowercase(),
        b[1].to_ascii_lowercase(),
        b[2].to_ascii_lowercase(),
    ];
    MONTHS
        .iter()
        .position(|m| **m == lower)
        .map(|i| i as u32 + 1)
}

fn digits(b: &[u8], pos: &mut usize, min: usize, max: usize) -> Option<u32> {
    let start = *pos;
    let mut v: u32 = 0;
    while *pos < b.len() && *pos - start < max && b[*pos].is_ascii_digit() {
        v = v * 10 + u32::from(b[*pos] - b'0');
        *pos += 1;
    }
    (*pos - start >= min).then_some(v)
}

fn expect(b: &[u8], pos: &mut usize, c: u8) -> Option<()> {
    if b.get(*pos) == Some(&c) {
        *pos += 1;
        Some(())
    } else {
        None
    }
}

/// Parses `hh:mm:ss[.frac]` returning (h, m, s, nanos).
pub fn parse_hms(b: &[u8], pos: &mut usize) -> Option<(u32, u32, u32, u32)> {
    let h = digits(b, pos, 2, 2)?;
    expect(b, pos, b':')?;
    let m = digits(b, pos, 2, 2)?;
    expect(b, pos, b':')?;
    let s = digits(b, pos, 2, 2)?;
    if h > 23 || m > 59 || s > 60 {
        return None;
    }
    let mut nanos = 0;
    if b.get(*pos) == Some(&b'.') || b.get(*pos) == Some(&b',') {
        *pos += 1;
        let start = *pos;
        let mut scale = 100_000_000u32;
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            if scale > 0 {
                nanos += u32::from(b[*pos] - b'0') * scale;
                scale /= 10;
            }
            *pos += 1;
        }
        if *pos == start {
            return None;
        }
    }
    Some((h, m, s, nanos))
}

fn bsd_stamp(b: &[u8], pos: &mut usize) -> Option<PartialStamp> {
    let month = month_from_abbr(b.get(*pos..*pos + 3)?)?;
    *pos += 3;
    if b.get(*pos) != Some(&b' ') {
        return None;
    }
    while b.get(*pos) == Some(&b' ') {
        *pos += 1;
    }
    let day = digits(b, pos, 1, 2)?;
    if !(1..=31).contains(&day) {
        return None;
    }
    expect(b, pos, b' ')?;
    let (hour, minute, second, nanos) = parse_hms(b, pos)?;
    Some(PartialStamp {
        month,
        day,
        hour,
        minute,
        second,
        nanos,
    })
}

fn iso_stamp(token: &str) -> Option<Stamp> {
    if let Ok(t) = DateTime::parse_from_rfc3339(token) {
        return Some(Stamp::Absolute(t));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(t) = NaiveDateTime::parse_from_str(token, fmt) {
            return Some(Stamp::Local(t));
        }
    }
    None
}

fn next_token<'a>(s: &'a str, pos: &mut usize) -> Option<&'a str> {
    let rest = s.get(*pos..)?;
    let end = rest.find(' ').unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let tok = &rest[..end];
    *pos += end;
    if s.as_bytes().get(*pos) == Some(&b' ') {
        *pos += 1;
    }
    Some(tok)
}

/// Splits `tag[pid]:` from the message. Returns (program, pid, message).
fn split_tag(rest: &str) -> (Option<&str>, Option<u32>, &str) {
    let tok_end = rest.find(' ').unwrap_or(rest.len());
    let tok = &rest[..tok_end];
    let Some(tag) = tok.strip_suffix(':') else {
        return (None, None, rest);
    };
    let message = rest[tok_end..].trim_start_matches(' ');
    if let Some(open) = tag.find('[')
        && let Some(inner) = tag[open + 1..].strip_suffix(']')
    {
        let program = &tag[..open];
        if program.is_empty() {
            return (None, None, rest);
        }
        return (Some(program), inner.parse().ok(), message);
    }
    if tag.is_empty() {
        return (None, None, rest);
    }
    (Some(tag), None, message)
}

/// Parses one line; returns `None` if no recognizable header is present.
pub fn parse_line(line: &str) -> Option<SyslogLine<'_>> {
    let b = line.as_bytes();
    let mut pos = 0;
    let mut rfc5424 = false;
    if b.first() == Some(&b'<') {
        let close = line.get(1..5)?.find('>')? + 1;
        if close < 2 || !b[1..close].iter().all(u8::is_ascii_digit) {
            return None;
        }
        pos = close + 1;
        if line[pos..].starts_with("1 ") {
            rfc5424 = true;
            pos += 2;
        }
    }
    let stamp = if b.get(pos).is_some_and(u8::is_ascii_digit) {
        let tok = next_token(line, &mut pos)?;
        if tok == "-" {
            return None;
        }
        iso_stamp(tok)?
    } else {
        let s = bsd_stamp(b, &mut pos)?;
        expect(b, &mut pos, b' ')?;
        Stamp::Partial(s)
    };
    let host = next_token(line, &mut pos)?;
    if rfc5424 {
        let app = next_token(line, &mut pos)?;
        let procid = next_token(line, &mut pos)?;
        let _msgid = next_token(line, &mut pos)?;
        let rest = &line[pos.min(line.len())..];
        let message = skip_structured_data(rest);
        return Some(SyslogLine {
            stamp,
            host,
            program: (app != "-").then_some(app),
            pid: procid.parse().ok(),
            message: message.trim_start_matches('\u{feff}'),
        });
    }
    let rest = &line[pos.min(line.len())..];
    let (program, pid, message) = split_tag(rest);
    Some(SyslogLine {
        stamp,
        host,
        program,
        pid,
        message,
    })
}

/// Skips RFC 5424 STRUCTURED-DATA (`-` or one or more `[...]` elements).
fn skip_structured_data(rest: &str) -> &str {
    if let Some(r) = rest.strip_prefix('-') {
        return r.strip_prefix(' ').unwrap_or(r);
    }
    let b = rest.as_bytes();
    let mut i = 0;
    while b.get(i) == Some(&b'[') {
        let mut escaped = false;
        let mut in_quotes = false;
        i += 1;
        while i < b.len() {
            let c = b[i];
            i += 1;
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_quotes = !in_quotes;
            } else if c == b']' && !in_quotes {
                break;
            }
        }
    }
    let r = &rest[i.min(rest.len())..];
    r.strip_prefix(' ').unwrap_or(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bsd_line() {
        let l =
            parse_line("Dec 31 23:07:12 web01 sshd[4242]: Accepted password for deploy").unwrap();
        let Stamp::Partial(p) = l.stamp else {
            panic!("expected partial stamp")
        };
        assert_eq!(
            (p.month, p.day, p.hour, p.minute, p.second),
            (12, 31, 23, 7, 12)
        );
        assert_eq!(l.host, "web01");
        assert_eq!(l.program, Some("sshd"));
        assert_eq!(l.pid, Some(4242));
        assert_eq!(l.message, "Accepted password for deploy");
    }

    #[test]
    fn padded_day_fraction_and_no_pid() {
        let l = parse_line("Jan  1 00:05:01.250 web01 sudo:   deploy : TTY=pts/1").unwrap();
        let Stamp::Partial(p) = l.stamp else { panic!() };
        assert_eq!((p.day, p.nanos), (1, 250_000_000));
        assert_eq!(l.program, Some("sudo"));
        assert_eq!(l.pid, None);
        assert_eq!(l.message, "deploy : TTY=pts/1");
    }

    #[test]
    fn untagged_message() {
        let l = parse_line("Mar  1 12:00:00 host last message repeated 3 times").unwrap();
        assert_eq!(l.program, None);
        assert_eq!(l.message, "last message repeated 3 times");
        let l = parse_line("Mar  1 12:00:00 host [x]: odd").unwrap();
        assert_eq!(l.program, None);
        let l = parse_line("Mar  1 12:00:00 host :").unwrap();
        assert_eq!(l.program, None);
    }

    #[test]
    fn iso_lines() {
        let l = parse_line("2024-03-01T12:00:00.123456+01:00 web01 CRON[77]: (root) CMD (true)")
            .unwrap();
        let Stamp::Absolute(t) = l.stamp else {
            panic!()
        };
        assert_eq!(t.timestamp(), 1_709_290_800);
        assert_eq!(l.program, Some("CRON"));
        let l = parse_line("2024-03-01T12:00:00 web01 app: hi").unwrap();
        assert!(matches!(l.stamp, Stamp::Local(_)));
    }

    #[test]
    fn rfc5424_line() {
        let l = parse_line(
            r#"<38>1 2024-03-01T12:00:00Z web01 sshd 4242 - [meta x="a]b" y="\"q\""] Accepted password for a"#,
        )
        .unwrap();
        assert_eq!(l.program, Some("sshd"));
        assert_eq!(l.pid, Some(4242));
        assert_eq!(l.message, "Accepted password for a");
        let l = parse_line("<38>1 2024-03-01T12:00:00Z web01 - - - - hello").unwrap();
        assert_eq!(l.program, None);
        assert_eq!(l.message, "hello");
        let l = parse_line("<13>Mar  1 12:00:00 web01 app: pri prefix").unwrap();
        assert_eq!(l.message, "pri prefix");
    }

    #[test]
    fn rejects_non_syslog() {
        for bad in [
            "",
            "hello world",
            "Foo  1 12:00:00 h p: m",
            "Mar 41 12:00:00 h p: m",
            "Mar  1 25:00:00 h p: m",
            "Mar  1 12:00 h p: m",
            "<x>Mar  1 12:00:00 h p: m",
            "2024-13-01T00:00:00Z h p: m",
            "Mar  1 12:00:00",
            "<99999>1 x",
            "Mar  1 12:00:00.x h",
        ] {
            assert!(parse_line(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn month_abbreviations() {
        assert_eq!(month_from_abbr(b"DEC"), Some(12));
        assert_eq!(month_from_abbr(b"Ja"), None);
    }
}
