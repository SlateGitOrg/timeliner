//! Sleuth Kit bodyfile (TSK 3.x+): `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`.
//!
//! The name may itself contain `|`, so the line is split from both ends: the
//! first field is the MD5 and the last nine are fixed. Timestamps may carry a
//! fractional part (`1735704543.123456789`); `0`, `-1` and empty mean "unset".
//! Timestamps shared by several of a file's MACB times collapse into one
//! event whose `macb` field reads like `mactime` output (`M.C.`).

use std::collections::BTreeMap;

use super::{ParseContext, ParseOutput, epoch_to_utc, lines};
use crate::event::{Event, EventKind, SourceKind};

/// Parses `secs[.frac]`; `Ok(None)` for "unset".
fn parse_time(s: &str) -> Result<Option<(i64, u32)>, ()> {
    let s = s.trim();
    if s.is_empty() || s == "0" || s == "-1" {
        return Ok(None);
    }
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = secs.parse().map_err(|_| ())?;
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let mut nanos: u32 = 0;
    for (i, b) in frac.bytes().take(9).enumerate() {
        nanos += u32::from(b - b'0') * 10u32.pow(8 - i as u32);
    }
    if secs <= 0 && nanos == 0 {
        return Ok(None);
    }
    Ok(Some((secs, nanos)))
}

/// Parses a bodyfile.
pub fn parse(data: &[u8], ctx: &ParseContext) -> ParseOutput {
    let mut out = ParseOutput::default();
    for (line_no, line) in lines(data) {
        out.records += 1;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 11 {
            out.warn(
                ctx,
                line_no,
                format!("expected 11 fields, found {}", parts.len()),
            );
            continue;
        }
        let n = parts.len();
        let md5 = parts[0];
        let name = parts[1..n - 9].join("|");
        let [inode, mode, uid, gid, size, atime, mtime, ctime, crtime] = [
            parts[n - 9],
            parts[n - 8],
            parts[n - 7],
            parts[n - 6],
            parts[n - 5],
            parts[n - 4],
            parts[n - 3],
            parts[n - 2],
            parts[n - 1],
        ];
        let mut times: BTreeMap<(i64, u32), [u8; 4]> = BTreeMap::new();
        let mut bad = false;
        for (slot, (letter, value)) in [(b'M', mtime), (b'A', atime), (b'C', ctime), (b'B', crtime)]
            .into_iter()
            .enumerate()
        {
            match parse_time(value) {
                Ok(Some(t)) => times.entry(t).or_insert(*b"....")[slot] = letter,
                Ok(None) => {}
                Err(()) => bad = true,
            }
        }
        if bad {
            out.warn(ctx, line_no, "non-numeric timestamp field");
            continue;
        }
        let deleted = name.contains("(deleted");
        for ((secs, nanos), flags) in times {
            let macb = String::from_utf8_lossy(&flags).into_owned();
            let Some(ts) = epoch_to_utc(secs, nanos) else {
                out.warn(ctx, line_no, format!("implausible timestamp {secs}"));
                continue;
            };
            let ev = Event::new(
                ts,
                SourceKind::Bodyfile,
                EventKind::FileActivity,
                &ctx.artifact,
                line_no,
                format!("{name} [{macb}] ({mode}, uid {uid}, {size} bytes)"),
            )
            .with_host(ctx.host.clone())
            .with_field("path", name.clone())
            .with_field("macb", macb)
            .with_field("inode", inode)
            .with_field("mode", mode)
            .with_field("uid", uid)
            .with_field("gid", gid)
            .with_field("size", size)
            .with_field("md5", if md5 == "0" { "" } else { md5 })
            .with_field("deleted", if deleted { "true" } else { "" })
            .with_raw(&line);
            out.events.push(ev);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_util::ctx;

    #[test]
    fn macb_grouping_and_pipes_in_names() {
        let data = b"# comment\n\
0|/tmp/.x.sh|1234|r/rrwxr-xr-x|1001|1001|231|1735704543|1735704543|1735704571|1735704543\n\
d41d8cd98f00b204e9800998ecf8427e|/odd|name (deleted)|99|r/rrw-------|0|0|0|1735704000.5|0|0|\n\
short|line\n\
0|/x|1|r|0|0|0|abc|0|0|0\n";
        let out = parse(data, &ctx("bodyfile.txt"));
        assert_eq!(out.warning_count, 2);
        assert_eq!(out.events.len(), 3);
        let e = &out.events[0];
        assert_eq!(e.get("macb"), Some("MA.B"));
        assert_eq!(e.get("path"), Some("/tmp/.x.sh"));
        assert_eq!(e.get("md5"), None);
        assert_eq!(out.events[1].get("macb"), Some("..C."));
        let e = &out.events[2];
        assert_eq!(e.get("path"), Some("/odd|name (deleted)"));
        assert_eq!(e.get("deleted"), Some("true"));
        assert_eq!(e.get("macb"), Some(".A.."));
        assert_eq!(e.ts.timestamp_subsec_millis(), 500);
        assert!(e.get("md5").is_some());
    }

    #[test]
    fn time_parsing() {
        assert_eq!(parse_time(""), Ok(None));
        assert_eq!(parse_time("-1"), Ok(None));
        assert_eq!(parse_time("0.0"), Ok(None));
        assert_eq!(parse_time("10.123456789123"), Ok(Some((10, 123_456_789))));
        assert_eq!(parse_time("1.x"), Err(()));
        assert_eq!(parse_time("x"), Err(()));
        let out = parse(b"0|/f|1|r|0|0|0|99999999999|0|0|0\n", &ctx("b"));
        assert_eq!(out.warning_count, 1);
    }
}
