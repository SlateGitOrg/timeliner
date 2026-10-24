//! CSV and l2tcsv writers (RFC 4180 quoting).
//!
//! Log content is attacker-controlled: a user name like `=HYPERLINK(...)`
//! becomes a live formula when an analyst opens the CSV in a spreadsheet.
//! With `safe` enabled, cells from untrusted text that start with `=`, `+`,
//! `-`, `@`, tab or CR (and are longer than one character) get a leading `'`
//! (OWASP CSV-injection guidance).

use std::io::{self, Write};

use chrono::{DateTime, Utc};

use crate::event::{Event, SourceKind, format_ts};
use crate::pipeline::Timeline;

/// Quotes a field if needed; optionally neutralizes formulas.
pub fn field(s: &str, safe: bool) -> String {
    let guarded;
    let s = if safe && s.len() > 1 && s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        guarded = format!("'{s}");
        guarded.as_str()
    } else {
        s
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn row(w: &mut dyn Write, cells: &[String]) -> io::Result<()> {
    w.write_all(cells.join(",").as_bytes())?;
    w.write_all(b"\r\n")
}

fn fields_text(e: &Event, sep: &str, kv: &str) -> String {
    e.fields
        .iter()
        .map(|(k, v)| format!("{k}{kv}{v}"))
        .collect::<Vec<_>>()
        .join(sep)
}

fn also_seen_text(e: &Event) -> String {
    e.also_seen
        .iter()
        .map(|p| format!("{}:{}", p.artifact, p.location))
        .collect::<Vec<_>>()
        .join("|")
}

/// Column names of timeliner's CSV.
pub const CSV_HEADER: [&str; 13] = [
    "timestamp",
    "source",
    "kind",
    "host",
    "user",
    "description",
    "tags",
    "severity",
    "artifact",
    "location",
    "time_flags",
    "also_seen",
    "fields",
];

/// Writes timeliner's CSV.
pub fn write_csv(tl: &Timeline, safe: bool, w: &mut dyn Write) -> io::Result<()> {
    row(w, &CSV_HEADER.map(String::from))?;
    for e in &tl.events {
        row(
            w,
            &[
                format_ts(&e.ts),
                e.source.to_string(),
                e.kind.to_string(),
                field(e.host.as_deref().unwrap_or(""), safe),
                field(e.user.as_deref().unwrap_or(""), safe),
                field(&e.description, safe),
                field(&e.tags.join(" "), safe),
                e.max_severity().map(|s| s.to_string()).unwrap_or_default(),
                field(&e.artifact, safe),
                e.location.to_string(),
                e.time_flags.labels().join(" "),
                field(&also_seen_text(e), safe),
                field(&fields_text(e, "; ", "="), safe),
            ],
        )?;
    }
    Ok(())
}

/// The 17 l2tcsv columns.
pub const L2T_HEADER: [&str; 17] = [
    "date",
    "time",
    "timezone",
    "MACB",
    "source",
    "sourcetype",
    "type",
    "user",
    "host",
    "short",
    "desc",
    "version",
    "filename",
    "inode",
    "notes",
    "format",
    "extra",
];

fn timestamp_desc(e: &Event) -> String {
    if e.source == SourceKind::Bodyfile {
        let macb = e.get("macb").unwrap_or("....");
        let names: Vec<&str> = macb
            .chars()
            .filter_map(|c| match c {
                'M' => Some("Content Modification Time"),
                'A' => Some("Last Access Time"),
                'C' => Some("Metadata Modification Time"),
                'B' => Some("Creation Time"),
                _ => None,
            })
            .collect();
        return names.join("; ");
    }
    match e.source {
        SourceKind::ShellHistory => "Command Execution Time",
        SourceKind::Wtmp | SourceKind::Utmp | SourceKind::Btmp => "Record Time",
        _ => "Entry Written",
    }
    .to_string()
}

fn dash(s: Option<&str>) -> &str {
    match s {
        Some(v) if !v.is_empty() => v,
        _ => "-",
    }
}

fn l2t_date_time(ts: &DateTime<Utc>) -> (String, String) {
    (
        ts.format("%m/%d/%Y").to_string(),
        ts.format("%H:%M:%S").to_string(),
    )
}

/// Writes plaso-compatible l2tcsv (timestamps in UTC).
pub fn write_l2tcsv(tl: &Timeline, safe: bool, w: &mut dyn Write) -> io::Result<()> {
    row(w, &L2T_HEADER.map(String::from))?;
    for e in &tl.events {
        let (date, time) = l2t_date_time(&e.ts);
        let macb = if e.source == SourceKind::Bodyfile {
            e.get("macb").unwrap_or("....").to_string()
        } else {
            "....".to_string()
        };
        let short: String = e.description.chars().take(80).collect();
        let mut extra = fields_text(e, "; ", ": ");
        let seen = also_seen_text(e);
        if !seen.is_empty() {
            extra.push_str(&format!("; also_seen: {seen}"));
        }
        let notes = if e.tags.is_empty() {
            "-".to_string()
        } else {
            e.tags.join(" ")
        };
        row(
            w,
            &[
                date,
                time,
                "UTC".into(),
                macb,
                e.source.l2t_short().into(),
                e.source.long_name().into(),
                timestamp_desc(e),
                field(dash(e.user.as_deref()), safe),
                field(dash(e.host.as_deref()), safe),
                field(&short, safe),
                field(&e.description, safe),
                "2".into(),
                field(&e.artifact, safe),
                field(dash(e.get("inode")), safe),
                field(&notes, safe),
                format!("timeliner:{}", e.source),
                field(if extra.is_empty() { "-" } else { &extra }, safe),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, Provenance};
    use crate::pipeline::BuildReport;
    use chrono::TimeZone;

    fn tl() -> Timeline {
        let ts = Utc.with_ymd_and_hms(2025, 1, 1, 4, 9, 3).unwrap();
        let mut a = Event::new(
            ts,
            SourceKind::AuthLog,
            EventKind::SshInvalidUser,
            "var/log/auth.log",
            7,
            "invalid user =cmd|' /C calc'!A0, \"x\"",
        )
        .with_user(Some("=cmd|' /C calc'!A0"))
        .with_field("src_ip", "203.0.113.45");
        a.add_tag("ssh");
        a.also_seen.push(Provenance {
            source: SourceKind::Journal,
            artifact: "journal.export".into(),
            location: 3,
        });
        let b = Event::new(
            ts,
            SourceKind::Bodyfile,
            EventKind::FileActivity,
            "bodyfile.txt",
            2,
            "/tmp/.x.sh [M.CB]",
        )
        .with_field("macb", "M.CB")
        .with_field("inode", "1234");
        Timeline {
            events: vec![a, b],
            report: BuildReport::default(),
        }
    }

    #[test]
    fn quoting_and_formula_guard() {
        assert_eq!(field("a,b", false), "\"a,b\"");
        assert_eq!(field("say \"hi\"", false), "\"say \"\"hi\"\"\"");
        assert_eq!(field("=1+1", true), "'=1+1");
        assert_eq!(field("=1+1", false), "=1+1");
        assert_eq!(field("-", true), "-");
        assert_eq!(field("-rf,x", true), "\"'-rf,x\"");
    }

    #[test]
    fn csv_output() {
        let mut out = Vec::new();
        write_csv(&tl(), true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines[0], CSV_HEADER.join(","));
        assert!(
            lines[1].starts_with("2025-01-01T04:09:03.000000Z,auth_log,ssh_invalid_user,,'=cmd")
        );
        assert!(lines[1].contains("journal.export:3"));
        assert!(lines[2].contains("macb=M.CB"));
    }

    #[test]
    fn l2tcsv_output() {
        let mut out = Vec::new();
        write_l2tcsv(&tl(), true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines[0], L2T_HEADER.join(","));
        assert!(
            lines[1].starts_with("01/01/2025,04:09:03,UTC,....,LOG,Auth Log,Entry Written,'=cmd")
        );
        assert!(lines[1].contains(",ssh,timeliner:auth_log,"));
        assert!(lines[1].contains("also_seen: journal.export:3"));
        assert!(lines[2].starts_with(
            "01/01/2025,04:09:03,UTC,M.CB,FILE,File System (bodyfile),Content Modification Time; Metadata Modification Time; Creation Time,-,-,"
        ));
        assert!(lines[2].contains(",1234,-,timeliner:bodyfile,"));
    }
}
