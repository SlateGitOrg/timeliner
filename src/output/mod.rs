//! Timeline renderers: JSONL, CSV, l2tcsv and a self-contained HTML report.

pub mod csv;
pub mod html;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::str::FromStr;

use crate::event::Severity;
use crate::pipeline::Timeline;
use crate::rules::RuleSet;

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One JSON object per line.
    Jsonl,
    /// timeliner's CSV columns.
    Csv,
    /// log2timeline/plaso `l2tcsv` (17 columns).
    L2tCsv,
    /// Self-contained static HTML report.
    Html,
    /// Aligned plain text for terminals (control characters escaped).
    Text,
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "jsonl" | "json" | "ndjson" => Ok(Format::Jsonl),
            "csv" => Ok(Format::Csv),
            "l2tcsv" | "l2t" => Ok(Format::L2tCsv),
            "html" | "htm" => Ok(Format::Html),
            "text" | "txt" => Ok(Format::Text),
            other => Err(format!(
                "unknown format `{other}` (jsonl, csv, l2tcsv, html, text)"
            )),
        }
    }
}

impl Format {
    /// Guesses the format from an output file name (`.l2t.csv` → l2tcsv).
    pub fn from_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
        if name.ends_with(".l2t.csv") || name.ends_with(".l2tcsv") {
            return Some(Format::L2tCsv);
        }
        name.rsplit_once('.').and_then(|(_, ext)| ext.parse().ok())
    }
}

/// Rendering options.
#[derive(Debug, Clone)]
pub struct OutputOptions {
    /// Neutralize spreadsheet formulas in attacker-controlled CSV cells.
    pub csv_safe: bool,
    /// Maximum events embedded in the HTML timeline table (rule hits are always kept).
    pub html_max_events: usize,
    /// Report title.
    pub title: String,
    /// Rule id → (title, severity), for reports.
    pub rule_info: BTreeMap<String, (String, Severity)>,
}

impl Default for OutputOptions {
    fn default() -> Self {
        OutputOptions {
            csv_safe: true,
            html_max_events: 50_000,
            title: "timeliner report".into(),
            rule_info: BTreeMap::new(),
        }
    }
}

impl OutputOptions {
    /// Copies rule titles and severities from a ruleset.
    pub fn with_rules(mut self, rules: &RuleSet) -> Self {
        self.rule_info = rules
            .rules
            .iter()
            .map(|r| (r.id.clone(), (r.title.clone(), r.severity)))
            .collect();
        self
    }
}

/// Writes JSONL.
pub fn write_jsonl(tl: &Timeline, w: &mut dyn Write) -> io::Result<()> {
    for e in &tl.events {
        serde_json::to_writer(&mut *w, e)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

/// Escapes control characters (including ANSI escape sequences planted in
/// logs) so that terminal output cannot be manipulated by artifact content.
pub fn terminal_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Writes one aligned line per event.
pub fn write_text(tl: &Timeline, w: &mut dyn Write) -> io::Result<()> {
    for e in &tl.events {
        let tags = if e.tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", e.tags.join(", "))
        };
        writeln!(
            w,
            "{}  {:<8}  {:<20}  {:<10}  {}{}",
            e.ts.format("%Y-%m-%dT%H:%M:%SZ"),
            e.max_severity().map_or("-", |s| s.as_str()),
            e.kind.as_str(),
            terminal_safe(e.user.as_deref().unwrap_or("-")),
            terminal_safe(&e.description),
            terminal_safe(&tags)
        )?;
    }
    Ok(())
}

/// Renders the timeline in `format`.
pub fn write(
    tl: &Timeline,
    format: Format,
    opts: &OutputOptions,
    w: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Jsonl => write_jsonl(tl, w),
        Format::Csv => csv::write_csv(tl, opts.csv_safe, w),
        Format::L2tCsv => csv::write_l2tcsv(tl, opts.csv_safe, w),
        Format::Html => html::write_html(tl, opts, w),
        Format::Text => write_text(tl, w),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parsing() {
        assert_eq!("JSONL".parse::<Format>(), Ok(Format::Jsonl));
        assert_eq!("l2t".parse::<Format>(), Ok(Format::L2tCsv));
        assert!("xml".parse::<Format>().is_err());
        assert_eq!("txt".parse::<Format>(), Ok(Format::Text));
        assert_eq!(Format::from_path(Path::new("t.txt")), Some(Format::Text));
        assert_eq!(
            Format::from_path(Path::new("out/t.l2t.csv")),
            Some(Format::L2tCsv)
        );
        assert_eq!(Format::from_path(Path::new("t.html")), Some(Format::Html));
        assert_eq!(Format::from_path(Path::new("t.csv")), Some(Format::Csv));
        assert_eq!(Format::from_path(Path::new("t")), None);
        let opts = OutputOptions::default().with_rules(&RuleSet::default_rules());
        assert!(opts.rule_info.contains_key("ssh-bruteforce"));
    }

    #[test]
    fn text_output_escapes_terminal_controls() {
        use crate::event::{Event, EventKind, SourceKind};
        use crate::pipeline::BuildReport;
        use chrono::{TimeZone, Utc};
        assert_eq!(
            terminal_safe("a\x1b[31mb\nc\td\r"),
            "a\\u{1b}[31mb\\nc\\td\\r"
        );
        let mut e = Event::new(
            Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            SourceKind::AuthLog,
            EventKind::SshInvalidUser,
            "a",
            1,
            "invalid user \x1b]0;pwned\x07",
        );
        e.add_tag("t");
        let tl = Timeline {
            events: vec![e],
            report: BuildReport::default(),
        };
        let mut out = Vec::new();
        write(&tl, Format::Text, &OutputOptions::default(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\x1b'));
        assert!(text.starts_with("2025-01-01T00:00:00Z  -         ssh_invalid_user      -           invalid user \\u{1b}]0;pwned\\u{7}  [t]"));
    }
}
