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
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "jsonl" | "json" | "ndjson" => Ok(Format::Jsonl),
            "csv" => Ok(Format::Csv),
            "l2tcsv" | "l2t" => Ok(Format::L2tCsv),
            "html" | "htm" => Ok(Format::Html),
            other => Err(format!(
                "unknown format `{other}` (jsonl, csv, l2tcsv, html)"
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
}
