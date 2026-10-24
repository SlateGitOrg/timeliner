//! End-to-end timeline construction.
//!
//! ```text
//! discover ─▶ phase A: parse absolute-time artifacts (parallel)
//!                 │  newest absolute timestamp ─▶ year anchor
//!                 ▼
//!             phase B: parse year-less logs (parallel)
//!                 ▼
//!             sort (ts, source, artifact, location) ─▶ dedup ─▶ rules ─▶ range filter
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{DateTime, Datelike, Duration, Utc};
use serde::Serialize;
use tracing::{info, warn};

use crate::dedup;
use crate::discover::{self, ArtifactFile, DEFAULT_MAX_DECOMPRESSED};
use crate::error::{Result, Warning};
use crate::event::Event;
use crate::parsers::{ArtifactKind, ParseContext, ParseOutput, user_from_path};
use crate::rules::RuleSet;
use crate::time::TimeZone;
use crate::time::year::YearAnchor;

/// Options for [`build`].
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Explicit zone for local timestamps (overrides the evidence's own zone).
    pub tz: Option<TimeZone>,
    /// Directory with IANA TZif files (for `etc/timezone` names).
    pub zoneinfo_dir: PathBuf,
    /// Year of the newest entry in year-less logs (overrides inference).
    pub year: Option<i32>,
    /// Host name override.
    pub host: Option<String>,
    /// Tagging rules (none = no tagging).
    pub rules: Option<RuleSet>,
    /// Merge cross-artifact duplicates.
    pub dedup: bool,
    /// Duplicate time tolerance.
    pub dedup_window: Duration,
    /// Keep events at or after this instant.
    pub from: Option<DateTime<Utc>>,
    /// Keep events at or before this instant.
    pub to: Option<DateTime<Utc>>,
    /// Worker threads (0 = available parallelism).
    pub threads: usize,
    /// Cap on decompressed `.gz` size.
    pub max_decompressed: u64,
    /// Fallback "now" used when no anchor exists (injected for determinism).
    pub now: DateTime<Utc>,
}

impl Default for BuildOptions {
    fn default() -> Self {
        BuildOptions {
            tz: None,
            zoneinfo_dir: PathBuf::from("/usr/share/zoneinfo"),
            year: None,
            host: None,
            rules: Some(RuleSet::default_rules()),
            dedup: true,
            dedup_window: Duration::seconds(2),
            from: None,
            to: None,
            threads: 0,
            max_decompressed: DEFAULT_MAX_DECOMPRESSED,
            now: Utc::now(),
        }
    }
}

/// Per-artifact statistics.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ArtifactReport {
    /// Display path.
    pub path: String,
    /// Detected format.
    pub kind: ArtifactKind,
    /// Lines / records examined.
    pub records: u64,
    /// Events produced (before dedup).
    pub events: u64,
    /// Warnings raised.
    pub warnings: u64,
    /// Read error, if the file could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Build summary.
#[derive(Debug, Clone, Serialize, Default)]
pub struct BuildReport {
    /// Per-artifact statistics, in discovery order.
    pub artifacts: Vec<ArtifactReport>,
    /// Zone used for local timestamps.
    pub timezone: String,
    /// Where the zone came from.
    pub timezone_source: String,
    /// How years were inferred.
    pub year_anchor: String,
    /// Host name used for artifacts that do not record one.
    pub host: Option<String>,
    /// Events produced by parsers.
    pub parsed_events: u64,
    /// Duplicates merged.
    pub duplicates_merged: u64,
    /// Events in the final timeline.
    pub events: u64,
    /// Hits per rule id.
    pub rule_hits: BTreeMap<String, u64>,
    /// Stored warnings (capped per artifact).
    pub warnings: Vec<Warning>,
    /// Earliest and latest event.
    pub first: Option<String>,
    /// Latest event.
    pub last: Option<String>,
}

/// A built timeline.
#[derive(Debug, Clone)]
pub struct Timeline {
    /// Events sorted by time.
    pub events: Vec<Event>,
    /// Build summary.
    pub report: BuildReport,
}

/// Result of parsing one artifact: output plus a read error, if any.
type FileResult = (ParseOutput, Option<String>);

fn parse_parallel(
    files: &[&ArtifactFile],
    make_ctx: &(dyn Fn(&ArtifactFile) -> ParseContext + Sync),
    threads: usize,
    max_decompressed: u64,
) -> Vec<FileResult> {
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<FileResult>>> = files.iter().map(|_| Mutex::new(None)).collect();
    let workers = threads.clamp(1, files.len().max(1));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(f) = files.get(i) else { break };
                    let res = match discover::read_artifact(&f.path, max_decompressed) {
                        Ok(data) => (f.kind.parse(&data, &make_ctx(f)), None),
                        Err(e) => {
                            warn!(artifact = %f.display, error = %e, "cannot read artifact");
                            (ParseOutput::default(), Some(e.to_string()))
                        }
                    };
                    if let Ok(mut slot) = results[i].lock() {
                        *slot = Some(res);
                    }
                }
            });
        }
    });
    results
        .into_iter()
        .map(|m| {
            m.into_inner()
                .ok()
                .flatten()
                .unwrap_or_else(|| (ParseOutput::default(), Some("worker failed".into())))
        })
        .collect()
}

/// Builds a timeline from already-discovered artifacts.
pub fn build_from_files(files: &[ArtifactFile], opts: &BuildOptions) -> Result<Timeline> {
    let mut report = BuildReport::default();

    // Context from the first evidence root that has one.
    let mut ev_ctx = discover::EvidenceContext::default();
    let mut roots: Vec<&PathBuf> = files.iter().filter_map(|f| f.root.as_ref()).collect();
    roots.dedup();
    for root in roots {
        let c = discover::evidence_context(root, &opts.zoneinfo_dir);
        if ev_ctx.timezone.is_none() {
            ev_ctx.timezone = c.timezone;
        }
        if ev_ctx.hostname.is_none() {
            ev_ctx.hostname = c.hostname;
        }
    }
    let (tz, tz_source) = match (&opts.tz, ev_ctx.timezone) {
        (Some(tz), _) => (tz.clone(), "command line".to_string()),
        (None, Some((tz, src))) => (tz, src),
        (None, None) => {
            warn!("no time zone given or found in the evidence; assuming UTC for local timestamps");
            (TimeZone::utc(), "default (UTC, unverified)".to_string())
        }
    };
    report.timezone = tz.label().to_string();
    report.timezone_source = tz_source;
    let host = opts.host.clone().or(ev_ctx.hostname);
    report.host = host.clone();
    let threads = if opts.threads == 0 {
        std::thread::available_parallelism().map_or(4, |n| n.get())
    } else {
        opts.threads
    };

    let ctx_for = |f: &ArtifactFile, anchor: YearAnchor| ParseContext {
        artifact: f.display.clone(),
        tz: tz.clone(),
        year_anchor: anchor,
        host: host.clone(),
        user: user_from_path(&f.display),
    };

    // Phase A: everything that does not need year inference.
    let (b_files, a_files): (Vec<&ArtifactFile>, Vec<&ArtifactFile>) =
        files.iter().partition(|f| f.kind.needs_year_inference());
    let placeholder = YearAnchor::Explicit(1970);
    let a_results = parse_parallel(
        &a_files,
        &|f| ctx_for(f, placeholder),
        threads,
        opts.max_decompressed,
    );
    let newest = a_files
        .iter()
        .zip(&a_results)
        .filter(|(f, _)| f.kind.anchors_years())
        .flat_map(|(_, (o, _))| o.events.iter().map(|e| e.ts))
        .max();
    let anchor = match (opts.year, newest) {
        (Some(y), _) => {
            report.year_anchor = format!("--year {y}: newest year-less entry is in {y}");
            YearAnchor::Explicit(y)
        }
        (None, Some(t)) => {
            let limit = tz.to_local(t) + Duration::days(1);
            report.year_anchor = format!(
                "inferred: year-less entries end no later than {} local (newest absolute timestamp + 1 day)",
                limit.format("%Y-%m-%d %H:%M:%S")
            );
            YearAnchor::NotAfter(limit)
        }
        (None, None) => {
            let y = opts.now.year();
            report.year_anchor = format!(
                "fallback: no absolute timestamps found; assuming newest entry is in {y} (pass --year)"
            );
            if !b_files.is_empty() {
                warn!(
                    "year anchor fell back to the current year; pass --year for reliable results"
                );
            }
            YearAnchor::Explicit(y)
        }
    };
    let b_results = parse_parallel(
        &b_files,
        &|f| ctx_for(f, anchor),
        threads,
        opts.max_decompressed,
    );

    let mut events = Vec::new();
    let mut per_file: Vec<(&ArtifactFile, ParseOutput, Option<String>)> = a_files
        .into_iter()
        .zip(a_results)
        .chain(b_files.into_iter().zip(b_results))
        .map(|(f, (o, e))| (f, o, e))
        .collect();
    let order: BTreeMap<&str, usize> = files
        .iter()
        .enumerate()
        .map(|(i, f)| (f.display.as_str(), i))
        .collect();
    per_file.sort_by_key(|(f, _, _)| order.get(f.display.as_str()).copied().unwrap_or(usize::MAX));
    for (f, out, error) in per_file {
        report.artifacts.push(ArtifactReport {
            path: f.display.clone(),
            kind: f.kind,
            records: out.records,
            events: out.events.len() as u64,
            warnings: out.warning_count,
            error,
        });
        report.warnings.extend(out.warnings);
        events.extend(out.events);
    }
    report.parsed_events = events.len() as u64;

    events.sort_by(|a, b| {
        (a.ts, a.source, &a.artifact, a.location).cmp(&(b.ts, b.source, &b.artifact, b.location))
    });
    if opts.dedup {
        let (deduped, merged) = dedup::dedup(events, opts.dedup_window);
        events = deduped;
        report.duplicates_merged = merged;
    }
    if let Some(rules) = &opts.rules {
        report.rule_hits = rules.apply(&mut events);
    }
    events.retain(|e| opts.from.is_none_or(|f| e.ts >= f) && opts.to.is_none_or(|t| e.ts <= t));
    report.events = events.len() as u64;
    report.first = events.first().map(|e| crate::event::format_ts(&e.ts));
    report.last = events.last().map(|e| crate::event::format_ts(&e.ts));
    info!(
        events = report.events,
        merged = report.duplicates_merged,
        artifacts = report.artifacts.len(),
        "timeline built"
    );
    Ok(Timeline { events, report })
}

/// Discovers artifacts under `inputs` and builds the timeline.
pub fn build(inputs: &[discover::InputSpec], opts: &BuildOptions) -> Result<Timeline> {
    let files = discover::discover(inputs)?;
    build_from_files(&files, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::InputSpec;
    use crate::event::EventKind;
    use chrono::TimeZone as _;
    use std::fs;

    fn write(root: &std::path::Path, rel: &str, data: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }

    #[test]
    fn anchors_years_from_absolute_artifacts_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "etc/hostname", b"web01\n");
        write(
            root,
            "var/log/auth.log",
            b"Dec 31 23:59:59 web01 sshd[1]: Accepted password for a from 1.2.3.4 port 5 ssh2\n\
Jan  1 00:00:10 web01 sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n",
        );
        write(
            root,
            "var/log/syslog",
            b"Jan  1 00:00:10 web01 sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n",
        );
        write(root, "home/a/.bash_history", b"#1735689620\nid\n");
        let opts = BuildOptions {
            tz: Some(TimeZone::utc()),
            ..BuildOptions::default()
        };
        let tl = build(&[InputSpec::parse(root.to_str().unwrap())], &opts).unwrap();
        assert_eq!(tl.report.parsed_events, 4);
        assert_eq!(tl.report.duplicates_merged, 1);
        assert_eq!(tl.events.len(), 3);
        assert_eq!(
            tl.events[0].ts,
            Utc.with_ymd_and_hms(2024, 12, 31, 23, 59, 59).unwrap()
        );
        assert_eq!(tl.events[1].kind, EventKind::SshLoginFailure);
        assert_eq!(tl.events[1].also_seen.len(), 1);
        assert_eq!(tl.events[2].kind, EventKind::ShellCommand);
        assert_eq!(tl.report.host.as_deref(), Some("web01"));
        assert!(tl.report.year_anchor.starts_with("inferred"));
        assert_eq!(tl.report.timezone_source, "command line");
        assert_eq!(tl.report.artifacts[0].path, "home/a/.bash_history");
    }

    #[test]
    fn explicit_year_range_filter_and_fallbacks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "var/log/syslog",
            b"Jun  1 10:00:00 h app: one\nJun  2 10:00:00 h app: two\n",
        );
        let input = [InputSpec::parse(root.to_str().unwrap())];
        let opts = BuildOptions {
            year: Some(2023),
            rules: None,
            from: Some(Utc.with_ymd_and_hms(2023, 6, 2, 0, 0, 0).unwrap()),
            threads: 1,
            ..BuildOptions::default()
        };
        let tl = build(&input, &opts).unwrap();
        assert_eq!(tl.events.len(), 1);
        assert_eq!(tl.report.timezone, "UTC");
        assert!(tl.report.timezone_source.contains("unverified"));
        let opts = BuildOptions {
            now: Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
            to: Some(Utc.with_ymd_and_hms(2030, 6, 1, 12, 0, 0).unwrap()),
            dedup: false,
            ..BuildOptions::default()
        };
        let tl = build(&input, &opts).unwrap();
        assert!(tl.report.year_anchor.starts_with("fallback"));
        assert_eq!(tl.events.len(), 1);
        assert_eq!(tl.events[0].ts.year(), 2030);
    }

    #[test]
    fn unreadable_artifact_is_reported_not_fatal() {
        let files = vec![ArtifactFile {
            path: PathBuf::from("/definitely/missing/wtmp"),
            display: "wtmp".into(),
            kind: ArtifactKind::Wtmp,
            root: None,
        }];
        let tl = build_from_files(&files, &BuildOptions::default()).unwrap();
        assert!(tl.events.is_empty());
        assert!(tl.report.artifacts[0].error.is_some());
    }
}
