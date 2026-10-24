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

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use tracing::{info, warn};

use crate::dedup;
use crate::discover::{self, ArtifactFile, DEFAULT_MAX_DECOMPRESSED};
use crate::error::{Result, Warning};
use crate::event::Event;
use crate::parsers::{AnchorTier, ArtifactKind, ParseContext, ParseOutput, user_from_path};
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

/// Clock-skew slack added to the year anchor.
const ANCHOR_SLACK: Duration = Duration::days(1);
/// A tail of anchor timestamps separated from the rest by more than this is
/// rejected as forged or corrupt (a genuine gap would have to exceed a year).
const ANCHOR_OUTLIER_GAP: Duration = Duration::days(366);
/// The tail rejected as outliers is at most this fraction of the timestamps (at least one).
const ANCHOR_OUTLIER_FRACTION: usize = 100;
/// Warn when one artifact alone pushes the anchor this far past every other.
const ANCHOR_SPREAD_WARN: Duration = Duration::days(30);

/// An anchoring artifact's display name and its absolute timestamps.
type ArtifactStamps<'a> = (&'a str, Vec<DateTime<Utc>>);

/// Newest anchor timestamp after outlier rejection, plus what was rejected or looks odd.
#[derive(Debug, Default, PartialEq)]
struct AnchorPick {
    newest: Option<DateTime<Utc>>,
    notes: Vec<String>,
}

/// Picks the year anchor from per-artifact absolute timestamps without
/// letting a handful of forged values move it:
///
/// 1. timestamps later than the analysis clock (`now` + slack) are impossible
///    for collected evidence and are dropped;
/// 2. the sorted tail is trimmed when at most 1 % of the values (at least one)
///    sit more than [`ANCHOR_OUTLIER_GAP`] after all the others;
/// 3. a warning is raised when the newest artifact alone is more than
///    [`ANCHOR_SPREAD_WARN`] ahead of every other anchoring artifact.
///
/// O(n log n) time, O(n) space in the number of timestamps.
fn robust_newest(per_artifact: &[ArtifactStamps<'_>], now: DateTime<Utc>) -> AnchorPick {
    let mut notes = Vec::new();
    let latest_possible = now + ANCHOR_SLACK;
    let mut all = Vec::new();
    for (artifact, ts) in per_artifact {
        let before = all.len();
        all.extend(ts.iter().copied().filter(|t| *t <= latest_possible));
        let future = ts.len() - (all.len() - before);
        if future > 0 {
            notes.push(format!(
                "ignored {future} timestamp(s) in {artifact} later than the analysis clock ({})",
                crate::event::format_ts(&now)
            ));
        }
    }
    all.sort_unstable();
    let n = all.len();
    let max_tail = (n / ANCHOR_OUTLIER_FRACTION).max(1);
    // Largest tail (≤ max_tail) cut off from the bulk by a gap over the limit.
    if let Some(tail) = (1..=max_tail.min(n.saturating_sub(1)))
        .rev()
        .find(|&j| all[n - j] - all[n - j - 1] > ANCHOR_OUTLIER_GAP)
    {
        let kept = all[n - tail - 1];
        let rejected: Vec<&str> = per_artifact
            .iter()
            .filter(|(_, ts)| ts.iter().any(|t| *t > kept && *t <= latest_possible))
            .map(|(a, _)| *a)
            .collect();
        notes.push(format!(
            "ignored {tail} outlying timestamp(s) (up to {}) in {} more than {} days after the rest of the evidence (newest kept: {})",
            crate::event::format_ts(&all[n - 1]),
            rejected.join(", "),
            ANCHOR_OUTLIER_GAP.num_days(),
            crate::event::format_ts(&kept)
        ));
        all.truncate(n - tail);
    }
    let newest = all.last().copied();
    if let Some(limit) = newest {
        let mut tops: Vec<(DateTime<Utc>, &str)> = per_artifact
            .iter()
            .filter_map(|(a, ts)| {
                ts.iter()
                    .copied()
                    .filter(|t| *t <= limit)
                    .max()
                    .map(|t| (t, *a))
            })
            .collect();
        tops.sort_unstable_by(|x, y| y.cmp(x));
        if let [(first, artifact), (second, _), ..] = tops.as_slice()
            && *first - *second > ANCHOR_SPREAD_WARN
        {
            notes.push(format!(
                "the anchor ({}) comes from {artifact} alone, {} days after the newest record of any other anchoring artifact ({})",
                crate::event::format_ts(first),
                (*first - *second).num_days(),
                crate::event::format_ts(second)
            ));
        }
    }
    AnchorPick { newest, notes }
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
    // Anchor on system records; shell histories only when there are none.
    let mut tiers: BTreeMap<AnchorTier, Vec<ArtifactStamps<'_>>> = BTreeMap::new();
    for (f, (o, _)) in a_files.iter().zip(&a_results) {
        if let Some(tier) = f.kind.anchor_tier() {
            tiers
                .entry(tier)
                .or_default()
                .push((f.display.as_str(), o.events.iter().map(|e| e.ts).collect()));
        }
    }
    let mut anchor_notes = Vec::new();
    let mut newest = None;
    for (tier, per_artifact) in &tiers {
        let pick = robust_newest(per_artifact, opts.now);
        anchor_notes.extend(pick.notes);
        if let Some(t) = pick.newest {
            if *tier == AnchorTier::UserWritable {
                anchor_notes.push(
                    "no system record (wtmp/btmp/utmp, journal, dpkg/apt) holds an absolute \
                     timestamp; the year anchor relies on user-writable shell history, pass \
                     --year if it may have been tampered with"
                        .to_string(),
                );
            }
            newest = Some((t, *tier));
            break;
        }
    }
    let anchor = match (opts.year, newest) {
        (Some(y), _) => {
            anchor_notes.clear();
            report.year_anchor = format!("--year {y}: newest year-less entry is in {y}");
            YearAnchor::Explicit(y)
        }
        (None, Some((t, tier))) => {
            let limit = tz.to_local(t) + ANCHOR_SLACK;
            let source = match tier {
                AnchorTier::System => "newest system-record timestamp",
                AnchorTier::UserWritable => "newest shell-history timestamp",
            };
            report.year_anchor = format!(
                "inferred: year-less entries end no later than {} local ({source} + 1 day)",
                limit.format("%Y-%m-%d %H:%M:%S")
            );
            YearAnchor::NotAfter(limit)
        }
        (None, None) => {
            // No absolute evidence: the analysis clock is still an upper
            // bound (logs cannot be from the future), which keeps rotated
            // files in the right year, unlike pinning to the current year.
            let limit = tz.to_local(opts.now) + ANCHOR_SLACK;
            report.year_anchor = format!(
                "fallback: no absolute timestamps found; assuming year-less entries end no later than {} local (analysis clock + 1 day; pass --year)",
                limit.format("%Y-%m-%d %H:%M:%S")
            );
            if !b_files.is_empty() {
                warn!(
                    "year anchor fell back to the analysis clock; pass --year for reliable results"
                );
            }
            YearAnchor::NotAfter(limit)
        }
    };
    if !b_files.is_empty() {
        for note in anchor_notes {
            warn!("year anchor: {note}");
            report.year_anchor.push_str("; WARNING: ");
            report.year_anchor.push_str(&note);
            report.warnings.push(Warning {
                artifact: "(year anchor)".into(),
                location: 0,
                message: note,
            });
        }
    }
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
        // No absolute timestamps: the analysis clock caps the entries, so
        // June entries analysed on 2030-01-01 belong to 2029, not 2030.
        let opts = BuildOptions {
            now: Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
            to: Some(Utc.with_ymd_and_hms(2029, 6, 1, 12, 0, 0).unwrap()),
            dedup: false,
            ..BuildOptions::default()
        };
        let tl = build(&input, &opts).unwrap();
        assert!(tl.report.year_anchor.starts_with("fallback"));
        assert!(tl.report.year_anchor.contains("2030-01-02 00:00:00"));
        assert_eq!(tl.events.len(), 1);
        assert_eq!(
            tl.events[0].ts,
            Utc.with_ymd_and_hms(2029, 6, 1, 10, 0, 0).unwrap()
        );
    }

    fn at(y: i32, mo: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, 12, 0, 0).unwrap()
    }

    fn days(y: i32, mo: u32, d: u32, n: i64) -> Vec<DateTime<Utc>> {
        (0..n).map(|i| at(y, mo, d) + Duration::days(i)).collect()
    }

    /// Review finding: loose rotated logs with no absolute timestamps were
    /// pinned to the *current year*, putting Nov/Dec entries in the future and
    /// after the newer file. The clock is an upper bound, not a year.
    #[test]
    fn clock_fallback_keeps_rotated_logs_in_the_past_and_in_order() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "auth.log", b"Jan  2 10:00:00 h sshd[1]: a\n");
        write(root, "auth.log.1", b"Dec 30 10:00:00 h sshd[1]: b\n");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"Nov 30 10:00:00 h sshd[1]: c\n").unwrap();
        write(root, "auth.log.2.gz", &gz.finish().unwrap());
        let now = Utc.with_ymd_and_hms(2026, 10, 24, 9, 0, 0).unwrap();
        let opts = BuildOptions {
            tz: Some(TimeZone::utc()),
            rules: None,
            now,
            ..BuildOptions::default()
        };
        let tl = build(&[InputSpec::parse(root.to_str().unwrap())], &opts).unwrap();
        let got: Vec<_> = tl.events.iter().map(|e| (e.ts, e.raw.clone())).collect();
        assert_eq!(got.len(), 3);
        assert_eq!(
            got[0].0,
            Utc.with_ymd_and_hms(2025, 11, 30, 10, 0, 0).unwrap()
        );
        assert!(got[0].1.ends_with(": c"));
        assert_eq!(
            got[1].0,
            Utc.with_ymd_and_hms(2025, 12, 30, 10, 0, 0).unwrap()
        );
        assert!(got[1].1.ends_with(": b"));
        assert_eq!(
            got[2].0,
            Utc.with_ymd_and_hms(2026, 1, 2, 10, 0, 0).unwrap()
        );
        assert!(tl.events.iter().all(|e| e.ts <= now));
        assert!(tl.report.year_anchor.starts_with("fallback"));
    }

    /// Review finding: one `#<epoch>` line appended to a shell history moved
    /// every year-less entry decades ahead. System records now take
    /// precedence, and history-only anchors reject future and outlying values.
    #[test]
    fn forged_history_timestamps_cannot_move_the_anchor() {
        let syslog =
            b"Dec 31 23:59:59 web01 sshd[1]: Accepted password for a from 1.2.3.4 port 5 ssh2\n\
Jan  1 00:00:10 web01 sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n";
        let now = Utc.with_ymd_and_hms(2026, 10, 24, 0, 0, 0).unwrap();
        let opts = BuildOptions {
            tz: Some(TimeZone::utc()),
            rules: None,
            now,
            ..BuildOptions::default()
        };
        let jan1 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 10).unwrap();

        // 1. A system record exists: user-writable history is not consulted.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "var/log/auth.log", syslog);
        write(
            root,
            "var/log/dpkg.log",
            b"2025-01-01 00:20:00 install curl:amd64 <none> 8.0\n",
        );
        // 2050-01-01 (future) and 2026-06-01 (past the clock-check, far ahead).
        write(
            root,
            "home/deploy/.bash_history",
            b"#1735689620\nid\n#2524608000\necho future\n#1780315200\necho later\n",
        );
        let tl = build(&[InputSpec::parse(root.to_str().unwrap())], &opts).unwrap();
        assert!(tl.events.iter().any(|e| e.ts == jan1));
        assert!(
            tl.report.year_anchor.contains("2025-01-02 00:20:00")
                && tl.report.year_anchor.contains("system-record"),
            "{}",
            tl.report.year_anchor
        );

        // 2. History is the only absolute source: the future value and the
        //    lone value more than a year past the rest are both rejected, and
        //    the report says so.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "var/log/auth.log", syslog);
        let mut hist = String::new();
        for i in 0..50 {
            hist.push_str(&format!("#{}\ncmd{i}\n", 1_735_690_000 + i * 60));
        }
        hist.push_str("#2524608000\necho future\n#1780315200\necho later\n");
        write(root, "home/deploy/.bash_history", hist.as_bytes());
        let tl = build(&[InputSpec::parse(root.to_str().unwrap())], &opts).unwrap();
        assert!(
            tl.events.iter().any(|e| e.ts == jan1),
            "{}",
            tl.report.year_anchor
        );
        let y = &tl.report.year_anchor;
        assert!(
            y.starts_with("inferred") && y.contains("shell-history"),
            "{y}"
        );
        assert!(y.contains("later than the analysis clock"), "{y}");
        assert!(y.contains("1 outlying timestamp"), "{y}");
        assert!(y.contains("user-writable"), "{y}");
        assert_eq!(tl.report.warnings.len(), 3, "{:?}", tl.report.warnings);
        assert!(
            tl.report
                .warnings
                .iter()
                .all(|w| w.artifact == "(year anchor)")
        );
    }

    #[test]
    fn robust_newest_rejects_only_small_far_tails() {
        let now = at(2026, 10, 24);
        // Empty input.
        assert_eq!(robust_newest(&[], now), AnchorPick::default());
        // A single value is kept even if it is the only one.
        let p = robust_newest(&[("wtmp", vec![at(2024, 1, 1)])], now);
        assert_eq!(p.newest, Some(at(2024, 1, 1)));
        assert!(p.notes.is_empty());
        // Clock slack: up to one day ahead of `now` is accepted.
        let p = robust_newest(&[("wtmp", vec![now + Duration::hours(20)])], now);
        assert_eq!(p.newest, Some(now + Duration::hours(20)));
        // Two outliers out of 200 (= 1 %) are trimmed together.
        let mut ts = days(2024, 1, 1, 198);
        ts.push(at(2025, 9, 1));
        ts.push(at(2025, 10, 1));
        let p = robust_newest(&[("wtmp", ts)], now);
        assert_eq!(p.newest, Some(at(2024, 1, 1) + Duration::days(197)));
        assert!(p.notes[0].contains("ignored 2 outlying"), "{:?}", p.notes);
        // Three far values out of 200 are more than 1 %: kept (they are bulk).
        let mut ts = days(2024, 1, 1, 197);
        ts.extend([at(2025, 9, 1), at(2025, 9, 2), at(2025, 9, 3)]);
        let p = robust_newest(&[("wtmp", ts)], now);
        assert_eq!(p.newest, Some(at(2025, 9, 3)));
        // A gap under a year is a quiet period, not an outlier.
        let p = robust_newest(&[("wtmp", vec![at(2024, 1, 1), at(2024, 12, 1)])], now);
        assert_eq!(p.newest, Some(at(2024, 12, 1)));
        assert!(p.notes.is_empty());
    }

    #[test]
    fn robust_newest_warns_when_one_artifact_drives_the_anchor() {
        let now = at(2026, 10, 24);
        let p = robust_newest(
            &[
                ("var/log/wtmp", days(2024, 12, 1, 20)),
                ("var/log/dpkg.log", vec![at(2025, 6, 1)]),
            ],
            now,
        );
        assert_eq!(p.newest, Some(at(2025, 6, 1)));
        assert_eq!(p.notes.len(), 1);
        assert!(
            p.notes[0].contains("var/log/dpkg.log alone"),
            "{:?}",
            p.notes
        );
        // Artifacts that agree raise nothing.
        let p = robust_newest(
            &[
                ("var/log/wtmp", days(2024, 12, 1, 20)),
                ("journal", days(2024, 12, 5, 20)),
            ],
            now,
        );
        assert!(p.notes.is_empty());
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
