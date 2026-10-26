//! Ground-truth story recovery on the synthetic incident.
//!
//! The committed fixture (`fixtures/incident`) and a freshly generated copy
//! must both yield every documented step, with the expected tags, in
//! chronological order. Negative controls show that the ordering genuinely
//! depends on time-zone normalization and on year inference.

use std::fs;
use std::path::{Path, PathBuf};

use timeliner::discover::{self, InputSpec};
use timeliner::fixtures::{self, FixtureOptions, GroundTruth, check_story};
use timeliner::output::{self, Format, OutputOptions};
use timeliner::parsers::ArtifactKind;
use timeliner::pipeline::{self, BuildOptions, Timeline};
use timeliner::rules::RuleSet;
use timeliner::time::TimeZone;

fn committed() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/incident")
}

fn build(evidence: &Path, opts: &BuildOptions) -> Timeline {
    pipeline::build(&[InputSpec::parse(evidence.to_str().unwrap())], opts).unwrap()
}

fn truth() -> GroundTruth {
    fixtures::load_ground_truth(&committed().join("GROUND_TRUTH.json")).unwrap()
}

#[test]
fn committed_fixture_recovers_every_step_in_order() {
    let tl = build(&committed().join("evidence"), &BuildOptions::default());
    let check = check_story(&truth(), &tl.events);
    let missing: Vec<_> = check.found.iter().filter(|(_, i)| i.is_none()).collect();
    assert!(missing.is_empty(), "missing steps: {missing:?}");
    assert!(
        check.missing_tags.is_empty(),
        "untagged: {:?}",
        check.missing_tags
    );
    assert!(check.in_order, "steps out of order: {:?}", check.found);
    assert!(check.passed());

    // The zone came from the evidence's own etc/localtime symlink, re-rooted.
    assert_eq!(tl.report.timezone, "America/New_York");
    assert_eq!(tl.report.timezone_source, "evidence etc/localtime");
    assert_eq!(tl.report.host.as_deref(), Some("web01"));
    // Year inference put every syslog-family event into 2024-12 / 2025-01.
    for e in &tl.events {
        if e.time_flags.year_inferred {
            let y = e.ts.format("%Y-%m").to_string();
            assert!(y == "2024-12" || y == "2025-01", "{y}: {}", e.raw);
        }
    }
    // No parser warnings on well-formed evidence.
    assert!(tl.report.warnings.is_empty(), "{:?}", tl.report.warnings);
}

#[test]
fn committed_fixture_is_reproducible_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let fresh = fixtures::generate(dir.path(), &FixtureOptions::default()).unwrap();
    assert_eq!(fresh, truth());
    let root = committed();
    let files =
        discover::discover(&[InputSpec::parse(root.join("evidence").to_str().unwrap())]).unwrap();
    assert_eq!(files.len(), 14);
    for f in &files {
        let rel = f.path.strip_prefix(&root).unwrap();
        assert_eq!(
            fs::read(&f.path).unwrap(),
            fs::read(dir.path().join(rel)).unwrap(),
            "{} differs from a fresh generation; run `make fixtures`",
            rel.display()
        );
    }
    for extra in ["GROUND_TRUTH.json", "STORY.md", "evidence/bodyfile.txt"] {
        assert_eq!(
            fs::read(root.join(extra)).unwrap(),
            fs::read(dir.path().join(extra)).unwrap(),
            "{extra}"
        );
    }
}

#[test]
fn other_seeds_and_scales_still_recover_the_story() {
    for (seed, scale) in [(2, 1), (99, 3)] {
        let dir = tempfile::tempdir().unwrap();
        let t = fixtures::generate(dir.path(), &FixtureOptions { seed, scale }).unwrap();
        let tl = build(&dir.path().join("evidence"), &BuildOptions::default());
        assert!(
            check_story(&t, &tl.events).passed(),
            "seed {seed} scale {scale}"
        );
    }
}

#[test]
fn wrong_time_zone_breaks_the_story() {
    let opts = BuildOptions {
        tz: Some(TimeZone::utc()),
        ..BuildOptions::default()
    };
    let tl = build(&committed().join("evidence"), &opts);
    assert!(!check_story(&truth(), &tl.events).passed());
}

/// Without the journal (which carries absolute copies of every syslog line),
/// the year-less logs are the only source for several steps; a wrong year
/// loses them while inference finds them.
#[test]
fn year_inference_is_load_bearing_without_the_journal() {
    let root = committed().join("evidence");
    let files: Vec<_> = discover::discover(&[InputSpec::parse(root.to_str().unwrap())])
        .unwrap()
        .into_iter()
        .filter(|f| f.kind != ArtifactKind::JournalExport)
        .collect();
    let inferred = pipeline::build_from_files(&files, &BuildOptions::default()).unwrap();
    assert!(check_story(&truth(), &inferred.events).passed());
    let wrong = pipeline::build_from_files(
        &files,
        &BuildOptions {
            year: Some(2024),
            ..BuildOptions::default()
        },
    )
    .unwrap();
    let check = check_story(&truth(), &wrong.events);
    assert!(!check.passed());
    assert!(check.found.iter().any(|(id, i)| id == "S17" && i.is_none()));
}

/// Regression: one forged `#<epoch>` line in the suspect's own shell
/// history moved every year-less event to 2049/2050. With and without the
/// journal, the forged line must not change the anchor, the dedup count or the
/// story.
#[test]
fn forged_shell_history_timestamp_does_not_move_year_inference() {
    let root = committed().join("evidence");
    let dir = tempfile::tempdir().unwrap();
    let forged = dir.path().join(".bash_history");
    let mut data = fs::read(root.join("home/deploy/.bash_history")).unwrap();
    data.extend_from_slice(b"#2524608000\necho future\n");
    fs::write(&forged, data).unwrap();
    let files = discover::discover(&[InputSpec::parse(root.to_str().unwrap())]).unwrap();
    assert!(
        files
            .iter()
            .any(|f| f.display == "home/deploy/.bash_history")
    );
    let tampered: Vec<_> = files
        .iter()
        .cloned()
        .map(|mut f| {
            if f.display == "home/deploy/.bash_history" {
                f.path = forged.clone();
            }
            f
        })
        .collect();
    for keep_journal in [true, false] {
        let pick = |v: &[discover::ArtifactFile]| -> Vec<discover::ArtifactFile> {
            v.iter()
                .filter(|f| keep_journal || f.kind != ArtifactKind::JournalExport)
                .cloned()
                .collect()
        };
        let clean = pipeline::build_from_files(&pick(&files), &BuildOptions::default()).unwrap();
        let bad = pipeline::build_from_files(&pick(&tampered), &BuildOptions::default()).unwrap();
        assert_eq!(bad.report.year_anchor, clean.report.year_anchor);
        assert_eq!(
            bad.report.duplicates_merged, clean.report.duplicates_merged,
            "journal kept: {keep_journal}"
        );
        assert!(check_story(&truth(), &bad.events).passed());
        for e in bad.events.iter().filter(|e| e.time_flags.year_inferred) {
            assert!(
                e.ts.format("%Y").to_string().as_str() <= "2025",
                "{}",
                e.raw
            );
        }
    }
}

#[test]
fn deduplication_merges_journal_and_cron_copies() {
    let tl = build(&committed().join("evidence"), &BuildOptions::default());
    assert!(tl.report.duplicates_merged > 1000);
    let login = tl
        .events
        .iter()
        .find(|e| {
            e.description
                .starts_with("SSH login accepted for deploy from 203.0.113.45")
        })
        .unwrap();
    let seen: Vec<_> = login
        .also_seen
        .iter()
        .map(|p| p.artifact.as_str())
        .collect();
    assert_eq!(seen, vec!["var/log/journal/web01.export"]);
    let raw = build(
        &committed().join("evidence"),
        &BuildOptions {
            dedup: false,
            ..BuildOptions::default()
        },
    );
    assert_eq!(raw.report.duplicates_merged, 0);
    assert_eq!(raw.events.len() as u64, raw.report.parsed_events);
}

#[test]
fn outputs_contain_the_story() {
    let tl = build(&committed().join("evidence"), &BuildOptions::default());
    let opts = OutputOptions::default().with_rules(&RuleSet::default_rules());
    let render = |f: Format| {
        let mut v = Vec::new();
        output::write(&tl, f, &opts, &mut v).unwrap();
        String::from_utf8(v).unwrap()
    };
    let jsonl = render(Format::Jsonl);
    assert_eq!(jsonl.lines().count(), tl.events.len());
    let back: Vec<timeliner::Event> = jsonl
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(back, tl.events);
    let csv = render(Format::Csv);
    assert!(csv.contains("cron ran for root: /tmp/.x.sh"));
    let l2t = render(Format::L2tCsv);
    assert!(
        l2t.lines()
            .any(|l| l.starts_with("01/01/2025,05:05:01,UTC,....,LOG,")
                && l.contains("cron ran for root: /tmp/.x.sh"))
    );
    let html = render(Format::Html);
    assert!(html.contains("Cron job executes a file from a world-writable temp directory"));
    assert!(html.contains("America/New_York"));
    assert_eq!(html, render(Format::Html), "HTML is deterministic");
}
