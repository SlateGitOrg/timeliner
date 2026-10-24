//! End-to-end tests of the `timeliner` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_timeliner"))
}

fn evidence() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/incident/evidence")
}

fn truth() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/incident/GROUND_TRUTH.json")
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn build_every_format_to_files() {
    let dir = tempfile::tempdir().unwrap();
    let ev = evidence();
    for (name, needle) in [
        ("t.jsonl", "\"kind\":\"cron_command\""),
        ("t.csv", "timestamp,source,kind"),
        ("t.l2t.csv", "date,time,timezone,MACB"),
        ("t.html", "<!doctype html>"),
    ] {
        let out = dir.path().join(name);
        let o = run(&[
            "build",
            ev.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--summary",
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        assert!(stderr(&o).contains("duplicates merged"));
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains(needle), "{name}");
    }
}

#[test]
fn build_to_stdout_with_filters() {
    let ev = evidence();
    let o = run(&[
        "build",
        ev.to_str().unwrap(),
        "--only-tagged",
        "--from",
        "2025-01-01T05:00:00Z",
        "--to",
        "2025-01-02",
        "-f",
        "csv",
        "--no-csv-safe",
        "--baseline-until",
        "2024-12-30",
        "--threads",
        "2",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    let rows: Vec<&str> = out.trim_end().split("\r\n").collect();
    assert!(rows.len() > 3);
    assert!(rows[1..].iter().all(|r| r.starts_with("2025-01-01T05:")));
}

#[test]
fn verify_passes_and_fails() {
    let ev = evidence();
    let ok = run(&[
        "verify",
        "--truth",
        truth().to_str().unwrap(),
        ev.to_str().unwrap(),
    ]);
    assert!(ok.status.success(), "{}", stdout(&ok));
    assert!(
        stdout(&ok)
            .contains("22/22 steps found, 0 missing tag(s), chronological order preserved: PASS")
    );
    let bad = run(&[
        "verify",
        "--truth",
        truth().to_str().unwrap(),
        ev.to_str().unwrap(),
        "--tz",
        "UTC",
    ]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(stdout(&bad).contains("FAIL"));
}

#[test]
fn tz_options() {
    let ev = evidence();
    let tzfile = ev.join("usr/share/zoneinfo/America/New_York");
    let o = run(&[
        "build",
        ev.to_str().unwrap(),
        "--tzfile",
        tzfile.to_str().unwrap(),
        "--summary",
        "-o",
        "/dev/null",
    ]);
    assert!(o.status.success());
    assert!(stderr(&o).contains("command line"));
    let o = run(&[
        "build",
        ev.to_str().unwrap(),
        "--tz",
        "EST5EDT,M3.2.0,M11.1.0",
        "--no-rules",
        "--no-dedup",
        "--year",
        "2025",
        "-o",
        "/dev/null",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run(&[
        "build",
        ev.to_str().unwrap(),
        "--tz",
        "Nowhere/Land",
        "--zoneinfo-dir",
        "/nonexistent",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("unknown time zone"));
}

#[test]
fn detect_rules_and_errors() {
    let ev = evidence();
    let o = run(&["detect", ev.to_str().unwrap()]);
    assert!(o.status.success());
    let out = stdout(&o);
    assert_eq!(out.lines().count(), 14);
    assert!(out.contains("journal_export  var/log/journal/web01.export"));

    let o = run(&["rules"]);
    assert!(o.status.success());
    assert!(stdout(&o).contains("ssh-bruteforce"));

    let dir = tempfile::tempdir().unwrap();
    let extra = dir.path().join("extra.yml");
    std::fs::write(&extra, "rules:\n  - id: alice-any\n    title: anything by alice\n    severity: info\n    when: {user: alice}\n").unwrap();
    let o = run(&[
        "rules",
        "--no-default-rules",
        "--rules",
        extra.to_str().unwrap(),
    ]);
    assert!(stdout(&o).contains("alice-any"));
    assert!(stderr(&o).contains("1 rule(s) OK"));
    std::fs::write(&extra, "rules: [{id: x}]").unwrap();
    let o = run(&["rules", "--rules", extra.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));

    let o = run(&["build", "/definitely/missing"]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["build", ev.to_str().unwrap(), "--from", "yesterday"]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["build", ev.to_str().unwrap(), "--dedup-window", "-1"]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&[
        "build",
        ev.to_str().unwrap(),
        "-o",
        "/definitely/missing/out.jsonl",
    ]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&[
        "build",
        ev.to_str().unwrap(),
        "--tzfile",
        "/definitely/missing",
    ]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn single_file_inputs_with_forced_kind() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("evidence-auth.txt");
    std::fs::write(
        &f,
        "Mar  1 12:00:00 h sshd[1]: Accepted password for a from 10.0.0.1 port 22 ssh2\n",
    )
    .unwrap();
    let spec = format!("auth_log={}", f.display());
    let o = run(&["build", &spec, "--year", "2024", "--tz", "+01:00", "-v"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("\"ts\":\"2024-03-01T11:00:00.000000Z\""));
}

#[test]
fn fixtures_and_bench_commands() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("fx");
    let o = run(&["fixtures", "--out", out.to_str().unwrap(), "--seed", "5"]);
    assert!(o.status.success());
    assert!(stderr(&o).contains("22 ground-truth steps"));
    let o = run(&["bench", "--lines", "300", "--rounds", "1"]);
    assert!(o.status.success());
    assert!(stdout(&o).contains("records/s"));
    let o = run(&["bench", "--lines", "100", "--rounds", "1", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 6);
}
