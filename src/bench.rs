//! Throughput benchmark (`timeliner bench`): synthesizes realistic inputs in
//! memory and measures each parser in records per second, then the full
//! sort → dedup → rules pipeline in events per second. Best of `rounds`
//! runs is reported to damp scheduler noise.

use std::fmt::Write as _;
use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::dedup;
use crate::fixtures::Rng;
use crate::parsers::utmp::{UtmpRecord, ut_type};
use crate::parsers::{ArtifactKind, ParseContext, journal};
use crate::rules::RuleSet;
use crate::time::TimeZone;
use crate::time::year::YearAnchor;

/// One benchmark measurement.
#[derive(Debug, Clone, Serialize)]
pub struct BenchResult {
    /// What was measured.
    pub name: String,
    /// Records (lines, entries, binary records or events) processed.
    pub records: u64,
    /// Input bytes.
    pub bytes: u64,
    /// Best wall-clock time in seconds.
    pub seconds: f64,
    /// Records per second.
    pub records_per_sec: f64,
    /// Input MiB per second.
    pub mib_per_sec: f64,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn base() -> DateTime<Utc> {
    DateTime::from_timestamp(1_704_067_200, 0).unwrap_or_default() // 2024-01-01
}

/// Synthesizes `n` RFC 3164 auth/syslog lines with a realistic message mix.
pub fn synth_syslog(n: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut out = String::with_capacity(n * 110);
    let mut t = base();
    for i in 0..n {
        t += Duration::milliseconds(rng.range(10, 3000));
        let ip = format!("198.18.{}.{}", rng.below(256), 1 + rng.below(254));
        let msg = match rng.below(10) {
            0 => format!("sshd[{}]: Accepted publickey for alice from {ip} port {} ssh2", 1000 + i % 30000, 30000 + rng.below(30000)),
            1 | 2 => format!("sshd[{}]: Failed password for invalid user admin from {ip} port {} ssh2", 1000 + i % 30000, 30000 + rng.below(30000)),
            3 => format!("sshd[{}]: Invalid user test from {ip} port {}", 1000 + i % 30000, 30000 + rng.below(30000)),
            4 => "sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status webapp".to_string(),
            5 => format!("CRON[{}]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)", 1000 + i % 30000),
            6 => format!("CRON[{}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", 1000 + i % 30000),
            7 => "systemd[1]: Started session-42.scope - Session 42 of User alice.".to_string(),
            8 => "systemd-logind[612]: New session 42 of user alice.".to_string(),
            _ => format!("kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=192.0.2.10 PROTO=TCP DPT=23"),
        };
        let _ = writeln!(
            out,
            "{} {:>2} {} web01 {msg}",
            MONTHS[(t.format("%m").to_string().parse::<usize>().unwrap_or(1) - 1) % 12],
            t.format("%-d"),
            t.format("%H:%M:%S")
        );
    }
    out.into_bytes()
}

/// Synthesizes `n` wtmp records (login/logout pairs).
pub fn synth_wtmp(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * crate::parsers::utmp::RECORD_SIZE);
    for i in 0..n {
        let mut r = UtmpRecord {
            ut_type: if i % 2 == 0 {
                ut_type::USER_PROCESS
            } else {
                ut_type::DEAD_PROCESS
            },
            pid: 1000 + i as i32,
            line: format!("pts/{}", (i / 2) % 50),
            user: if i % 2 == 0 {
                "alice".into()
            } else {
                String::new()
            },
            host: "198.51.100.7".into(),
            tv_sec: 1_704_067_200 + i as i32 * 30,
            ..UtmpRecord::default()
        };
        r.set_address("198.51.100.7");
        out.extend_from_slice(&r.encode());
    }
    out
}

/// Synthesizes `n` journal export entries.
pub fn synth_journal(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * 300);
    for i in 0..n {
        let ts = (1_704_067_200_000_000i64 + i as i64 * 1_234_567).to_string();
        let pid = (1000 + i % 30000).to_string();
        write_one(&mut out, &ts, &pid, i);
    }
    out
}

fn write_one(out: &mut Vec<u8>, ts: &str, pid: &str, i: usize) {
    let msg = if i % 3 == 0 {
        "Failed password for invalid user admin from 198.18.0.5 port 40000 ssh2"
    } else {
        "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)"
    };
    journal::write_entry(
        out,
        &[
            ("__REALTIME_TIMESTAMP", ts),
            ("_HOSTNAME", "web01"),
            ("SYSLOG_IDENTIFIER", "sshd"),
            ("_PID", pid),
            ("PRIORITY", "6"),
            ("MESSAGE", msg),
        ],
    );
}

/// Synthesizes `n` bodyfile lines.
pub fn synth_bodyfile(n: usize) -> Vec<u8> {
    let mut out = String::with_capacity(n * 90);
    for i in 0..n {
        let t = 1_704_067_200 + i as i64 * 7;
        let _ = writeln!(
            out,
            "0|/usr/share/doc/pkg{}/file{}.txt|{}|r/rrw-r--r--|0|0|{}|{}|{}|{}|{}",
            i / 100,
            i % 100,
            100_000 + i,
            i * 13 % 9000,
            t + 50,
            t,
            t + 3,
            t
        );
    }
    out.into_bytes()
}

/// Synthesizes `n` bash history entries.
pub fn synth_bash(n: usize) -> Vec<u8> {
    let mut out = String::with_capacity(n * 30);
    for i in 0..n {
        let _ = writeln!(
            out,
            "#{}\ngit status --short {}",
            1_704_067_200 + i * 5,
            i % 7
        );
    }
    out.into_bytes()
}

fn ctx() -> ParseContext {
    ParseContext {
        artifact: "bench".into(),
        tz: TimeZone::utc(),
        year_anchor: YearAnchor::Explicit(2024),
        host: Some("web01".into()),
        user: Some("alice".into()),
    }
}

fn measure(name: &str, rounds: usize, bytes: u64, mut f: impl FnMut() -> u64) -> BenchResult {
    let mut best = f64::MAX;
    let mut records = 0;
    for _ in 0..rounds.max(1) {
        let start = Instant::now();
        records = f();
        best = best.min(start.elapsed().as_secs_f64());
    }
    let secs = best.max(1e-9);
    BenchResult {
        name: name.into(),
        records,
        bytes,
        seconds: best,
        records_per_sec: records as f64 / secs,
        mib_per_sec: bytes as f64 / secs / (1024.0 * 1024.0),
    }
}

/// Runs every benchmark with `n` records each.
pub fn run(n: usize, rounds: usize) -> Vec<BenchResult> {
    let c = ctx();
    let mut results = Vec::new();
    let inputs: Vec<(&str, ArtifactKind, Vec<u8>)> = vec![
        (
            "auth.log (RFC 3164 + semantics)",
            ArtifactKind::AuthLog,
            synth_syslog(n, 7),
        ),
        ("wtmp (384-byte records)", ArtifactKind::Wtmp, synth_wtmp(n)),
        (
            "journal export",
            ArtifactKind::JournalExport,
            synth_journal(n),
        ),
        ("bodyfile", ArtifactKind::Bodyfile, synth_bodyfile(n)),
        ("bash history", ArtifactKind::BashHistory, synth_bash(n)),
    ];
    for (name, kind, data) in &inputs {
        results.push(measure(name, rounds, data.len() as u64, || {
            kind.parse(data, &c).records
        }));
    }
    // Full post-processing on the auth.log events.
    let events = ArtifactKind::AuthLog.parse(&inputs[0].2, &c).events;
    let rules = RuleSet::default_rules();
    results.push(measure("sort + dedup + default rules", rounds, 0, || {
        let mut ev = events.clone();
        ev.sort_by_key(|e| (e.ts, e.location));
        let (mut ev, _) = dedup::dedup(ev, Duration::seconds(2));
        rules.apply(&mut ev);
        ev.len() as u64
    }));
    results
}

/// Formats results as a Markdown table.
pub fn table(results: &[BenchResult]) -> String {
    let mut s = String::from(
        "| stage | records | input MiB | best time (s) | records/s | MiB/s |\n|---|---:|---:|---:|---:|---:|\n",
    );
    for r in results {
        let _ = writeln!(
            s,
            "| {} | {} | {:.1} | {:.3} | {:.0} | {} |",
            r.name,
            r.records,
            r.bytes as f64 / 1_048_576.0,
            r.seconds,
            r.records_per_sec,
            if r.bytes > 0 {
                format!("{:.1}", r.mib_per_sec)
            } else {
                "—".into()
            }
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_inputs_parse_cleanly() {
        let c = ctx();
        let out = ArtifactKind::AuthLog.parse(&synth_syslog(500, 1), &c);
        assert_eq!(out.records, 500);
        assert_eq!(out.events.len(), 500);
        assert_eq!(out.warning_count, 0);
        assert_eq!(
            ArtifactKind::Wtmp.parse(&synth_wtmp(10), &c).events.len(),
            10
        );
        assert_eq!(
            ArtifactKind::JournalExport
                .parse(&synth_journal(10), &c)
                .events
                .len(),
            10
        );
        assert_eq!(
            ArtifactKind::Bodyfile
                .parse(&synth_bodyfile(10), &c)
                .events
                .len(),
            30
        );
        assert_eq!(
            ArtifactKind::BashHistory
                .parse(&synth_bash(10), &c)
                .events
                .len(),
            10
        );
    }

    #[test]
    fn run_and_table() {
        let r = run(200, 1);
        assert_eq!(r.len(), 6);
        assert!(r.iter().all(|x| x.records > 0 && x.records_per_sec > 0.0));
        let t = table(&r);
        assert!(t.contains("| wtmp (384-byte records) | 200 |"));
    }
}
