//! Property tests: no parser panics on arbitrary or mutated input, and core
//! invariants hold (round-trips, monotone year inference, TZ round-trips).

use chrono::{DateTime, NaiveDate, Utc};
use proptest::prelude::*;

use timeliner::output::csv::field;
use timeliner::parsers::utmp::UtmpRecord;
use timeliner::parsers::{ArtifactKind, ParseContext, syslog_line};
use timeliner::time::TimeZone;
use timeliner::time::posix::PosixTz;
use timeliner::time::tzif::TzifZone;
use timeliner::time::year::{PartialStamp, YearAnchor, infer_years};

fn ctx() -> ParseContext {
    ParseContext {
        artifact: "prop".into(),
        tz: TimeZone::parse("EST5EDT,M3.2.0,M11.1.0", std::path::Path::new(".")).unwrap(),
        year_anchor: YearAnchor::Explicit(2025),
        host: Some("h".into()),
        user: None,
    }
}

/// Valid seed lines per format; mutations of these reach deep parser paths.
fn seeds(kind: ArtifactKind) -> Vec<u8> {
    let s: &str = match kind {
        ArtifactKind::AuthLog | ArtifactKind::Syslog | ArtifactKind::CronLog => {
            "Dec 31 23:10:44 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash\n\
Jan  1 00:05:01 web01 CRON[9]: (root) CMD (/tmp/.x.sh)\n\
<38>1 2025-01-01T04:07:12Z web01 sshd 7 - [a b=\"c\"] Accepted password for deploy from 203.0.113.45 port 1 ssh2\n\
root (01/01-00:05:01-1234) CMD (/tmp/x)\n"
        }
        ArtifactKind::BashHistory => "#1735704485\nid\n#1735704500\nls\n",
        ArtifactKind::ZshHistory => ": 1735704485:0;echo a \\\nb\n",
        ArtifactKind::FishHistory => "- cmd: ls\n  when: 1735704485\n",
        ArtifactKind::JournalExport => {
            "__REALTIME_TIMESTAMP=1735704432123456\nSYSLOG_IDENTIFIER=sshd\nMESSAGE=Invalid user x from 1.2.3.4 port 5\n\n"
        }
        ArtifactKind::Bodyfile => {
            "0|/tmp/.x.sh|1|r/rrwxr-xr-x|0|0|5|1735704543|1735704543|1735704571|1735704543\n"
        }
        ArtifactKind::DpkgLog => {
            "2024-12-31 23:11:33 install netcat-openbsd:amd64 <none> 1.226-1ubuntu2\n"
        }
        ArtifactKind::AptHistory => {
            "Start-Date: 2024-12-31  23:11:31\nCommandline: apt install x\nInstall: x:amd64 (1)\nEnd-Date: 2024-12-31  23:11:34\n"
        }
        ArtifactKind::Wtmp | ArtifactKind::Btmp | ArtifactKind::Utmp => {
            let mut r = UtmpRecord {
                ut_type: 7,
                line: "pts/1".into(),
                user: "deploy".into(),
                host: "203.0.113.45".into(),
                tv_sec: 1_735_704_433,
                ..UtmpRecord::default()
            };
            r.set_address("203.0.113.45");
            return r.encode().to_vec();
        }
    };
    s.as_bytes().to_vec()
}

fn mutate(mut data: Vec<u8>, edits: &[(usize, u8)], cut: usize) -> Vec<u8> {
    for (pos, byte) in edits {
        if !data.is_empty() {
            let i = pos % data.len();
            data[i] = *byte;
        }
    }
    let keep = if data.is_empty() {
        0
    } else {
        cut % (data.len() + 1)
    };
    data.truncate(keep.max(data.len() / 2));
    data
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn parsers_never_panic_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2048), k in 0usize..13) {
        let kind = ArtifactKind::ALL[k];
        let out = kind.parse(&data, &ctx());
        prop_assert!(out.events.len() as u64 <= out.records.max(1) * 4);
    }

    #[test]
    fn parsers_never_panic_on_mutated_valid_input(
        k in 0usize..13,
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..8),
        cut in any::<usize>(),
    ) {
        let kind = ArtifactKind::ALL[k];
        let data = mutate(seeds(kind), &edits, cut);
        let _ = kind.parse(&data, &ctx());
    }

    #[test]
    fn syslog_line_parser_never_panics(line in "\\PC{0,200}") {
        let _ = syslog_line::parse_line(&line);
    }

    #[test]
    fn syslog_like_lines_parse(
        month in 0usize..12, day in 1u32..29, h in 0u32..24, m in 0u32..60, s in 0u32..60,
        host in "[a-z][a-z0-9-]{0,15}", prog in "[a-zA-Z][a-zA-Z0-9_-]{0,12}", pid in 1u32..99999,
        msg in "[ -~]{0,80}",
    ) {
        const M: [&str; 12] = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
        let line = format!("{} {:>2} {:02}:{:02}:{:02} {host} {prog}[{pid}]: {msg}", M[month], day, h, m, s);
        let l = syslog_line::parse_line(&line).expect("well-formed line must parse");
        prop_assert_eq!(l.host, host.as_str());
        prop_assert_eq!(l.program, Some(prog.as_str()));
        prop_assert_eq!(l.pid, Some(pid));
        prop_assert_eq!(l.message, msg.trim_start_matches(' '));
    }

    #[test]
    fn tzif_and_posix_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512), spec in "\\PC{0,40}") {
        let _ = TzifZone::parse(&data);
        if let Ok(p) = PosixTz::parse(&spec) {
            let _ = p.offset_at(1_735_704_000);
        }
    }

    #[test]
    fn utmp_roundtrip(
        ty in 0i16..10, pid in any::<i32>(), line in "[a-z/0-9]{0,31}", user in "[a-z0-9_]{0,31}",
        host in "[a-z0-9.]{0,60}", sec in any::<i32>(), usec in any::<i32>(), session in any::<i32>(),
    ) {
        let r = UtmpRecord { ut_type: ty, pid, line, id: "ab".into(), user, host, session, tv_sec: sec, tv_usec: usec, ..UtmpRecord::default() };
        prop_assert_eq!(UtmpRecord::decode(&r.encode()), r);
    }

    #[test]
    fn year_inference_is_monotone_for_chronological_input(
        mut days in proptest::collection::vec(0u32..2000, 1..60),
    ) {
        // Chronological input with gaps shorter than a year.
        days.sort_unstable();
        days.dedup();
        let start = NaiveDate::from_ymd_opt(2019, 1, 1).unwrap();
        let mut dates = Vec::new();
        for (i, d) in days.iter().enumerate() {
            if i > 0 && d - days[i - 1] > 300 { break; }
            dates.push(start + chrono::Duration::days(i64::from(*d)));
        }
        let stamps: Vec<PartialStamp> = dates.iter().map(|d| {
            use chrono::Datelike;
            PartialStamp { month: d.month(), day: d.day(), hour: 1, minute: 0, second: 0, nanos: 0 }
        }).collect();
        use chrono::Datelike;
        let last_year = dates.last().unwrap().year();
        let years = infer_years(&stamps, YearAnchor::Explicit(last_year));
        for (d, y) in dates.iter().zip(&years) {
            prop_assert_eq!(d.year(), *y);
        }
    }

    #[test]
    fn local_utc_roundtrip_outside_transitions(secs in 946_684_800i64..2_524_608_000) {
        let tz = TimeZone::parse("EST5EDT,M3.2.0,M11.1.0", std::path::Path::new(".")).unwrap();
        let utc = DateTime::<Utc>::from_timestamp(secs, 0).unwrap();
        let local = tz.to_local(utc);
        let back = tz.local_to_utc(local);
        if !back.ambiguous && !back.gap {
            prop_assert_eq!(back.utc, utc);
        } else {
            prop_assert!((back.utc - utc).num_seconds().abs() <= 3600);
        }
    }

    #[test]
    fn csv_field_quoting_roundtrips(s in "\\PC{0,60}") {
        let f = field(&s, false);
        let unquoted = if f.starts_with('"') {
            f[1..f.len() - 1].replace("\"\"", "\"")
        } else {
            f.clone()
        };
        prop_assert_eq!(unquoted, s);
    }
}
