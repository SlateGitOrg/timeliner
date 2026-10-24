//! Cross-artifact de-duplication.
//!
//! The same occurrence is often recorded twice: rsyslog writes sshd lines to
//! both `auth.log` and `syslog`, journald keeps its own copy, and rotated
//! files overlap after `copytruncate`. Two events are duplicates when they
//! have the same kind, host, user and description, come from *different*
//! artifacts, and lie within `window` of each other (artifacts disagree on
//! sub-second precision: syslog truncates to seconds, journald keeps µs).
//!
//! Identical events from the *same* artifact are never merged — three
//! identical failed passwords in one second are three attempts. A survivor
//! absorbs at most one duplicate per other artifact, so N copies in each of
//! two files pair up 1:1.
//!
//! Complexity: one pass over the time-sorted events, O(n · k) where k is the
//! number of identical events inside the window (small in practice); memory
//! O(n) for the fingerprint index.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};

use chrono::Duration;

use crate::event::Event;

fn fingerprint(e: &Event) -> u64 {
    let mut h = DefaultHasher::new();
    e.kind.hash(&mut h);
    e.host.as_deref().map(str::to_ascii_lowercase).hash(&mut h);
    e.user.hash(&mut h);
    e.description.hash(&mut h);
    h.finish()
}

fn same_occurrence(a: &Event, b: &Event) -> bool {
    a.kind == b.kind
        && a.user == b.user
        && a.description == b.description
        && a.host.as_deref().map(str::to_ascii_lowercase)
            == b.host.as_deref().map(str::to_ascii_lowercase)
}

/// Merges duplicates in a time-sorted list; returns survivors and the number merged.
pub fn dedup(events: Vec<Event>, window: Duration) -> (Vec<Event>, u64) {
    let mut survivors: Vec<Event> = Vec::with_capacity(events.len());
    let mut recent: HashMap<u64, VecDeque<usize>> = HashMap::new();
    let mut merged = 0u64;
    for e in events {
        let fp = fingerprint(&e);
        let candidates = recent.entry(fp).or_default();
        while let Some(&front) = candidates.front() {
            if e.ts - survivors[front].ts > window {
                candidates.pop_front();
            } else {
                break;
            }
        }
        let target = candidates.iter().copied().find(|&i| {
            let s = &survivors[i];
            s.artifact != e.artifact
                && !s.also_seen.iter().any(|p| p.artifact == e.artifact)
                && same_occurrence(s, &e)
        });
        match target {
            Some(i) => {
                survivors[i].also_seen.push(e.provenance());
                merged += 1;
            }
            None => {
                candidates.push_back(survivors.len());
                survivors.push(e);
            }
        }
    }
    (survivors, merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, SourceKind};
    use chrono::{TimeZone, Utc};

    fn ev(ms: i64, artifact: &str, desc: &str) -> Event {
        Event::new(
            Utc.timestamp_millis_opt(1_735_704_432_000 + ms).unwrap(),
            SourceKind::AuthLog,
            EventKind::SshLoginFailure,
            artifact,
            ms as u64,
            desc,
        )
        .with_host(Some("web01"))
        .with_user(Some("root"))
    }

    #[test]
    fn merges_across_artifacts_only() {
        let events = vec![
            ev(0, "auth.log", "fail"),
            ev(0, "auth.log", "fail"),
            ev(120, "journal", "fail"),
            ev(130, "journal", "fail"),
            ev(140, "journal", "fail"), // third journal copy: no partner left
            ev(150, "syslog", "fail"),
            ev(200, "journal", "other"),
            ev(5_000, "journal", "fail"), // outside window
        ];
        let (out, merged) = dedup(events, Duration::seconds(2));
        assert_eq!(merged, 3);
        assert_eq!(out.len(), 5);
        assert_eq!(out[0].also_seen.len(), 2); // journal + syslog
        assert_eq!(out[1].also_seen.len(), 1);
        assert_eq!(out[2].artifact, "journal");
    }

    #[test]
    fn host_comparison_is_case_insensitive() {
        let a = ev(0, "a", "x");
        let b = ev(0, "b", "x").with_host(Some("WEB01"));
        let (out, merged) = dedup(vec![a, b], Duration::seconds(1));
        assert_eq!((out.len(), merged), (1, 1));
    }
}
