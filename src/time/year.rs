//! Year inference for timestamps that omit the year (RFC 3164 syslog,
//! legacy cron logs).
//!
//! Log files are written in chronological order, so walking a file forward a
//! *decrease* of the month (Dec → Jan) means the year rolled over. The
//! algorithm runs one O(n) pass that assigns each entry a relative year
//! offset `k`, then anchors the absolute year:
//!
//! * [`YearAnchor::Explicit`] — the user says which year the *last* entry is in;
//! * [`YearAnchor::NotAfter`] — the last entry must not be later than a
//!   reference instant (default: the newest absolute timestamp found in the
//!   rest of the evidence, plus slack). The latest year satisfying that is used.
//!
//! Stragglers: after a rollover, an entry whose date lies at most
//! [`STRAGGLER_DAYS`] days *before* the preceding entry once wrapped into the
//! previous year (a `Dec 31` line written after a `Jan 1` line) is assigned to
//! the previous year without changing the running state. A larger forward jump
//! is treated as a gap within the current year.

use chrono::{Datelike, NaiveDate, NaiveDateTime};

/// A timestamp without a year.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialStamp {
    /// Month 1..=12.
    pub month: u32,
    /// Day of month 1..=31.
    pub day: u32,
    /// Hour 0..=23.
    pub hour: u32,
    /// Minute 0..=59.
    pub minute: u32,
    /// Second 0..=60 (a leap second is clamped to 59).
    pub second: u32,
    /// Sub-second nanoseconds.
    pub nanos: u32,
}

impl PartialStamp {
    /// Combines with a year; `None` if the date does not exist (e.g. Feb 29 in a common year).
    pub fn with_year(&self, year: i32) -> Option<NaiveDateTime> {
        NaiveDate::from_ymd_opt(year, self.month, self.day)?.and_hms_nano_opt(
            self.hour,
            self.minute,
            self.second.min(59),
            self.nanos,
        )
    }
}

/// How to pin the relative years to absolute ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YearAnchor {
    /// The last entry is in this year.
    Explicit(i32),
    /// The last entry is at or before this local time.
    NotAfter(NaiveDateTime),
}

/// Maximum distance (days) for an out-of-order line to count as a straggler.
pub const STRAGGLER_DAYS: u32 = 7;

/// Day of a non-leap year (1..=365) for month/day; used only for distances.
fn approx_doy(month: u32, day: u32) -> u32 {
    const CUM: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    CUM[(month.clamp(1, 12) - 1) as usize] + day
}

/// Assigns an absolute year to each stamp (same order as the input).
pub fn infer_years(stamps: &[PartialStamp], anchor: YearAnchor) -> Vec<i32> {
    let mut rel: Vec<i32> = Vec::with_capacity(stamps.len());
    let mut k: i32 = 0;
    let mut prev: Option<&PartialStamp> = None;
    for s in stamps {
        match prev {
            Some(p) if s.month < p.month => {
                k += 1;
                prev = Some(s);
                rel.push(k);
            }
            Some(p)
                if k > 0
                    && s.month > p.month
                    && approx_doy(p.month, p.day) + 365 - approx_doy(s.month, s.day)
                        <= STRAGGLER_DAYS =>
            {
                // Late-written line from just before the rollover.
                rel.push(k - 1);
            }
            _ => {
                prev = Some(s);
                rel.push(k);
            }
        }
    }
    let Some(last_idx) = rel.len().checked_sub(1) else {
        return Vec::new();
    };
    let last_rel = rel[last_idx];
    let last = stamps[last_idx];
    let last_year = match anchor {
        YearAnchor::Explicit(y) => y,
        YearAnchor::NotAfter(limit) => {
            let y0 = limit.year();
            (y0 - 4..=y0)
                .rev()
                .find(|&y| last.with_year(y).is_some_and(|t| t <= limit))
                .unwrap_or(y0)
        }
    };
    let base = last_year - last_rel;
    rel.into_iter().map(|r| base + r).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(month: u32, day: u32) -> PartialStamp {
        PartialStamp {
            month,
            day,
            hour: 12,
            minute: 0,
            second: 0,
            nanos: 0,
        }
    }

    fn at(y: i32, m: u32, d: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(23, 0, 0)
            .unwrap()
    }

    #[test]
    fn rollover_with_explicit_anchor() {
        let s = [st(12, 30), st(12, 31), st(1, 1), st(1, 2)];
        assert_eq!(
            infer_years(&s, YearAnchor::Explicit(2025)),
            vec![2024, 2024, 2025, 2025]
        );
    }

    #[test]
    fn multiple_rollovers() {
        let s = [st(11, 1), st(2, 1), st(12, 1), st(3, 1)];
        assert_eq!(
            infer_years(&s, YearAnchor::Explicit(2026)),
            vec![2024, 2025, 2025, 2026]
        );
    }

    #[test]
    fn not_after_anchor_picks_latest_valid_year() {
        let s = [st(12, 31), st(1, 1)];
        assert_eq!(
            infer_years(&s, YearAnchor::NotAfter(at(2025, 1, 2))),
            vec![2024, 2025]
        );
        // Reference is earlier in the year than the last entry: previous year.
        let s = [st(6, 1), st(9, 1)];
        assert_eq!(
            infer_years(&s, YearAnchor::NotAfter(at(2025, 3, 1))),
            vec![2024, 2024]
        );
    }

    #[test]
    fn leap_day_constrains_not_after_anchor() {
        // Feb 29 exists only in 2024 within the search window.
        let s = [st(2, 29)];
        assert_eq!(infer_years(&s, YearAnchor::NotAfter(at(2027, 5, 1))), vec![2024]);
        assert!(st(2, 29).with_year(2025).is_none());
    }

    #[test]
    fn straggler_after_rollover() {
        let s = [st(12, 31), st(1, 1), st(12, 31), st(1, 1)];
        assert_eq!(
            infer_years(&s, YearAnchor::Explicit(2025)),
            vec![2024, 2025, 2024, 2025]
        );
    }

    #[test]
    fn forward_gap_without_rollover_is_same_year() {
        let s = [st(1, 5), st(12, 5)];
        assert_eq!(infer_years(&s, YearAnchor::Explicit(2024)), vec![2024, 2024]);
    }

    #[test]
    fn empty_input() {
        assert!(infer_years(&[], YearAnchor::Explicit(2024)).is_empty());
    }
}
