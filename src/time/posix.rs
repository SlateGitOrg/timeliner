//! POSIX `TZ` rule strings (`EST5EDT,M3.2.0,M11.1.0`), as found in the footer
//! of TZif v2+ files and in the `TZ` environment variable.
//!
//! Grammar (POSIX.1-2017 §8.3 plus the RFC 8536 v3 extensions):
//!
//! ```text
//! std offset [dst [offset] [,start[/time],end[/time]]]
//! ```
//!
//! POSIX offsets are *west-positive* (`EST5` is UTC-5); they are stored here
//! as east-positive UTC offsets in seconds.

use chrono::{Datelike, NaiveDate};

use crate::error::{Error, Result};

const SECS_PER_DAY: i64 = 86_400;

/// A day-of-year rule for a DST transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DayRule {
    /// `Jn`: Julian day 1..=365, February 29 is never counted.
    JulianNoLeap(u16),
    /// `n`: zero-based day of year 0..=365, February 29 counted.
    ZeroBased(u16),
    /// `Mm.w.d`: day `d` (0 = Sunday) of week `w` (1..=5, 5 = last) of month `m`.
    MonthWeekDay {
        /// Month 1..=12.
        month: u8,
        /// Week 1..=5.
        week: u8,
        /// Weekday 0..=6 (Sunday = 0).
        weekday: u8,
    },
}

/// A transition rule: a day plus a local time-of-day (may be negative or > 24h in v3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionRule {
    /// Day selector.
    pub day: DayRule,
    /// Seconds after local midnight (default 7200).
    pub time: i64,
}

/// DST part of a POSIX TZ string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstRule {
    /// DST abbreviation.
    pub name: String,
    /// UTC offset in seconds (east-positive) during DST.
    pub offset: i32,
    /// When DST starts (in standard local time).
    pub start: TransitionRule,
    /// When DST ends (in DST local time).
    pub end: TransitionRule,
}

/// A parsed POSIX TZ string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixTz {
    /// Standard-time abbreviation.
    pub std_name: String,
    /// UTC offset in seconds (east-positive) during standard time.
    pub std_offset: i32,
    /// Daylight-saving rule, if any.
    pub dst: Option<DstRule>,
}

struct Cursor<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn number(&mut self, max_digits: usize) -> Option<i64> {
        let start = self.pos;
        let mut v: i64 = 0;
        while let Some(c) = self.peek() {
            if !c.is_ascii_digit() || self.pos - start >= max_digits {
                break;
            }
            v = v * 10 + i64::from(c - b'0');
            self.pos += 1;
        }
        (self.pos > start).then_some(v)
    }

    fn name(&mut self) -> Option<String> {
        if self.eat(b'<') {
            let start = self.pos;
            while let Some(c) = self.peek() {
                if c == b'>' {
                    let name = std::str::from_utf8(&self.s[start..self.pos])
                        .ok()?
                        .to_string();
                    self.pos += 1;
                    return (name.len() >= 3
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-'))
                    .then_some(name);
                }
                self.pos += 1;
            }
            None
        } else {
            let start = self.pos;
            while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
                self.pos += 1;
            }
            (self.pos - start >= 3)
                .then(|| String::from_utf8_lossy(&self.s[start..self.pos]).into_owned())
        }
    }

    /// `[+-]hh[:mm[:ss]]` with hours up to `max_hours`; returns signed seconds.
    fn hms(&mut self, max_hours: i64) -> Option<i64> {
        let sign = if self.eat(b'-') {
            -1
        } else {
            self.eat(b'+');
            1
        };
        let h = self.number(3)?;
        if h > max_hours {
            return None;
        }
        let mut secs = h * 3600;
        if self.eat(b':') {
            let m = self.number(2)?;
            if m > 59 {
                return None;
            }
            secs += m * 60;
            if self.eat(b':') {
                let s = self.number(2)?;
                if s > 59 {
                    return None;
                }
                secs += s;
            }
        }
        Some(sign * secs)
    }

    fn rule(&mut self) -> Option<TransitionRule> {
        let day = if self.eat(b'J') {
            let n = self.number(3)?;
            if !(1..=365).contains(&n) {
                return None;
            }
            DayRule::JulianNoLeap(n as u16)
        } else if self.eat(b'M') {
            let m = self.number(2)?;
            if !self.eat(b'.') {
                return None;
            }
            let w = self.number(1)?;
            if !self.eat(b'.') {
                return None;
            }
            let d = self.number(1)?;
            if !(1..=12).contains(&m) || !(1..=5).contains(&w) || d > 6 {
                return None;
            }
            DayRule::MonthWeekDay {
                month: m as u8,
                week: w as u8,
                weekday: d as u8,
            }
        } else {
            let n = self.number(3)?;
            if n > 365 {
                return None;
            }
            DayRule::ZeroBased(n as u16)
        };
        let time = if self.eat(b'/') { self.hms(167)? } else { 7200 };
        Some(TransitionRule { day, time })
    }
}

impl PosixTz {
    /// Parses a POSIX TZ string.
    pub fn parse(spec: &str) -> Result<Self> {
        let err = || Error::TimeZone(format!("invalid POSIX TZ string `{spec}`"));
        let mut c = Cursor {
            s: spec.as_bytes(),
            pos: 0,
        };
        let std_name = c.name().ok_or_else(err)?;
        let std_offset = -(c.hms(24).ok_or_else(err)?) as i32;
        let dst = if c.peek().is_some() {
            let name = c.name().ok_or_else(err)?;
            let offset = match c.peek() {
                Some(b) if b == b'+' || b == b'-' || b.is_ascii_digit() => {
                    -(c.hms(24).ok_or_else(err)?) as i32
                }
                _ => std_offset + 3600,
            };
            let (start, end) = if c.eat(b',') {
                let start = c.rule().ok_or_else(err)?;
                if !c.eat(b',') {
                    return Err(err());
                }
                let end = c.rule().ok_or_else(err)?;
                (start, end)
            } else {
                // POSIX leaves the default implementation-defined; glibc and
                // tzcode use the current US rules.
                (
                    TransitionRule {
                        day: DayRule::MonthWeekDay {
                            month: 3,
                            week: 2,
                            weekday: 0,
                        },
                        time: 7200,
                    },
                    TransitionRule {
                        day: DayRule::MonthWeekDay {
                            month: 11,
                            week: 1,
                            weekday: 0,
                        },
                        time: 7200,
                    },
                )
            };
            Some(DstRule {
                name,
                offset,
                start,
                end,
            })
        } else {
            None
        };
        if c.pos != c.s.len() {
            return Err(err());
        }
        Ok(PosixTz {
            std_name,
            std_offset,
            dst,
        })
    }

    /// UTC offset (east-positive seconds) in effect at `utc` (seconds since epoch).
    pub fn offset_at(&self, utc: i64) -> i32 {
        let Some(dst) = &self.dst else {
            return self.std_offset;
        };
        let Some(year) = year_of(utc + i64::from(self.std_offset)) else {
            return self.std_offset;
        };
        let start = rule_local_secs(year, &dst.start) - i64::from(self.std_offset);
        let end = rule_local_secs(year, &dst.end) - i64::from(dst.offset);
        let in_dst = if start < end {
            start <= utc && utc < end
        } else {
            !(end <= utc && utc < start)
        };
        if in_dst { dst.offset } else { self.std_offset }
    }

    /// Abbreviation in effect at `utc`.
    pub fn abbreviation_at(&self, utc: i64) -> &str {
        match &self.dst {
            Some(d) if self.offset_at(utc) == d.offset && d.offset != self.std_offset => &d.name,
            _ => &self.std_name,
        }
    }

    /// UTC instants of the DST start and end transitions in `year`, if the zone has DST.
    pub fn transitions_in_year(&self, year: i32) -> Option<(i64, i64)> {
        let dst = self.dst.as_ref()?;
        Some((
            rule_local_secs(year, &dst.start) - i64::from(self.std_offset),
            rule_local_secs(year, &dst.end) - i64::from(dst.offset),
        ))
    }
}

fn year_of(secs: i64) -> Option<i32> {
    let days = secs.div_euclid(SECS_PER_DAY);
    let days = i32::try_from(days).ok()?;
    NaiveDate::from_num_days_from_ce_opt(days.checked_add(719_163)?).map(|d| d.year())
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_since_epoch(date: NaiveDate) -> i64 {
    i64::from(date.num_days_from_ce()) - 719_163
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

/// Local seconds since the epoch (as if local time were UTC) of a rule in `year`.
fn rule_local_secs(year: i32, rule: &TransitionRule) -> i64 {
    let Some(jan1) = NaiveDate::from_ymd_opt(year, 1, 1) else {
        return 0;
    };
    let base = days_since_epoch(jan1);
    let day_offset: i64 = match rule.day {
        DayRule::JulianNoLeap(n) => {
            let n = i64::from(n);
            n - 1 + i64::from(is_leap(year) && n >= 60)
        }
        DayRule::ZeroBased(n) => i64::from(n),
        DayRule::MonthWeekDay {
            month,
            week,
            weekday,
        } => {
            let month = u32::from(month);
            let first = NaiveDate::from_ymd_opt(year, month, 1).unwrap_or(jan1);
            let first_wd = first.weekday().num_days_from_sunday();
            let mut day = 1 + (u32::from(weekday) + 7 - first_wd) % 7 + 7 * (u32::from(week) - 1);
            let dim = days_in_month(year, month);
            while day > dim {
                day -= 7;
            }
            days_since_epoch(first) - base + i64::from(day - 1)
        }
    };
    (base + day_offset) * SECS_PER_DAY + rule.time
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> i64 {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0)
            .unwrap()
            .timestamp()
    }

    #[test]
    fn new_york_rules() {
        let tz = PosixTz::parse("EST5EDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!(tz.std_offset, -5 * 3600);
        assert_eq!(tz.dst.as_ref().unwrap().offset, -4 * 3600);
        // 2024: DST from 2024-03-10 07:00Z to 2024-11-03 06:00Z.
        assert_eq!(tz.offset_at(ts(2024, 3, 10, 6, 59)), -18000);
        assert_eq!(tz.offset_at(ts(2024, 3, 10, 7, 0)), -14400);
        assert_eq!(tz.offset_at(ts(2024, 11, 3, 5, 59)), -14400);
        assert_eq!(tz.offset_at(ts(2024, 11, 3, 6, 0)), -18000);
        assert_eq!(tz.offset_at(ts(2025, 1, 1, 4, 0)), -18000);
        assert_eq!(tz.abbreviation_at(ts(2024, 7, 1, 0, 0)), "EDT");
        assert_eq!(tz.abbreviation_at(ts(2024, 1, 1, 0, 0)), "EST");
        assert_eq!(
            tz.transitions_in_year(2024),
            Some((ts(2024, 3, 10, 7, 0), ts(2024, 11, 3, 6, 0)))
        );
    }

    #[test]
    fn default_rules_and_implicit_dst_offset() {
        let a = PosixTz::parse("EST5EDT").unwrap();
        let b = PosixTz::parse("EST5EDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn southern_hemisphere() {
        // Australia/Sydney: AEST-10AEDT,M10.1.0,M4.1.0/3
        let tz = PosixTz::parse("AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap();
        assert_eq!(tz.offset_at(ts(2024, 1, 15, 0, 0)), 11 * 3600);
        assert_eq!(tz.offset_at(ts(2024, 7, 15, 0, 0)), 10 * 3600);
        assert_eq!(tz.offset_at(ts(2024, 12, 31, 20, 0)), 11 * 3600);
    }

    #[test]
    fn quoted_names_julian_and_negative_times() {
        let tz = PosixTz::parse("<+0330>-3:30").unwrap();
        assert_eq!(tz.std_offset, 3 * 3600 + 1800);
        assert_eq!(tz.offset_at(0), 12_600);
        let j = PosixTz::parse("XXX3YYY,J60/0,J300/-1").unwrap();
        // J60 is March 1 in every year.
        let (start, _) = j.transitions_in_year(2024).unwrap();
        assert_eq!(start, ts(2024, 3, 1, 3, 0));
        let z = PosixTz::parse("XXX3YYY,59,300").unwrap();
        let (start, _) = z.transitions_in_year(2024).unwrap();
        assert_eq!(start, ts(2024, 2, 29, 5, 0));
        // v3: permanent DST encoded as a full-year rule
        let perm = PosixTz::parse("EST5EDT4,0/0,J365/25").unwrap();
        assert_eq!(perm.offset_at(ts(2024, 6, 1, 0, 0)), -4 * 3600);
    }

    #[test]
    fn fifth_week_means_last() {
        // Last Sunday of October 2024 is the 27th.
        let tz = PosixTz::parse("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        let (_, end) = tz.transitions_in_year(2024).unwrap();
        assert_eq!(end, ts(2024, 10, 27, 1, 0));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "E5",
            "EST",
            "EST5EDT,M3.2.0",
            "EST5EDT,M13.1.0,M1.1.0",
            "EST5x",
            "<AB>5",
            "EST25",
            "EST5EDT,J0,J1",
            "EST5EDT,M3.2.7,M1.1.0",
            "EST5:60",
            "<EST5",
        ] {
            assert!(PosixTz::parse(bad).is_err(), "{bad} should fail");
        }
    }
}
