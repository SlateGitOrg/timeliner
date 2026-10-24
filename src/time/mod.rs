//! Time-zone normalization and year inference.
//!
//! Every parser emits UTC. Artifacts that store local wall-clock time
//! (RFC 3164 syslog, dpkg, apt) are converted with a [`TimeZone`], which can be
//! UTC, a fixed offset, a POSIX rule string, or a TZif zone (ideally the
//! evidence's own `/etc/localtime`).

pub mod posix;
pub mod tzif;
pub mod year;

use std::path::{Component, Path};

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::error::{Error, Result};
use posix::PosixTz;
use tzif::TzifZone;

#[derive(Debug, Clone, PartialEq, Eq)]
enum TzKind {
    Utc,
    Fixed(i32),
    Posix(PosixTz),
    Tzif(Box<TzifZone>),
}

/// A time zone used to interpret local wall-clock timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeZone {
    kind: TzKind,
    label: String,
}

/// Result of converting a local wall-clock time to UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalConversion {
    /// The chosen UTC instant.
    pub utc: DateTime<Utc>,
    /// The local time occurred twice; the earlier instant was chosen.
    pub ambiguous: bool,
    /// The local time fell in a DST gap; it was interpreted with the pre-gap offset.
    pub gap: bool,
}

impl TimeZone {
    /// Coordinated Universal Time.
    pub fn utc() -> Self {
        TimeZone {
            kind: TzKind::Utc,
            label: "UTC".into(),
        }
    }

    /// A fixed offset east of UTC, in seconds (|offset| < 26h).
    pub fn fixed(offset_secs: i32) -> Result<Self> {
        if offset_secs.abs() >= 26 * 3600 {
            return Err(Error::TimeZone(format!(
                "offset {offset_secs}s out of range"
            )));
        }
        let sign = if offset_secs < 0 { '-' } else { '+' };
        let a = offset_secs.unsigned_abs();
        Ok(TimeZone {
            kind: TzKind::Fixed(offset_secs),
            label: format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60),
        })
    }

    /// Builds a zone from TZif bytes (e.g. the evidence's `/etc/localtime`).
    pub fn from_tzif(bytes: &[u8], label: &str) -> Result<Self> {
        Ok(TimeZone {
            kind: TzKind::Tzif(Box::new(TzifZone::parse(bytes)?)),
            label: label.to_string(),
        })
    }

    /// Parses a user specification:
    ///
    /// * `UTC`, `Z`, `GMT` (case-insensitive)
    /// * fixed offsets `+05:30`, `-0800`, `+03`
    /// * POSIX rule strings `EST5EDT,M3.2.0,M11.1.0`
    /// * IANA names (`America/New_York`) looked up as TZif files under `zoneinfo_dir`
    pub fn parse(spec: &str, zoneinfo_dir: &Path) -> Result<Self> {
        let spec = spec.trim();
        if ["utc", "z", "gmt", "etc/utc", "etc/gmt", "universal", "zulu"]
            .contains(&spec.to_ascii_lowercase().as_str())
        {
            return Ok(Self::utc());
        }
        if let Some(off) = parse_fixed_offset(spec) {
            return Self::fixed(off);
        }
        if let Ok(p) = PosixTz::parse(spec) {
            return Ok(TimeZone {
                kind: TzKind::Posix(p),
                label: spec.to_string(),
            });
        }
        let rel = Path::new(spec);
        if spec.is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(Error::TimeZone(format!("invalid time zone `{spec}`")));
        }
        let path = zoneinfo_dir.join(rel);
        let bytes = std::fs::read(&path).map_err(|e| {
            Error::TimeZone(format!(
                "unknown time zone `{spec}` (could not read {}: {e})",
                path.display()
            ))
        })?;
        Self::from_tzif(&bytes, spec)
    }

    /// Human-readable label (`UTC`, `+05:30`, `America/New_York`, ...).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// UTC offset (east-positive seconds) in effect at `utc_secs`.
    pub fn offset_at(&self, utc_secs: i64) -> i32 {
        match &self.kind {
            TzKind::Utc => 0,
            TzKind::Fixed(o) => *o,
            TzKind::Posix(p) => p.offset_at(utc_secs),
            TzKind::Tzif(z) => z.offset_at(utc_secs),
        }
    }

    /// Converts an instant to local wall-clock time.
    pub fn to_local(&self, utc: DateTime<Utc>) -> NaiveDateTime {
        let off = self.offset_at(utc.timestamp());
        utc.naive_utc() + chrono::Duration::seconds(i64::from(off))
    }

    /// Converts a local wall-clock time to UTC, resolving DST overlaps and gaps.
    ///
    /// Overlaps (the hour repeated at fall-back) resolve to the *earlier*
    /// instant and set `ambiguous`; gaps (the hour skipped at spring-forward)
    /// are interpreted with the offset in effect before the gap and set `gap`,
    /// matching what `mktime(3)` does with `tm_isdst = -1` on glibc.
    pub fn local_to_utc(&self, local: NaiveDateTime) -> LocalConversion {
        let l = local.and_utc().timestamp();
        let sub = local.and_utc().timestamp_subsec_nanos();
        let mk = |secs: i64| {
            DateTime::<Utc>::from_timestamp(secs, sub).unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        };
        if let TzKind::Utc | TzKind::Fixed(_) = self.kind {
            return LocalConversion {
                utc: mk(l - i64::from(self.offset_at(0))),
                ambiguous: false,
                gap: false,
            };
        }
        let mut candidates: Vec<i64> = Vec::with_capacity(2);
        for probe in [l - 86_400, l, l + 86_400] {
            let off = i64::from(self.offset_at(probe));
            let u = l - off;
            if i64::from(self.offset_at(u)) == off && !candidates.contains(&u) {
                candidates.push(u);
            }
        }
        candidates.sort_unstable();
        match candidates.as_slice() {
            [] => {
                let before = i64::from(self.offset_at(l - 86_400));
                LocalConversion {
                    utc: mk(l - before),
                    ambiguous: false,
                    gap: true,
                }
            }
            [one] => LocalConversion {
                utc: mk(*one),
                ambiguous: false,
                gap: false,
            },
            [first, ..] => LocalConversion {
                utc: mk(*first),
                ambiguous: true,
                gap: false,
            },
        }
    }
}

/// Parses `+HH:MM`, `-HHMM`, `+HH` (sign required) into east-positive seconds.
pub fn parse_fixed_offset(s: &str) -> Option<i32> {
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) || rest.matches(':').count() > 1 {
        return None;
    }
    let (h, m) = match digits.len() {
        2 => (digits.parse::<i32>().ok()?, 0),
        4 => (
            digits[..2].parse::<i32>().ok()?,
            digits[2..].parse::<i32>().ok()?,
        ),
        _ => return None,
    };
    if h > 25 || m > 59 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, TimeZone as _};

    fn local(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, 0)
            .unwrap()
    }

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    #[test]
    fn parses_specs() {
        let dir = Path::new("/nonexistent");
        assert_eq!(TimeZone::parse("utc", dir).unwrap().label(), "UTC");
        assert_eq!(TimeZone::parse("+05:30", dir).unwrap().offset_at(0), 19_800);
        assert_eq!(TimeZone::parse("-0800", dir).unwrap().label(), "-08:00");
        assert_eq!(TimeZone::parse("+03", dir).unwrap().offset_at(0), 10_800);
        assert!(TimeZone::parse("EST5EDT", dir).is_ok());
        assert!(TimeZone::parse("Mars/Olympus", dir).is_err());
        assert!(TimeZone::parse("../../etc/passwd", dir).is_err());
        assert!(TimeZone::parse("/etc/passwd", dir).is_err());
        assert!(TimeZone::fixed(30 * 3600).is_err());
        assert_eq!(parse_fixed_offset("+5"), None);
        assert_eq!(parse_fixed_offset("+05:3x"), None);
        assert_eq!(parse_fixed_offset("05:00"), None);
        assert_eq!(parse_fixed_offset("+26:00"), None);
    }

    #[test]
    fn fixed_and_utc_conversion() {
        let tz = TimeZone::fixed(-5 * 3600).unwrap();
        let c = tz.local_to_utc(local(2024, 12, 31, 23, 10));
        assert_eq!(c.utc, utc(2025, 1, 1, 4, 10));
        assert!(!c.ambiguous && !c.gap);
        assert_eq!(tz.to_local(c.utc), local(2024, 12, 31, 23, 10));
        let u = TimeZone::utc().local_to_utc(local(2024, 1, 1, 0, 0));
        assert_eq!(u.utc, utc(2024, 1, 1, 0, 0));
    }

    #[test]
    fn dst_overlap_and_gap() {
        let tz = TimeZone::parse("EST5EDT,M3.2.0,M11.1.0", Path::new(".")).unwrap();
        // Normal winter and summer times.
        assert_eq!(
            tz.local_to_utc(local(2024, 1, 5, 12, 0)).utc,
            utc(2024, 1, 5, 17, 0)
        );
        assert_eq!(
            tz.local_to_utc(local(2024, 7, 5, 12, 0)).utc,
            utc(2024, 7, 5, 16, 0)
        );
        // 2024-11-03 01:30 happens twice: EDT (05:30Z) then EST (06:30Z).
        let amb = tz.local_to_utc(local(2024, 11, 3, 1, 30));
        assert!(amb.ambiguous);
        assert_eq!(amb.utc, utc(2024, 11, 3, 5, 30));
        // 2024-03-10 02:30 does not exist; pre-gap offset (EST) is applied.
        let gap = tz.local_to_utc(local(2024, 3, 10, 2, 30));
        assert!(gap.gap);
        assert_eq!(gap.utc, utc(2024, 3, 10, 7, 30));
    }

    #[test]
    fn subseconds_survive_conversion() {
        let tz = TimeZone::parse("EST5EDT", Path::new(".")).unwrap();
        let l = local(2024, 1, 5, 12, 0) + chrono::Duration::microseconds(123_456);
        let c = tz.local_to_utc(l);
        assert_eq!(c.utc.timestamp_subsec_micros(), 123_456);
    }

    #[test]
    fn iana_lookup_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        let types = vec![tzif::LocalType {
            utoff: 3600,
            is_dst: false,
            abbr: "CET".into(),
        }];
        std::fs::create_dir_all(dir.path().join("Europe")).unwrap();
        std::fs::write(
            dir.path().join("Europe/Test"),
            tzif::write_tzif_v2(&[], &types, Some("CET-1CEST,M3.5.0,M10.5.0/3")),
        )
        .unwrap();
        let tz = TimeZone::parse("Europe/Test", dir.path()).unwrap();
        assert_eq!(tz.label(), "Europe/Test");
        assert_eq!(tz.offset_at(utc(2024, 7, 1, 0, 0).timestamp()), 7200);
        assert_eq!(
            tz.local_to_utc(local(2024, 7, 1, 12, 0)).utc,
            utc(2024, 7, 1, 10, 0)
        );
    }
}
