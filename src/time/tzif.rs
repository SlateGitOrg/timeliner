//! TZif (RFC 8536) reader and a minimal writer.
//!
//! Forensically the most trustworthy time-zone source is the evidence's own
//! `/etc/localtime`, which is a TZif file. The reader accepts versions 1-4,
//! prefers the 64-bit v2+ data block, and uses the POSIX footer for instants
//! after the last transition. Every count is validated against the input
//! length before allocation, so arbitrary bytes never panic.
//!
//! The writer exists for the fixture generator (it produces an evidence set
//! whose `/etc/localtime` exercises both the transition table and the footer).

use crate::error::{Error, Result};
use crate::time::posix::PosixTz;

/// One local-time type (`ttinfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalType {
    /// UTC offset in seconds, east-positive.
    pub utoff: i32,
    /// Whether this type is daylight-saving time.
    pub is_dst: bool,
    /// Abbreviation such as `EST`.
    pub abbr: String,
}

/// A parsed TZif zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TzifZone {
    /// Format version (1-4).
    pub version: u8,
    /// Transition instants (seconds since epoch), strictly increasing.
    pub transitions: Vec<i64>,
    /// Local type index for each transition.
    pub type_indices: Vec<u8>,
    /// Local-time types.
    pub types: Vec<LocalType>,
    /// POSIX footer rule for instants after the last transition.
    pub footer: Option<PosixTz>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| Error::TimeZone("TZif: truncated file".into()))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn be32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[derive(Debug, Clone, Copy)]
struct Header {
    version: u8,
    isutcnt: usize,
    isstdcnt: usize,
    leapcnt: usize,
    timecnt: usize,
    typecnt: usize,
    charcnt: usize,
}

fn read_header(r: &mut Reader<'_>) -> Result<Header> {
    if r.take(4)? != b"TZif" {
        return Err(Error::TimeZone("TZif: bad magic".into()));
    }
    let version = match r.take(1)?[0] {
        0 => 1,
        b'2' => 2,
        b'3' => 3,
        b'4' => 4,
        v => {
            return Err(Error::TimeZone(format!(
                "TZif: unknown version byte {v:#x}"
            )));
        }
    };
    r.take(15)?;
    let mut counts = [0usize; 6];
    for c in &mut counts {
        *c = r.be32()? as usize;
    }
    let [isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt] = counts;
    Ok(Header {
        version,
        isutcnt,
        isstdcnt,
        leapcnt,
        timecnt,
        typecnt,
        charcnt,
    })
}

fn block_len(h: &Header, time_size: usize) -> Option<usize> {
    h.timecnt
        .checked_mul(time_size)?
        .checked_add(h.timecnt)?
        .checked_add(h.typecnt.checked_mul(6)?)?
        .checked_add(h.charcnt)?
        .checked_add(h.leapcnt.checked_mul(time_size + 4)?)?
        .checked_add(h.isstdcnt)?
        .checked_add(h.isutcnt)
}

impl TzifZone {
    /// Parses TZif bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader { data, pos: 0 };
        let h1 = read_header(&mut r)?;
        let len1 =
            block_len(&h1, 4).ok_or_else(|| Error::TimeZone("TZif: count overflow".into()))?;
        let (h, time_size) = if h1.version >= 2 {
            r.take(len1)?;
            (read_header(&mut r)?, 8)
        } else {
            (h1, 4)
        };
        if h.typecnt == 0 || h.typecnt > 256 {
            return Err(Error::TimeZone(format!(
                "TZif: invalid type count {}",
                h.typecnt
            )));
        }
        if (h.isstdcnt != 0 && h.isstdcnt != h.typecnt)
            || (h.isutcnt != 0 && h.isutcnt != h.typecnt)
        {
            return Err(Error::TimeZone(
                "TZif: inconsistent indicator counts".into(),
            ));
        }
        let need = block_len(&h, time_size)
            .ok_or_else(|| Error::TimeZone("TZif: count overflow".into()))?;
        if need > data.len().saturating_sub(r.pos) {
            return Err(Error::TimeZone("TZif: truncated data block".into()));
        }
        let mut transitions = Vec::with_capacity(h.timecnt);
        for _ in 0..h.timecnt {
            let b = r.take(time_size)?;
            let t = if time_size == 8 {
                i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            } else {
                i64::from(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            };
            if transitions.last().is_some_and(|&prev| t <= prev) {
                return Err(Error::TimeZone(
                    "TZif: transitions not strictly increasing".into(),
                ));
            }
            transitions.push(t);
        }
        let type_indices = r.take(h.timecnt)?.to_vec();
        if type_indices.iter().any(|&i| usize::from(i) >= h.typecnt) {
            return Err(Error::TimeZone("TZif: type index out of range".into()));
        }
        let mut raw_types = Vec::with_capacity(h.typecnt);
        for _ in 0..h.typecnt {
            let b = r.take(6)?;
            let utoff = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            if utoff == i32::MIN || utoff.abs() > 25 * 3600 {
                return Err(Error::TimeZone(format!("TZif: implausible offset {utoff}")));
            }
            raw_types.push((utoff, b[4] != 0, usize::from(b[5])));
        }
        let chars = r.take(h.charcnt)?;
        let types = raw_types
            .into_iter()
            .map(|(utoff, is_dst, idx)| {
                if idx >= chars.len().max(1) && !chars.is_empty() {
                    return Err(Error::TimeZone(
                        "TZif: abbreviation index out of range".into(),
                    ));
                }
                let abbr = chars
                    .get(idx..)
                    .map(|s| {
                        let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                        String::from_utf8_lossy(&s[..end]).into_owned()
                    })
                    .unwrap_or_default();
                Ok(LocalType {
                    utoff,
                    is_dst,
                    abbr,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        r.take(h.leapcnt * (time_size + 4) + h.isstdcnt + h.isutcnt)?;
        let footer = if h.version >= 2 {
            let rest = &data[r.pos..];
            parse_footer(rest)?
        } else {
            None
        };
        Ok(TzifZone {
            version: h.version,
            transitions,
            type_indices,
            types,
            footer,
        })
    }

    /// UTC offset (east-positive seconds) at `utc` seconds since the epoch.
    pub fn offset_at(&self, utc: i64) -> i32 {
        self.type_at(utc).map_or_else(
            || self.footer.as_ref().map_or(0, |f| f.offset_at(utc)),
            |t| t.utoff,
        )
    }

    /// Abbreviation in effect at `utc`.
    pub fn abbreviation_at(&self, utc: i64) -> String {
        match self.type_at(utc) {
            Some(t) => t.abbr.clone(),
            None => self
                .footer
                .as_ref()
                .map(|f| f.abbreviation_at(utc).to_string())
                .unwrap_or_default(),
        }
    }

    /// The local type for `utc`, or `None` when the footer rule applies.
    fn type_at(&self, utc: i64) -> Option<&LocalType> {
        let n = self.transitions.partition_point(|&t| t <= utc);
        if n == 0 {
            if self.transitions.is_empty() && self.footer.is_some() {
                return None;
            }
            return self.types.first();
        }
        if n == self.transitions.len() && self.footer.is_some() {
            return None;
        }
        self.types.get(usize::from(self.type_indices[n - 1]))
    }
}

fn parse_footer(rest: &[u8]) -> Result<Option<PosixTz>> {
    if rest.is_empty() {
        return Ok(None);
    }
    if rest[0] != b'\n' {
        return Err(Error::TimeZone(
            "TZif: footer does not start with newline".into(),
        ));
    }
    let body = &rest[1..];
    let end = body
        .iter()
        .position(|&c| c == b'\n')
        .ok_or_else(|| Error::TimeZone("TZif: unterminated footer".into()))?;
    let s = std::str::from_utf8(&body[..end])
        .map_err(|_| Error::TimeZone("TZif: footer is not UTF-8".into()))?;
    if s.is_empty() {
        return Ok(None);
    }
    PosixTz::parse(s).map(Some)
}

/// Serializes a zone as a TZif version-2 file (v1 block left empty, as RFC 8536 permits).
pub fn write_tzif_v2(
    transitions: &[(i64, u8)],
    types: &[LocalType],
    footer: Option<&str>,
) -> Vec<u8> {
    let mut chars: Vec<u8> = Vec::new();
    let mut desig = Vec::with_capacity(types.len());
    for t in types {
        desig.push(chars.len() as u8);
        chars.extend_from_slice(t.abbr.as_bytes());
        chars.push(0);
    }
    let header = |out: &mut Vec<u8>, timecnt: u32, typecnt: u32, charcnt: u32| {
        out.extend_from_slice(b"TZif2");
        out.extend_from_slice(&[0u8; 15]);
        for c in [0u32, 0, 0, timecnt, typecnt, charcnt] {
            out.extend_from_slice(&c.to_be_bytes());
        }
    };
    let mut out = Vec::new();
    // v1 block: one placeholder type and no transitions.
    header(&mut out, 0, 1, 1);
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    header(
        &mut out,
        transitions.len() as u32,
        types.len() as u32,
        chars.len() as u32,
    );
    for (t, _) in transitions {
        out.extend_from_slice(&t.to_be_bytes());
    }
    for (_, i) in transitions {
        out.push(*i);
    }
    for (t, d) in types.iter().zip(&desig) {
        out.extend_from_slice(&t.utoff.to_be_bytes());
        out.push(u8::from(t.is_dst));
        out.push(*d);
    }
    out.extend_from_slice(&chars);
    out.push(b'\n');
    if let Some(f) = footer {
        out.extend_from_slice(f.as_bytes());
    }
    out.push(b'\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn ts(y: i32, mo: u32, d: u32, h: u32) -> i64 {
        Utc.with_ymd_and_hms(y, mo, d, h, 0, 0).unwrap().timestamp()
    }

    fn est_edt() -> Vec<LocalType> {
        vec![
            LocalType {
                utoff: -18000,
                is_dst: false,
                abbr: "EST".into(),
            },
            LocalType {
                utoff: -14400,
                is_dst: true,
                abbr: "EDT".into(),
            },
        ]
    }

    #[test]
    fn roundtrip_with_transitions_and_footer() {
        let trans = vec![(ts(2024, 3, 10, 7), 1u8), (ts(2024, 11, 3, 6), 0u8)];
        let bytes = write_tzif_v2(&trans, &est_edt(), Some("EST5EDT,M3.2.0,M11.1.0"));
        let z = TzifZone::parse(&bytes).unwrap();
        assert_eq!(z.version, 2);
        assert_eq!(z.transitions.len(), 2);
        assert_eq!(z.offset_at(ts(2024, 1, 1, 0)), -18000); // before first: type 0
        assert_eq!(z.offset_at(ts(2024, 7, 1, 0)), -14400);
        assert_eq!(z.abbreviation_at(ts(2024, 7, 1, 0)), "EDT");
        // After the last transition the footer applies (DST in summer 2025).
        assert_eq!(z.offset_at(ts(2025, 7, 1, 0)), -14400);
        assert_eq!(z.offset_at(ts(2025, 1, 1, 0)), -18000);
        assert_eq!(z.abbreviation_at(ts(2025, 7, 1, 0)), "EDT");
    }

    #[test]
    fn footer_only_zone() {
        let bytes = write_tzif_v2(&[], &est_edt()[..1], Some("EST5EDT"));
        let z = TzifZone::parse(&bytes).unwrap();
        assert_eq!(z.offset_at(ts(2024, 7, 1, 0)), -14400);
        let no_footer = write_tzif_v2(&[], &est_edt()[..1], None);
        let z = TzifZone::parse(&no_footer).unwrap();
        assert!(z.footer.is_none());
        assert_eq!(z.offset_at(ts(2024, 7, 1, 0)), -18000);
    }

    #[test]
    fn rejects_corrupt_files() {
        let good = write_tzif_v2(&[(10, 0)], &est_edt(), Some("EST5"));
        assert!(TzifZone::parse(b"NOPE").is_err());
        for cut in [3, 20, 50, 60, good.len() - 3] {
            assert!(TzifZone::parse(&good[..cut]).is_err(), "cut at {cut}");
        }
        let mut bad_idx = write_tzif_v2(&[(10, 5)], &est_edt(), None);
        assert!(TzifZone::parse(&bad_idx).is_err());
        bad_idx[4] = b'9';
        assert!(TzifZone::parse(&bad_idx).is_err());
        let unsorted = write_tzif_v2(&[(10, 0), (5, 1)], &est_edt(), None);
        assert!(TzifZone::parse(&unsorted).is_err());
        let mut bad_footer = write_tzif_v2(&[], &est_edt(), Some("EST5"));
        let n = bad_footer.len();
        bad_footer[n - 6] = b'x';
        assert!(TzifZone::parse(&bad_footer).is_err());
    }

    #[test]
    fn reads_system_zoneinfo_when_available() {
        let path = std::path::Path::new("/usr/share/zoneinfo/America/New_York");
        let Ok(bytes) = std::fs::read(path) else {
            return; // not every CI image ships tzdata
        };
        let z = TzifZone::parse(&bytes).unwrap();
        assert_eq!(z.offset_at(ts(2024, 7, 1, 12)), -14400);
        assert_eq!(z.offset_at(ts(2024, 12, 31, 12)), -18000);
        assert_eq!(z.offset_at(ts(2040, 7, 1, 12)), -14400);
        assert_eq!(z.offset_at(ts(1950, 1, 1, 12)), -18000);
    }
}
