//! Artifact parsers. Each parser turns raw bytes into [`Event`]s plus
//! non-fatal [`Warning`]s; none of them panics on malformed input (this is
//! property-tested in `tests/prop_parsers.rs`).

pub mod bodyfile;
pub mod history;
pub mod journal;
pub mod packages;
pub mod semantics;
pub mod syslog;
pub mod syslog_line;
pub mod utmp;

use std::borrow::Cow;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::Warning;
use crate::event::{Event, SourceKind};
use crate::time::TimeZone;
use crate::time::year::YearAnchor;

/// Maximum warnings stored per artifact (the total is still counted).
pub const MAX_STORED_WARNINGS: usize = 50;

/// Everything a parser needs besides the bytes.
#[derive(Debug, Clone)]
pub struct ParseContext {
    /// Display path of the artifact (relative to the evidence root).
    pub artifact: String,
    /// Zone for local wall-clock timestamps.
    pub tz: TimeZone,
    /// Anchor for year-less timestamps.
    pub year_anchor: YearAnchor,
    /// Host name to use when the artifact does not record one.
    pub host: Option<String>,
    /// Account owning the artifact (shell histories), if known.
    pub user: Option<String>,
}

/// Parser result for one artifact.
#[derive(Debug, Clone, Default)]
pub struct ParseOutput {
    /// Recovered events (in artifact order).
    pub events: Vec<Event>,
    /// Up to [`MAX_STORED_WARNINGS`] warnings.
    pub warnings: Vec<Warning>,
    /// Total number of warnings, including ones not stored.
    pub warning_count: u64,
    /// Lines / records / entries examined.
    pub records: u64,
}

impl ParseOutput {
    /// Records a warning.
    pub fn warn(&mut self, ctx: &ParseContext, location: u64, message: impl Into<String>) {
        self.warning_count += 1;
        if self.warnings.len() < MAX_STORED_WARNINGS {
            self.warnings.push(Warning {
                artifact: ctx.artifact.clone(),
                location,
                message: message.into(),
            });
        }
    }
}

/// Trust level of an artifact's timestamps as a year anchor
/// (see [`ArtifactKind::anchor_tier`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnchorTier {
    /// Written by privileged system components (wtmp/btmp/utmp, journal, dpkg/apt).
    System,
    /// Freely writable by an unprivileged account (shell histories).
    UserWritable,
}

/// Supported artifact formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// auth.log / secure (syslog format).
    AuthLog,
    /// syslog / messages / kern.log / daemon.log.
    Syslog,
    /// cron / cron.log (syslog or legacy cron format).
    CronLog,
    /// bash history with `#<epoch>` lines.
    BashHistory,
    /// zsh extended history (`: <epoch>:<dur>;cmd`).
    ZshHistory,
    /// fish history (YAML-like).
    FishHistory,
    /// wtmp binary records.
    Wtmp,
    /// btmp binary records.
    Btmp,
    /// utmp binary records.
    Utmp,
    /// `journalctl -o export` stream.
    JournalExport,
    /// Sleuth Kit bodyfile.
    Bodyfile,
    /// dpkg.log.
    DpkgLog,
    /// apt history.log.
    AptHistory,
}

impl ArtifactKind {
    /// Every kind.
    pub const ALL: &'static [ArtifactKind] = &[
        ArtifactKind::AuthLog,
        ArtifactKind::Syslog,
        ArtifactKind::CronLog,
        ArtifactKind::BashHistory,
        ArtifactKind::ZshHistory,
        ArtifactKind::FishHistory,
        ArtifactKind::Wtmp,
        ArtifactKind::Btmp,
        ArtifactKind::Utmp,
        ArtifactKind::JournalExport,
        ArtifactKind::Bodyfile,
        ArtifactKind::DpkgLog,
        ArtifactKind::AptHistory,
    ];

    /// Canonical name, as accepted by `--type`.
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::AuthLog => "auth_log",
            ArtifactKind::Syslog => "syslog",
            ArtifactKind::CronLog => "cron_log",
            ArtifactKind::BashHistory => "bash_history",
            ArtifactKind::ZshHistory => "zsh_history",
            ArtifactKind::FishHistory => "fish_history",
            ArtifactKind::Wtmp => "wtmp",
            ArtifactKind::Btmp => "btmp",
            ArtifactKind::Utmp => "utmp",
            ArtifactKind::JournalExport => "journal_export",
            ArtifactKind::Bodyfile => "bodyfile",
            ArtifactKind::DpkgLog => "dpkg_log",
            ArtifactKind::AptHistory => "apt_history",
        }
    }

    /// Parses a canonical name.
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == s)
    }

    /// Source label for events from this artifact.
    pub fn source(self) -> SourceKind {
        match self {
            ArtifactKind::AuthLog => SourceKind::AuthLog,
            ArtifactKind::Syslog => SourceKind::Syslog,
            ArtifactKind::CronLog => SourceKind::Cron,
            ArtifactKind::BashHistory | ArtifactKind::ZshHistory | ArtifactKind::FishHistory => {
                SourceKind::ShellHistory
            }
            ArtifactKind::Wtmp => SourceKind::Wtmp,
            ArtifactKind::Btmp => SourceKind::Btmp,
            ArtifactKind::Utmp => SourceKind::Utmp,
            ArtifactKind::JournalExport => SourceKind::Journal,
            ArtifactKind::Bodyfile => SourceKind::Bodyfile,
            ArtifactKind::DpkgLog => SourceKind::Dpkg,
            ArtifactKind::AptHistory => SourceKind::AptHistory,
        }
    }

    /// True when timestamps may lack a year (needs a [`YearAnchor`]).
    pub fn needs_year_inference(self) -> bool {
        matches!(
            self,
            ArtifactKind::AuthLog | ArtifactKind::Syslog | ArtifactKind::CronLog
        )
    }

    /// Whether, and how much, the artifact's absolute timestamps may anchor
    /// year inference for the year-less logs (`None`: never).
    ///
    /// Only records written by privileged system components (login
    /// accounting, journald, dpkg/apt) are [`AnchorTier::System`]. Shell
    /// histories are [`AnchorTier::UserWritable`]: the suspect account can
    /// write any `#<epoch>` line into them, so they are consulted only when
    /// the evidence holds no system record at all. The bodyfile is never
    /// used (timestomping, collection-time mtimes).
    pub fn anchor_tier(self) -> Option<AnchorTier> {
        match self {
            ArtifactKind::Wtmp
            | ArtifactKind::Btmp
            | ArtifactKind::Utmp
            | ArtifactKind::JournalExport
            | ArtifactKind::DpkgLog
            | ArtifactKind::AptHistory => Some(AnchorTier::System),
            ArtifactKind::BashHistory | ArtifactKind::ZshHistory | ArtifactKind::FishHistory => {
                Some(AnchorTier::UserWritable)
            }
            ArtifactKind::AuthLog
            | ArtifactKind::Syslog
            | ArtifactKind::CronLog
            | ArtifactKind::Bodyfile => None,
        }
    }

    /// Runs the matching parser.
    pub fn parse(self, data: &[u8], ctx: &ParseContext) -> ParseOutput {
        match self {
            ArtifactKind::AuthLog | ArtifactKind::Syslog | ArtifactKind::CronLog => {
                syslog::parse(data, ctx, self.source())
            }
            ArtifactKind::BashHistory => history::parse_bash(data, ctx),
            ArtifactKind::ZshHistory => history::parse_zsh(data, ctx),
            ArtifactKind::FishHistory => history::parse_fish(data, ctx),
            ArtifactKind::Wtmp | ArtifactKind::Btmp | ArtifactKind::Utmp => {
                utmp::parse(data, ctx, self.source())
            }
            ArtifactKind::JournalExport => journal::parse(data, ctx),
            ArtifactKind::Bodyfile => bodyfile::parse(data, ctx),
            ArtifactKind::DpkgLog => packages::parse_dpkg(data, ctx),
            ArtifactKind::AptHistory => packages::parse_apt_history(data, ctx),
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Iterates `(1-based line number, line)` over text, tolerating invalid UTF-8
/// and CRLF line endings.
pub fn lines(data: &[u8]) -> impl Iterator<Item = (u64, Cow<'_, str>)> {
    let data = data.strip_suffix(b"\n").unwrap_or(data);
    let empty = data.is_empty();
    data.split(|&b| b == b'\n')
        .filter(move |_| !empty)
        .enumerate()
        .map(|(i, l)| {
            let l = l.strip_suffix(b"\r").unwrap_or(l);
            (i as u64 + 1, String::from_utf8_lossy(l))
        })
}

/// Converts seconds + nanoseconds since the epoch, rejecting absurd values
/// (before 1970 or after 2200), which in practice indicate corruption.
pub fn epoch_to_utc(secs: i64, nanos: u32) -> Option<DateTime<Utc>> {
    const MAX: i64 = 7_258_118_400; // 2200-01-01
    if !(0..MAX).contains(&secs) {
        return None;
    }
    DateTime::from_timestamp(secs, nanos)
}

/// Guesses the account from a path such as `home/alice/.bash_history` or `root/.zsh_history`.
pub fn user_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    for (i, p) in parts.iter().enumerate() {
        if *p == "home" && i + 2 < parts.len() {
            return Some(parts[i + 1].to_string());
        }
        if *p == "root" && i + 1 < parts.len() {
            return Some("root".into());
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    pub fn ctx(artifact: &str) -> ParseContext {
        ParseContext {
            artifact: artifact.into(),
            tz: TimeZone::utc(),
            year_anchor: YearAnchor::Explicit(2025),
            host: Some("web01".into()),
            user: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_iteration() {
        let v: Vec<_> = lines(b"a\r\nb\n\xffc\n").collect();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], (1, Cow::Borrowed("a")));
        assert_eq!(v[2].1, "\u{fffd}c");
        assert_eq!(lines(b"").count(), 0);
        assert_eq!(lines(b"\n").count(), 0);
        assert_eq!(lines(b"\n\n").count(), 2);
    }

    #[test]
    fn epoch_bounds() {
        assert!(epoch_to_utc(-1, 0).is_none());
        assert!(epoch_to_utc(8_000_000_000, 0).is_none());
        assert_eq!(epoch_to_utc(1, 5).unwrap().timestamp(), 1);
    }

    #[test]
    fn users_from_paths() {
        assert_eq!(
            user_from_path("home/alice/.bash_history").as_deref(),
            Some("alice")
        );
        assert_eq!(
            user_from_path("/x/root/.zsh_history").as_deref(),
            Some("root")
        );
        assert_eq!(user_from_path("var/log/syslog"), None);
        assert_eq!(user_from_path("home/.bash_history"), None);
    }

    #[test]
    fn kind_names_roundtrip() {
        for k in ArtifactKind::ALL {
            assert_eq!(ArtifactKind::from_name(k.as_str()), Some(*k));
            assert_eq!(k.to_string(), k.as_str());
            let _ = k.source();
        }
        assert_eq!(ArtifactKind::from_name("x"), None);
    }
}
