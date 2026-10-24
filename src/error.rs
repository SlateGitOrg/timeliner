//! Error types shared by the library.
//!
//! Per-line problems inside an artifact are *not* errors: they are reported as
//! [`Warning`]s so that one corrupt line never stops a timeline from being
//! built. [`Error`] is reserved for conditions that make an operation
//! impossible (unreadable file, invalid time-zone specification, bad rule file).

use std::fmt;
use std::path::PathBuf;

/// Library-level error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or directory could not be read or written.
    #[error("I/O error on {path}: {source}")]
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// A time-zone specification or TZif file was invalid.
    #[error("time zone error: {0}")]
    TimeZone(String),
    /// A tagging-rule file was invalid.
    #[error("rule error: {0}")]
    Rule(String),
    /// An argument was invalid (bad timestamp, unknown artifact kind, ...).
    #[error("invalid argument: {0}")]
    Invalid(String),
}

impl Error {
    /// Convenience constructor for [`Error::Io`].
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

/// Library result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// A non-fatal problem found while parsing one artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Warning {
    /// Display name of the artifact.
    pub artifact: String,
    /// 1-based line number (text) or 0-based record index (binary); 0 if not applicable.
    pub location: u64,
    /// Human-readable description.
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.artifact, self.location, self.message)
    }
}
