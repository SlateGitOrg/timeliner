//! # timeliner
//!
//! A Linux forensic super-timeline builder. Parsers turn heterogeneous
//! artifacts (syslog/auth/cron logs, shell histories, utmp-family binary
//! records, journald export streams, Sleuth Kit bodyfiles, dpkg/apt logs)
//! into one [`event::Event`] model with UTC timestamps; the
//! [`pipeline`] sorts and de-duplicates them, [`rules`] tags them, and
//! [`output`] renders JSONL, CSV, l2tcsv or a self-contained HTML report.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod event;
pub mod time;

pub use error::{Error, Result, Warning};
pub use event::{Event, EventKind, SourceKind};
pub mod parsers;
pub mod rules;
