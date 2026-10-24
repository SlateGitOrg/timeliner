//! # timeliner
//!
//! A Linux forensic super-timeline builder. Parsers turn heterogeneous
//! artifacts (syslog/auth/cron logs, shell histories, utmp-family binary
//! records, journald export streams, Sleuth Kit bodyfiles, dpkg/apt logs)
//! into one [`event::Event`] model with UTC timestamps; the
//! [`pipeline`] sorts and de-duplicates them, [`rules`] tags them, and
//! [`output`] renders JSONL, CSV, l2tcsv or a self-contained HTML report.
//!
//! ```no_run
//! use timeliner::discover::InputSpec;
//! use timeliner::pipeline::{build, BuildOptions};
//!
//! let tl = build(&[InputSpec::parse("evidence/")], &BuildOptions::default())?;
//! for e in tl.events.iter().filter(|e| !e.tags.is_empty()) {
//!     println!("{} {} {}", timeliner::event::format_ts(&e.ts), e.kind, e.description);
//! }
//! # Ok::<(), timeliner::Error>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bench;
pub mod dedup;
pub mod discover;
pub mod error;
pub mod event;
pub mod fixtures;
pub mod output;
pub mod parsers;
pub mod pipeline;
pub mod rules;
pub mod time;

pub use error::{Error, Result, Warning};
pub use event::{Event, EventKind, SourceKind};
