# Architecture

timeliner is one library crate (`src/lib.rs`) plus a thin CLI (`src/main.rs`).
Every module has unit tests at the bottom. Cross-module behaviour is tested in
`tests/`.

```
src/
├── event.rs            unified Event model, SourceKind / EventKind / Severity enums
├── error.rs            Error (fatal) vs Warning (per-line, non-fatal)
├── time/
│   ├── mod.rs          TimeZone (UTC | fixed | POSIX rule | TZif), local→UTC with DST resolution
│   ├── posix.rs        POSIX TZ string parser + transition computation
│   ├── tzif.rs         RFC 8536 TZif reader (v1–v4) and v2 writer
│   └── year.rs         year inference for year-less timestamps
├── parsers/
│   ├── mod.rs          ArtifactKind, ParseContext, ParseOutput, helpers
│   ├── syslog_line.rs  zero-copy RFC 3164 / 3339 / 5424 header parser
│   ├── semantics.rs    program+message → EventKind, user, fields
│   ├── syslog.rs       auth.log / syslog / cron logs (two-pass)
│   ├── history.rs      bash / zsh / fish history
│   ├── utmp.rs         wtmp / btmp / utmp records
│   ├── journal.rs      journalctl export format
│   ├── bodyfile.rs     Sleuth Kit bodyfile
│   └── packages.rs     dpkg.log, apt history.log
├── discover.rs         evidence walk, artifact detection, gzip, evidence context
├── pipeline.rs         two-phase parallel build, sort, dedup, rules, range filter
├── dedup.rs            cross-artifact duplicate merging
├── rules.rs            YAML rule compiler and engine
├── output/             jsonl + text (mod.rs), csv.rs (CSV + l2tcsv), html.rs
├── fixtures.rs         synthetic incident generator + ground-truth checker
└── bench.rs            synthetic-input throughput benchmark
```

## Data model

`Event` holds `ts: DateTime<Utc>`, `source`, `kind`, `host`, `user`,
`description`, `fields` (sorted map), `tags`, `rule_hits`, `time_flags`,
`artifact`, `location`, `also_seen`, and `raw` (truncated to 512 bytes).

- `kind` is the *meaning* (`ssh_login_success`, `sudo_command`, `user_created`,
  ...). A sshd login normalizes to the same kind and description whether it
  came from `auth.log`, `syslog` or the journal. That property is what makes
  dedup and rules source-agnostic.
- `location` is a 1-based line number for text artifacts, a 0-based record
  index for utmp files, and the entry number for journal export.
- `time_flags` records `year_inferred`, `local_time`, `tz_ambiguous` and
  `tz_gap`, so an analyst can see which timestamps are derived.
- `Event::get(name)` serves both built-ins (`kind`, `user`, ...) and fields
  (`src_ip`, `fields.command`). Rules and the ground-truth checker use it.

## Time normalization

### Zones

`TimeZone` wraps four representations behind `offset_at(utc)`:

| kind | source | lookup |
|---|---|---|
| UTC / fixed | `--tz UTC`, `--tz +05:30` | constant |
| POSIX rule | `--tz EST5EDT,M3.2.0,M11.1.0`, TZif footer | compute the year's two transition instants: O(1) |
| TZif | evidence `etc/localtime`, `--tzfile`, IANA name via `--zoneinfo-dir` | binary search over transitions, O(log T); footer after the last one |

**local → UTC** (`TimeZone::local_to_utc`): for wall-clock `L` (seconds as if
UTC), take the offsets in effect around `L-1d`, `L` and `L+1d` as candidates
`o`. Keep every `u = L - o` with `offset_at(u) == o`.

- One solution: unambiguous.
- Two: a DST overlap (fall back). The earliest is used and `tz_ambiguous` is set.
- None: a DST gap (spring forward). The pre-gap offset is applied (same as
  glibc `mktime` with `tm_isdst = -1`) and `tz_gap` is set.

This relies on transitions being more than a day apart, which holds for every
real zone.

**TZif parsing** validates every count against the remaining length with
checked arithmetic *before* allocating, requires strictly increasing
transitions, in-range type and abbreviation indices and plausible offsets
(|off| ≤ 25 h). Property tests feed it arbitrary bytes.

**Evidence context**: `etc/localtime` is usually an *absolute* symlink
(`/usr/share/zoneinfo/America/New_York`). `discover::resolve_in_root` follows
it inside the evidence root one component at a time: a symlink at *any*
position (the file itself or an intermediate directory such as `usr -> /usr`
or `etc -> /etc`) is expanded, absolute targets are re-rooted, `..` is clamped
at the root, and it gives up after 8 hops (symlink loops). `etc/timezone` and
`etc/hostname` go through the same resolver. If you just called
`fs::read("evidence/etc/localtime")`, or only checked the last component, the
OS would follow the links and you'd silently read the analyst's own zone
file.

### Year inference (`time/year.rs`)

RFC 3164 lines have no year. Files are chronological, so one forward pass
assigns a relative year `k`:

```
for each stamp s (month, day, time):
    if s.month < prev.month:                      k += 1            # Dec → Jan
    elif k > 0 and s.month > prev.month and
         days(prev → s wrapped into previous year) ≤ 7:
                                                  emit k-1 (straggler, state unchanged)
    else:                                         emit k
```

The absolute year is pinned at the last entry:

- `YearAnchor::Explicit(y)` (`--year`): the last entry is in `y`.
- `YearAnchor::NotAfter(limit)`: the latest year in `[limit.year-4, limit.year]`
  in which the last entry's date exists and is ≤ `limit`. Checking that the
  date exists makes `Feb 29` pick a leap year.

The pipeline computes `limit` as *newest trusted absolute timestamp + 1 day*,
converted to local time (`pipeline::robust_newest`):

- **Tiers.** System records (wtmp/btmp/utmp, journal, dpkg/apt) are used
  first. Shell histories, which the suspect account can write freely, are used
  only when no system record has a timestamp, and the report says so. The
  bodyfile never anchors (timestomping, collection-time mtimes).
- **Rejection.** Values after the analysis clock + 1 day are dropped. Then,
  with the values sorted, the largest tail of at most 1 % of them (at least
  one) that sits more than 366 days after the rest is dropped.
- **Warning.** If the newest artifact alone is more than 30 days ahead of every
  other anchoring artifact, a warning names it.
- **No absolute timestamps.** `NotAfter(analysis clock + 1 day)`, not "the
  current year", so rotated files (`auth.log.2.gz` with November entries
  analysed in October) land in the previous year and stay in order.

Every rejection or warning goes to the log, to `report.warnings` as
`(year anchor)` and to the report's year-anchor line.

Cost: O(n) time and O(n) memory for the per-line relative years.

## Parsing pipeline (`pipeline.rs`)

1. **Discover** (`discover.rs`): walk the inputs in sorted order and don't
   follow symlinks. Detect by path (rotation suffixes `.1`, `.gz` and
   `-YYYYMMDD` are stripped), then by content sniffing (journal fields,
   bodyfile shape, syslog header). Files under `etc/` are never sniffed. `.gz`
   is decompressed with `MultiGzDecoder` up to a 1 GiB cap.
2. **Phase A**, in parallel: every artifact that doesn't need year inference.
   Workers pull file indices from an `AtomicUsize`, and results land in
   per-index slots, so the output doesn't depend on thread scheduling.
3. **Year anchor**: `--year` if given, else phase A's newest trusted
   timestamp after outlier rejection (system records first, shell histories
   only without them), else the analysis clock as an upper bound (flagged).
4. **Phase B**, in parallel: syslog-family files with the anchor.
5. **Sort** by `(ts, source, artifact, location)`: a total, stable and
   deterministic order. O(n log n).
6. **Dedup** (below), then **rules** (below), then the `--from/--to` filter.
   Filtering comes after the rules so that `first_seen` baselines see the whole
   evidence.

### Syslog-family parser

Two passes over the file. First, parse every header with the hand-written
zero-copy `syslog_line::parse_line`: an optional `<PRI>`, then a BSD stamp,
an RFC 3339 token or RFC 5424 fields, then `host` and `tag[pid]:`. Collect the
partial stamps. Second, infer years, convert local time to UTC and classify the
message.

`semantics::classify` dispatches on the normalized program name, so only that
program's regexes run. Messages it can't classify become `log_message`.
Patterns are compiled once (`LazyLock`).

### Binary and structured parsers

- **utmp**: fixed 384-byte records decoded with bounds-free slicing
  (`chunks_exact`). A trailing partial record is reported. `DEAD_PROCESS` is
  paired with the open `USER_PROCESS` on the same `ut_line` (HashMap,
  O(1)/record), and `BOOT_TIME` clears open sessions. In btmp, `LOGIN_PROCESS`
  and `USER_PROCESS` are failed logins.
- **journal export**: a byte-level state machine. Text fields are
  `NAME=value\n`, binary fields are `NAME\n<u64 LE len><bytes>\n`, with the
  length checked against the remaining data and capped at 16 MiB. The time is
  `_SOURCE_REALTIME_TIMESTAMP`, falling back to `__REALTIME_TIMESTAMP`.
- **bodyfile**: split on `|` from both ends (the name may contain `|`). Equal
  timestamps among M/A/C/B collapse into one event with a `mactime`-style
  `macb` string.

## Dedup (`dedup.rs`)

```
for e in events (time-sorted):
    fp = hash(kind, lower(host), user, description)
    drop candidates[fp] older than e.ts - window
    target = first candidate c with
             c.artifact != e.artifact
             and e.artifact not already in c.also_seen
             and full key equal              # guards hash collisions
    if target: target.also_seen += provenance(e)
    else:      survivors += e; candidates[fp] += e
```

Two rules are worth spelling out:

- Identical events inside one artifact are never merged.
- A survivor takes at most one copy per other artifact, so *N* copies in each
  of two files pair up 1:1.

Complexity is O(n·k) time, where k is the number of identical events in the
window (small), and O(n) memory. The default window is 2 s. Syslog truncates
timestamps to the second and the journal keeps µs, so the window has to cover
truncation plus a little receive delay.

## Rules (`rules.rs`)

A rule compiles into a conjunction of `(field, Matcher)` pairs (`when`), an
optional conjunction that vetoes it (`unless`), and a `Stateful` mode:

| mode | state | per-event cost |
|---|---|---|
| none | none | O(m) matchers |
| `threshold {count, window, group_by}` | `HashMap<group, VecDeque<ts>>` sliding window | amortized O(1) |
| `first_seen {value, group_by, require_history, learn_until}` | `HashMap<group, HashSet<value>>` | O(1) |

`ssh-new-ip` uses `first_seen` with `group_by: [user]` and
`require_history: true`. It fires when an account that has already logged in
from somewhere logs in from a new source. An account's very first login in the
evidence doesn't fire. `--baseline-until` turns the earlier period into a pure
learning window instead.

The engine makes one pass over the sorted timeline: O(n·r) time, with memory
proportional to the distinct groups.

## Outputs

- **JSONL**: serde serialization of `Event`. It round-trips (tested).
- **CSV**: 13 columns. RFC 4180 quoting, CRLF line endings. Formula guard: a
  cell longer than one character that starts with `= + - @ \t \r` gets a `'`
  prefix (on by default, `--no-csv-safe` turns it off).
- **l2tcsv**: plaso's 17 columns (`date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`), with UTC dates as `MM/DD/YYYY`. The bodyfile `macb` goes into the MACB column, and the `type` column spells out the timestamp descriptions.
- **text**: aligned columns. Control characters, including ESC, are escaped,
  so logs can't inject terminal sequences.
- **HTML**: a single file.
  - Content: summary cards, findings table (server-rendered and escaped), SVG
    histogram with adaptive buckets (≤ ~120 bars), rule-hit and artifact
    tables, and a client-side filterable and paginated timeline.
  - Data: events are embedded as compact JSON arrays in
    `<script type="application/json">`, with `< > &` and U+2028/2029 escaped.
    Rows are rendered via `textContent` only.
  - CSP: `default-src 'none'`, plus `style-src` and `script-src` restricted to
    the SHA-256 hashes of the inline CSS and JS.
  - Size and determinism: the embedded table is capped (`--html-max-events`,
    flagged events always kept). There's no generation timestamp, so output is
    deterministic.

## Fixture generator (`fixtures.rs`)

The generator is SplitMix64-seeded. It builds the story's events at UTC
instants and renders each artifact in its native format:

- local EST wall clock for syslog, dpkg and apt
- epoch for wtmp, journal, histories and bodyfile
- a TZif `etc/localtime` (2023–2024 transitions plus the POSIX footer, so the
  incident window exercises the footer path) behind an absolute symlink

It writes `GROUND_TRUTH.json`, with each step's UTC time, expected kind, user,
fields and tag, and `STORY.md`. `check_story` finds the first event matching
each step at the same second and verifies tags and order.
`cargo test --test story` asserts that the committed tree is byte-identical to
a fresh generation.
