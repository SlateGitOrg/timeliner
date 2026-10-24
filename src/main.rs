//! `timeliner` command-line interface.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use timeliner::bench;
use timeliner::discover::{self, InputSpec};
use timeliner::fixtures::{self, FixtureOptions};
use timeliner::output::{self, Format, OutputOptions};
use timeliner::pipeline::{self, BuildOptions, Timeline};
use timeliner::rules::RuleSet;
use timeliner::time::TimeZone;

#[derive(Parser)]
#[command(
    name = "timeliner",
    version,
    about = "Linux forensic super-timeline builder",
    long_about = "Parses auth/syslog/cron logs, shell histories, wtmp/btmp/utmp, journal export, \
Sleuth Kit bodyfiles and dpkg/apt logs into one UTC timeline, de-duplicates it, tags it with \
YAML rules and writes JSONL, CSV, l2tcsv or a self-contained HTML report."
)]
struct Cli {
    /// More logging on stderr (-v info, -vv debug).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build a timeline from evidence directories and/or files.
    Build(BuildArgs),
    /// Check a timeline against a fixture's GROUND_TRUTH.json.
    Verify(VerifyArgs),
    /// List the artifacts that would be parsed.
    Detect {
        /// Directories or files (`KIND=path` forces a format).
        #[arg(required = true)]
        inputs: Vec<String>,
    },
    /// Validate and list tagging rules.
    Rules(RuleArgs),
    /// Generate the synthetic incident fixture set.
    Fixtures {
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
        /// PRNG seed.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Background-noise multiplier.
        #[arg(long, default_value_t = 1)]
        scale: u32,
    },
    /// Measure parser throughput on synthetic data.
    Bench {
        /// Records per parser.
        #[arg(long, default_value_t = 200_000)]
        lines: usize,
        /// Repetitions (best is reported).
        #[arg(long, default_value_t = 3)]
        rounds: usize,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args, Clone)]
struct RuleArgs {
    /// Extra rule files (YAML).
    #[arg(long = "rules", value_name = "FILE")]
    rules: Vec<PathBuf>,
    /// Do not load the built-in ruleset.
    #[arg(long)]
    no_default_rules: bool,
}

#[derive(Args, Clone)]
struct TimeArgs {
    /// Directories or files; `KIND=path` forces a format (e.g. `bodyfile=fls.txt`).
    #[arg(required = true)]
    inputs: Vec<String>,
    /// Zone for local-time logs: UTC, +05:30, a POSIX rule or an IANA name
    /// (default: the evidence's own etc/localtime).
    #[arg(long)]
    tz: Option<String>,
    /// TZif file to use as the zone (e.g. a copy of the suspect's /etc/localtime).
    #[arg(long, conflicts_with = "tz")]
    tzfile: Option<PathBuf>,
    /// Directory of IANA TZif files for zone names.
    #[arg(long, default_value = "/usr/share/zoneinfo")]
    zoneinfo_dir: PathBuf,
    /// Year of the newest entry in year-less logs (default: inferred).
    #[arg(long)]
    year: Option<i32>,
    /// Host name for artifacts that do not record one (default: etc/hostname).
    #[arg(long)]
    host: Option<String>,
    #[command(flatten)]
    rules: RuleArgs,
    /// Disable tagging entirely.
    #[arg(long)]
    no_rules: bool,
    /// Keep cross-artifact duplicates.
    #[arg(long)]
    no_dedup: bool,
    /// Duplicate tolerance in seconds.
    #[arg(long, default_value_t = 2)]
    dedup_window: i64,
    /// Treat events before this instant as the baseline for first-seen rules.
    #[arg(long, value_name = "TIME")]
    baseline_until: Option<String>,
    /// Worker threads (0 = all cores).
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

#[derive(Args)]
struct BuildArgs {
    #[command(flatten)]
    time: TimeArgs,
    /// Output file (default: stdout).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Output format: jsonl, csv, l2tcsv, html (default: from the file name, else jsonl).
    #[arg(short, long)]
    format: Option<Format>,
    /// Keep events at or after this time (RFC 3339 or YYYY-MM-DD, UTC).
    #[arg(long)]
    from: Option<String>,
    /// Keep events at or before this time.
    #[arg(long)]
    to: Option<String>,
    /// Only output events with a rule hit.
    #[arg(long)]
    only_tagged: bool,
    /// Do not neutralize spreadsheet formulas in CSV output.
    #[arg(long)]
    no_csv_safe: bool,
    /// Maximum unflagged events embedded in the HTML timeline table.
    #[arg(long, default_value_t = 50_000)]
    html_max_events: usize,
    /// Report title.
    #[arg(long, default_value = "timeliner report")]
    title: String,
    /// Print a build summary to stderr.
    #[arg(long)]
    summary: bool,
}

#[derive(Args)]
struct VerifyArgs {
    #[command(flatten)]
    time: TimeArgs,
    /// Ground-truth file written by `timeliner fixtures`.
    #[arg(long)]
    truth: PathBuf,
}

fn parse_time(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .with_context(|| format!("invalid time `{s}` (use RFC 3339 or YYYY-MM-DD)"))?;
    Ok(d.and_hms_opt(0, 0, 0)
        .ok_or_else(|| anyhow!("invalid date"))?
        .and_utc())
}

fn load_rules(args: &RuleArgs) -> Result<RuleSet> {
    let mut set = if args.no_default_rules {
        RuleSet::default()
    } else {
        RuleSet::default_rules()
    };
    for p in &args.rules {
        set.extend(RuleSet::from_file(p)?)?;
    }
    Ok(set)
}

fn build_options(t: &TimeArgs) -> Result<(BuildOptions, Option<RuleSet>)> {
    let tz = match (&t.tz, &t.tzfile) {
        (Some(spec), _) => Some(TimeZone::parse(spec, &t.zoneinfo_dir)?),
        (None, Some(path)) => {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            Some(TimeZone::from_tzif(&bytes, &path.display().to_string())?)
        }
        (None, None) => None,
    };
    let rules = if t.no_rules {
        None
    } else {
        let mut r = load_rules(&t.rules)?;
        if let Some(b) = &t.baseline_until {
            r.set_baseline_until(parse_time(b)?);
        }
        Some(r)
    };
    if t.dedup_window < 0 {
        bail!("--dedup-window must be >= 0");
    }
    let opts = BuildOptions {
        tz,
        zoneinfo_dir: t.zoneinfo_dir.clone(),
        year: t.year,
        host: t.host.clone(),
        rules: rules.clone(),
        dedup: !t.no_dedup,
        dedup_window: chrono::Duration::seconds(t.dedup_window),
        threads: t.threads,
        ..BuildOptions::default()
    };
    Ok((opts, rules))
}

fn inputs(raw: &[String]) -> Vec<InputSpec> {
    raw.iter().map(|s| InputSpec::parse(s)).collect()
}

fn print_summary(tl: &Timeline) {
    let r = &tl.report;
    eprintln!(
        "timeliner: {} events ({} parsed, {} duplicates merged) from {} artifacts",
        r.events,
        r.parsed_events,
        r.duplicates_merged,
        r.artifacts.len()
    );
    eprintln!("  time zone: {} ({})", r.timezone, r.timezone_source);
    eprintln!("  years:     {}", r.year_anchor);
    if let (Some(a), Some(b)) = (&r.first, &r.last) {
        eprintln!("  range:     {a} .. {b}");
    }
    for a in &r.artifacts {
        eprintln!(
            "  {:<48} {:<15} {:>7} records {:>7} events {:>4} warnings{}",
            a.path,
            a.kind.as_str(),
            a.records,
            a.events,
            a.warnings,
            a.error
                .as_deref()
                .map(|e| format!("  ERROR: {e}"))
                .unwrap_or_default()
        );
    }
    for (rule, n) in &r.rule_hits {
        eprintln!("  rule {rule:<28} {n:>5} hit(s)");
    }
}

fn cmd_build(args: BuildArgs) -> Result<()> {
    let (mut opts, rules) = build_options(&args.time)?;
    opts.from = args.from.as_deref().map(parse_time).transpose()?;
    opts.to = args.to.as_deref().map(parse_time).transpose()?;
    let mut tl = pipeline::build(&inputs(&args.time.inputs), &opts)?;
    if args.only_tagged {
        tl.events.retain(|e| !e.rule_hits.is_empty());
    }
    if args.summary {
        print_summary(&tl);
    }
    let format = args
        .format
        .or_else(|| args.output.as_deref().and_then(Format::from_path))
        .unwrap_or(Format::Jsonl);
    let mut oo = OutputOptions {
        csv_safe: !args.no_csv_safe,
        html_max_events: args.html_max_events,
        title: args.title.clone(),
        ..OutputOptions::default()
    };
    if let Some(r) = &rules {
        oo = oo.with_rules(r);
    }
    match &args.output {
        Some(path) => {
            let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
            let mut w = BufWriter::new(f);
            output::write(&tl, format, &oo, &mut w)?;
            w.flush()?;
        }
        None => {
            let stdout = io::stdout();
            let mut w = BufWriter::new(stdout.lock());
            output::write(&tl, format, &oo, &mut w)?;
            w.flush()?;
        }
    }
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<bool> {
    let truth = fixtures::load_ground_truth(&args.truth)?;
    let (opts, _) = build_options(&args.time)?;
    let tl = pipeline::build(&inputs(&args.time.inputs), &opts)?;
    let check = fixtures::check_story(&truth, &tl.events);
    println!(
        "{:<4} {:<21} {:<20} {:<6} {:<5} title",
        "step", "expected (UTC)", "kind", "found", "tag"
    );
    for (step, (_, idx)) in truth.steps.iter().zip(&check.found) {
        let tag_ok = if step.tag.is_none() {
            "-"
        } else if check.missing_tags.contains(&step.id) {
            "MISS"
        } else if idx.is_some() {
            "ok"
        } else {
            "-"
        };
        println!(
            "{:<4} {:<21} {:<20} {:<6} {:<5} {}",
            step.id,
            step.utc,
            step.kind.as_str(),
            idx.map_or("NO".to_string(), |i| format!("#{i}")),
            tag_ok,
            step.title
        );
    }
    let found = check.found.iter().filter(|(_, i)| i.is_some()).count();
    println!(
        "\n{found}/{} steps found, {} missing tag(s), chronological order {}: {}",
        truth.steps.len(),
        check.missing_tags.len(),
        if check.in_order {
            "preserved"
        } else {
            "VIOLATED"
        },
        if check.passed() { "PASS" } else { "FAIL" }
    );
    Ok(check.passed())
}

fn cmd_detect(raw: &[String]) -> Result<()> {
    for f in discover::discover(&inputs(raw))? {
        println!("{:<15} {}", f.kind.as_str(), f.display);
    }
    Ok(())
}

fn cmd_rules(args: &RuleArgs) -> Result<()> {
    let set = load_rules(args)?;
    for r in &set.rules {
        println!("{:<28} {:<8} {}", r.id, r.severity.as_str(), r.title);
    }
    eprintln!("{} rule(s) OK", set.rules.len());
    Ok(())
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Build(a) => cmd_build(a)?,
        Cmd::Verify(a) => {
            if !cmd_verify(a)? {
                return Ok(ExitCode::from(1));
            }
        }
        Cmd::Detect { inputs } => cmd_detect(&inputs)?,
        Cmd::Rules(a) => cmd_rules(&a)?,
        Cmd::Fixtures { out, seed, scale } => {
            let truth = fixtures::generate(&out, &FixtureOptions { seed, scale })?;
            eprintln!(
                "wrote {} ({} ground-truth steps)",
                out.display(),
                truth.steps.len()
            );
        }
        Cmd::Bench {
            lines,
            rounds,
            json,
        } => {
            let results = bench::run(lines, rounds);
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                print!("{}", bench::table(&results));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)),
        )
        .with_writer(io::stderr)
        .without_time()
        .with_target(false)
        .init();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            if e.downcast_ref::<io::Error>()
                .is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe)
            {
                return ExitCode::SUCCESS;
            }
            eprintln!("timeliner: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_arguments() {
        assert_eq!(
            parse_time("2025-01-01").unwrap(),
            DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z").unwrap()
        );
        assert!(parse_time("2025-01-01T04:00:00-05:00").is_ok());
        assert!(parse_time("yesterday").is_err());
    }
}
