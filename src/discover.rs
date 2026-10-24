//! Evidence discovery: walk input directories, recognize artifacts by path
//! and content, and read system context (time zone, host name) from the
//! evidence itself rather than from the analysis machine.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use flate2::read::MultiGzDecoder;
use tracing::debug;

use crate::error::{Error, Result};
use crate::parsers::{ArtifactKind, syslog_line};
use crate::time::TimeZone;

/// Default cap on decompressed size of one `.gz` artifact (zip-bomb guard).
pub const DEFAULT_MAX_DECOMPRESSED: u64 = 1 << 30;

/// Maximum symlink hops followed when resolving a path inside an evidence root.
const MAX_LINK_HOPS: usize = 8;

/// One artifact selected for parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactFile {
    /// Real path on disk.
    pub path: PathBuf,
    /// Path shown in output (relative to the evidence root, `/`-separated).
    pub display: String,
    /// Detected or forced format.
    pub kind: ArtifactKind,
    /// Evidence root the file was found under, if it came from a directory walk.
    pub root: Option<PathBuf>,
}

/// Strips rotation suffixes: `.gz`, `.1`, `-20240101`.
pub fn base_name(name: &str) -> &str {
    let mut n = name.strip_suffix(".gz").unwrap_or(name);
    if let Some((stem, suffix)) = n.rsplit_once('.')
        && !suffix.is_empty()
        && suffix.len() <= 3
        && suffix.bytes().all(|b| b.is_ascii_digit())
    {
        n = stem;
    }
    if let Some((stem, suffix)) = n.rsplit_once('-')
        && suffix.len() == 8
        && suffix.bytes().all(|b| b.is_ascii_digit())
    {
        n = stem;
    }
    n
}

/// Recognizes an artifact from its relative path alone.
pub fn detect_by_path(rel: &str) -> Option<ArtifactKind> {
    let rel = rel.replace('\\', "/");
    let mut parts = rel.rsplit('/');
    let file = parts.next()?;
    let parent = parts.next().unwrap_or("");
    let base = base_name(file);
    let kind = match base {
        "auth.log" | "secure" => ArtifactKind::AuthLog,
        "syslog" | "messages" | "kern.log" | "daemon.log" | "user.log" => ArtifactKind::Syslog,
        "cron" | "cron.log" => ArtifactKind::CronLog,
        "wtmp" => ArtifactKind::Wtmp,
        "btmp" => ArtifactKind::Btmp,
        "utmp" => ArtifactKind::Utmp,
        ".bash_history" => ArtifactKind::BashHistory,
        ".zsh_history" | ".zhistory" | ".histfile" => ArtifactKind::ZshHistory,
        "fish_history" => ArtifactKind::FishHistory,
        "dpkg.log" => ArtifactKind::DpkgLog,
        "history.log" if parent == "apt" => ArtifactKind::AptHistory,
        "bodyfile" | "bodyfile.txt" => ArtifactKind::Bodyfile,
        b if b.ends_with(".body") || b.ends_with(".bodyfile") => ArtifactKind::Bodyfile,
        b if b.ends_with(".export") => ArtifactKind::JournalExport,
        _ => return None,
    };
    Some(kind)
}

/// Recognizes an artifact from its first bytes (used when the path is not conclusive).
pub fn detect_by_content(head: &[u8]) -> Option<ArtifactKind> {
    let text = String::from_utf8_lossy(head);
    if text.contains("__REALTIME_TIMESTAMP=") || text.contains("__CURSOR=") {
        return Some(ArtifactKind::JournalExport);
    }
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))?;
    let fields: Vec<&str> = first.split('|').collect();
    if fields.len() >= 11
        && fields[fields.len() - 4..].iter().all(|f| {
            f.split('.')
                .next()
                .is_some_and(|s| s.parse::<i64>().is_ok())
        })
    {
        return Some(ArtifactKind::Bodyfile);
    }
    if syslog_line::parse_line(first).is_some() {
        return Some(ArtifactKind::Syslog);
    }
    None
}

/// Reads an artifact, transparently decompressing gzip (bounded by `max_decompressed`).
pub fn read_artifact(path: &Path, max_decompressed: u64) -> Result<Vec<u8>> {
    let raw = fs::read(path).map_err(|e| Error::io(path, e))?;
    if raw.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        MultiGzDecoder::new(raw.as_slice())
            .take(max_decompressed + 1)
            .read_to_end(&mut out)
            .map_err(|e| Error::io(path, e))?;
        if out.len() as u64 > max_decompressed {
            return Err(Error::Invalid(format!(
                "{}: decompressed size exceeds {max_decompressed} bytes",
                path.display()
            )));
        }
        return Ok(out);
    }
    Ok(raw)
}

fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| Error::io(dir, e))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for p in entries {
        let meta = fs::symlink_metadata(&p).map_err(|e| Error::io(&p, e))?;
        if meta.file_type().is_symlink() {
            debug!(path = %p.display(), "skipping symlink (evidence symlinks may point outside the image)");
        } else if meta.is_dir() {
            walk(&p, out)?;
        } else if meta.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

/// An input specification: a path, optionally with a forced kind (`kind=path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSpec {
    /// File or directory.
    pub path: PathBuf,
    /// Forced artifact kind for a single file.
    pub kind: Option<ArtifactKind>,
}

impl InputSpec {
    /// Parses `path` or `kind=path`.
    pub fn parse(s: &str) -> Self {
        if let Some((k, p)) = s.split_once('=')
            && let Some(kind) = ArtifactKind::from_name(k)
        {
            return InputSpec {
                path: PathBuf::from(p),
                kind: Some(kind),
            };
        }
        InputSpec {
            path: PathBuf::from(s),
            kind: None,
        }
    }
}

/// Discovers artifacts under the given inputs (sorted, deterministic).
pub fn discover(inputs: &[InputSpec]) -> Result<Vec<ArtifactFile>> {
    let mut found = Vec::new();
    for input in inputs {
        let meta = fs::metadata(&input.path).map_err(|e| Error::io(&input.path, e))?;
        if meta.is_dir() {
            let mut files = Vec::new();
            walk(&input.path, &mut files)?;
            for f in files {
                let rel = rel_display(&input.path, &f);
                let kind = match detect_by_path(&rel) {
                    Some(k) => Some(k),
                    None if rel.starts_with("etc/") => None,
                    None => sniff(&f),
                };
                match kind {
                    Some(kind) => found.push(ArtifactFile {
                        path: f,
                        display: rel,
                        kind,
                        root: Some(input.path.clone()),
                    }),
                    None => debug!(path = rel.as_str(), "not a recognized artifact"),
                }
            }
        } else {
            let display = input.path.to_string_lossy().replace('\\', "/");
            let kind = input
                .kind
                .or_else(|| detect_by_path(&display))
                .or_else(|| sniff(&input.path))
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "cannot detect the artifact type of {display}; prefix it with KIND= (e.g. syslog={display})"
                    ))
                })?;
            found.push(ArtifactFile {
                path: input.path.clone(),
                display,
                kind,
                root: None,
            });
        }
    }
    Ok(found)
}

fn sniff(path: &Path) -> Option<ArtifactKind> {
    let data = read_artifact(path, 1 << 20).ok()?;
    detect_by_content(&data[..data.len().min(4096)])
}

/// One step of a path being resolved inside an evidence root.
enum Step {
    Name(std::ffi::OsString),
    Parent,
}

/// Pushes the components of `path` onto `pending` so that they pop in order.
fn push_steps(pending: &mut Vec<Step>, path: &Path) {
    let steps: Vec<Step> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(Step::Name(n.to_os_string())),
            Component::ParentDir => Some(Step::Parent),
            // Root, prefix and `.` carry no movement once re-rooted.
            _ => None,
        })
        .collect();
    pending.extend(steps.into_iter().rev());
}

/// Resolves `rel` inside `root` the way the suspect host's kernel would, but
/// with `root` as `/`: **every** component is checked, and a symlink at any
/// position (`etc -> /etc`, `usr -> /usr`, `etc/localtime ->
/// /usr/share/zoneinfo/...`) is expanded with absolute targets re-rooted under
/// `root` and `..` clamped at `root`. A mounted image therefore never resolves
/// to the analysis host's own files. Returns `None` on a missing component or
/// after 8 symlinks (loops).
pub fn resolve_in_root(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut pending = Vec::new();
    push_steps(&mut pending, Path::new(rel));
    // Invariant: `resolved` names a path under `root` none of whose
    // components is a symlink, so `..` can be applied lexically.
    let mut resolved = PathBuf::new();
    let mut hops = 0;
    while let Some(step) = pending.pop() {
        let name = match step {
            Step::Parent => {
                resolved.pop();
                continue;
            }
            Step::Name(n) => n,
        };
        let candidate = resolved.join(&name);
        let full = root.join(&candidate);
        let meta = fs::symlink_metadata(&full).ok()?;
        if !meta.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        hops += 1;
        if hops > MAX_LINK_HOPS {
            return None;
        }
        let target = fs::read_link(&full).ok()?;
        if target.has_root() {
            resolved = PathBuf::new();
        }
        push_steps(&mut pending, &target);
    }
    Some(root.join(resolved))
}

/// Reads a small text file at `rel` inside `root` (see [`resolve_in_root`]).
fn read_in_root(root: &Path, rel: &str) -> Option<String> {
    fs::read_to_string(resolve_in_root(root, rel)?).ok()
}

/// Context recovered from an evidence root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceContext {
    /// Time zone, with a description of where it came from.
    pub timezone: Option<(TimeZone, String)>,
    /// Host name from `etc/hostname`.
    pub hostname: Option<String>,
}

/// Reads `etc/localtime` (TZif), `etc/timezone` (IANA name) and `etc/hostname`.
pub fn evidence_context(root: &Path, zoneinfo_dir: &Path) -> EvidenceContext {
    let mut ctx = EvidenceContext::default();
    if let Some(p) = resolve_in_root(root, "etc/localtime")
        && let Ok(bytes) = fs::read(&p)
    {
        let label = read_in_root(root, "etc/timezone")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "etc/localtime".into());
        match TimeZone::from_tzif(&bytes, &label) {
            Ok(tz) => ctx.timezone = Some((tz, "evidence etc/localtime".into())),
            Err(e) => debug!(error = %e, "evidence etc/localtime is not valid TZif"),
        }
    }
    if ctx.timezone.is_none()
        && let Some(name) = read_in_root(root, "etc/timezone")
        && let Ok(tz) = TimeZone::parse(name.trim(), zoneinfo_dir)
    {
        ctx.timezone = Some((tz, "evidence etc/timezone + host zoneinfo".into()));
    }
    ctx.hostname = read_in_root(root, "etc/hostname")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 253);
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rotation_suffixes() {
        assert_eq!(base_name("auth.log.2.gz"), "auth.log");
        assert_eq!(base_name("secure-20240101"), "secure");
        assert_eq!(base_name("syslog.1"), "syslog");
        assert_eq!(base_name("fish_history"), "fish_history");
        assert_eq!(base_name("a.tar"), "a.tar");
    }

    #[test]
    fn path_detection() {
        let cases = [
            ("var/log/auth.log.1", Some(ArtifactKind::AuthLog)),
            ("var/log/secure-20240101", Some(ArtifactKind::AuthLog)),
            ("var/log/messages", Some(ArtifactKind::Syslog)),
            ("var/log/cron.log", Some(ArtifactKind::CronLog)),
            ("var/log/apt/history.log", Some(ArtifactKind::AptHistory)),
            ("var/log/other/history.log", None),
            ("home/a/.zsh_history", Some(ArtifactKind::ZshHistory)),
            ("x/fls.body", Some(ArtifactKind::Bodyfile)),
            ("j/system.export", Some(ArtifactKind::JournalExport)),
            ("run/utmp", Some(ArtifactKind::Utmp)),
            ("var/log/btmp.1", Some(ArtifactKind::Btmp)),
            ("readme.md", None),
        ];
        for (p, k) in cases {
            assert_eq!(detect_by_path(p), k, "{p}");
        }
    }

    #[test]
    fn content_detection() {
        assert_eq!(
            detect_by_content(b"__CURSOR=s\nMESSAGE=x\n"),
            Some(ArtifactKind::JournalExport)
        );
        assert_eq!(
            detect_by_content(b"# c\n0|/a|1|r|0|0|0|1|2|3|4\n"),
            Some(ArtifactKind::Bodyfile)
        );
        assert_eq!(
            detect_by_content(b"Mar  1 12:00:00 h app: m\n"),
            Some(ArtifactKind::Syslog)
        );
        assert_eq!(detect_by_content(b"hello\n"), None);
        assert_eq!(detect_by_content(b""), None);
    }

    #[test]
    fn input_specs() {
        let s = InputSpec::parse("bodyfile=/x/y.txt");
        assert_eq!(s.kind, Some(ArtifactKind::Bodyfile));
        let s = InputSpec::parse("weird=name");
        assert_eq!(s.kind, None);
        assert_eq!(s.path, PathBuf::from("weird=name"));
    }

    #[test]
    fn gzip_and_bomb_guard() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("auth.log.2.gz");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&vec![b'a'; 10_000]).unwrap();
        fs::write(&p, enc.finish().unwrap()).unwrap();
        assert_eq!(read_artifact(&p, 1 << 20).unwrap().len(), 10_000);
        assert!(read_artifact(&p, 100).is_err());
        assert!(read_artifact(&dir.path().join("missing"), 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn discovery_symlinks_and_context() {
        use crate::time::tzif::{LocalType, write_tzif_v2};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("var/log")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("usr/share/zoneinfo/America")).unwrap();
        fs::write(
            root.join("var/log/auth.log"),
            "Mar  1 12:00:00 h sshd[1]: x\n",
        )
        .unwrap();
        fs::write(root.join("var/log/mystery"), "Mar  1 12:00:00 h app: x\n").unwrap();
        fs::write(root.join("var/log/notes.txt"), "nothing\n").unwrap();
        fs::write(root.join("etc/hostname"), "web01\n").unwrap();
        fs::write(root.join("etc/timezone"), "America/New_York\n").unwrap();
        let types = [LocalType {
            utoff: -18000,
            is_dst: false,
            abbr: "EST".into(),
        }];
        fs::write(
            root.join("usr/share/zoneinfo/America/New_York"),
            write_tzif_v2(&[], &types, Some("EST5EDT,M3.2.0,M11.1.0")),
        )
        .unwrap();
        // Absolute symlink, as in a real image: must be re-rooted.
        std::os::unix::fs::symlink(
            "/usr/share/zoneinfo/America/New_York",
            root.join("etc/localtime"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            root.join("var/log/auth.log"),
            root.join("var/log/linked.log"),
        )
        .unwrap();
        let files = discover(&[InputSpec::parse(root.to_str().unwrap())]).unwrap();
        let names: Vec<_> = files.iter().map(|f| (f.display.as_str(), f.kind)).collect();
        assert_eq!(
            names,
            vec![
                ("var/log/auth.log", ArtifactKind::AuthLog),
                ("var/log/mystery", ArtifactKind::Syslog)
            ]
        );
        let ctx = evidence_context(root, Path::new("/nonexistent"));
        let (tz, src) = ctx.timezone.unwrap();
        assert_eq!(tz.label(), "America/New_York");
        assert_eq!(src, "evidence etc/localtime");
        assert_eq!(ctx.hostname.as_deref(), Some("web01"));

        // Single-file inputs: detection failure is an error; KIND= forces it.
        let notes = root.join("var/log/notes.txt");
        assert!(discover(&[InputSpec::parse(notes.to_str().unwrap())]).is_err());
        let forced = discover(&[InputSpec::parse(&format!("syslog={}", notes.display()))]).unwrap();
        assert_eq!(forced[0].kind, ArtifactKind::Syslog);
        assert!(discover(&[InputSpec::parse("/definitely/missing")]).is_err());

        // A symlink loop resolves to nothing.
        std::os::unix::fs::symlink("loop2", root.join("loop1")).unwrap();
        std::os::unix::fs::symlink("loop1", root.join("loop2")).unwrap();
        assert_eq!(resolve_in_root(root, "loop1"), None);
    }

    /// Intermediate components are re-rooted too: `usr -> /usr` or `etc -> /etc`
    /// in the evidence must never reach the analysis host's own files.
    #[cfg(unix)]
    #[test]
    fn intermediate_symlinks_stay_inside_the_root() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // `usr -> /usr` plus `etc/localtime -> /usr/share/zoneinfo/Asia/Tokyo`:
        // the host has that file, the evidence does not.
        fs::create_dir_all(root.join("etc")).unwrap();
        symlink("/usr", root.join("usr")).unwrap();
        symlink("/usr/share/zoneinfo/Asia/Tokyo", root.join("etc/localtime")).unwrap();
        assert_eq!(resolve_in_root(root, "etc/localtime"), None);
        let ctx = evidence_context(root, Path::new("/nonexistent"));
        assert_eq!(ctx.timezone, None);

        // `etc -> /etc`: etc/hosts, etc/timezone, etc/hostname must not be
        // read from the host's /etc (the link re-roots onto itself: a loop).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        symlink("/etc", root.join("etc")).unwrap();
        assert_eq!(resolve_in_root(root, "etc/hosts"), None);
        assert_eq!(resolve_in_root(root, "etc/hostname"), None);
        assert_eq!(
            evidence_context(root, Path::new("/nonexistent")),
            EvidenceContext::default()
        );

        // Links that stay inside the evidence still resolve, through any
        // component, with `..` clamped at the root.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("real/share/zoneinfo/America")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("real/share/zoneinfo/America/New_York"), "tz").unwrap();
        fs::write(root.join("real/hostname"), "web02\n").unwrap();
        symlink("real", root.join("usr")).unwrap();
        symlink("/usr/share", root.join("share")).unwrap();
        symlink(
            "../../../../share/zoneinfo/./America/New_York",
            root.join("etc/localtime"),
        )
        .unwrap();
        symlink("/usr/hostname", root.join("etc/hostname")).unwrap();
        assert_eq!(
            resolve_in_root(root, "etc/localtime"),
            Some(root.join("real/share/zoneinfo/America/New_York"))
        );
        assert_eq!(
            evidence_context(root, Path::new("/nonexistent"))
                .hostname
                .as_deref(),
            Some("web02")
        );
        assert_eq!(resolve_in_root(root, "etc/missing"), None);
    }

    #[test]
    fn context_without_localtime_uses_timezone_name() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("etc/timezone"), "UTC\n").unwrap();
        let ctx = evidence_context(dir.path(), Path::new("/nonexistent"));
        assert_eq!(ctx.timezone.unwrap().0.label(), "UTC");
        assert!(ctx.hostname.is_none());
    }
}
