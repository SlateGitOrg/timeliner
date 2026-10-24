//! Debian package-manager logs: `/var/log/dpkg.log` and
//! `/var/log/apt/history.log`. Both record *local* time with a year.

use chrono::NaiveDateTime;

use super::{ParseContext, ParseOutput, lines};
use crate::event::{Event, EventKind, SourceKind, TimeFlags};

fn local_to_utc(
    ctx: &ParseContext,
    local: NaiveDateTime,
) -> (chrono::DateTime<chrono::Utc>, TimeFlags) {
    let c = ctx.tz.local_to_utc(local);
    (
        c.utc,
        TimeFlags {
            local_time: true,
            tz_ambiguous: c.ambiguous,
            tz_gap: c.gap,
            ..TimeFlags::default()
        },
    )
}

/// Parses dpkg.log. Only package state changes (`install`, `upgrade`,
/// `remove`, `purge`) become events; `status`, `configure`, `trigproc`,
/// `startup` and `conffile` lines are counted but not emitted.
pub fn parse_dpkg(data: &[u8], ctx: &ParseContext) -> ParseOutput {
    let mut out = ParseOutput::default();
    for (line_no, line) in lines(data) {
        out.records += 1;
        if line.trim().is_empty() {
            continue;
        }
        let Some(stamp) = line.get(..19) else {
            out.warn(ctx, line_no, "line too short for a dpkg timestamp");
            continue;
        };
        let Ok(local) = NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S") else {
            out.warn(ctx, line_no, "invalid dpkg timestamp");
            continue;
        };
        let mut words = line[19..].split_whitespace();
        let action = words.next().unwrap_or_default();
        let kind = match action {
            "install" => EventKind::PackageInstall,
            "upgrade" => EventKind::PackageUpgrade,
            "remove" | "purge" => EventKind::PackageRemove,
            "status" | "configure" | "trigproc" | "startup" | "conffile" => continue,
            _ => {
                out.warn(ctx, line_no, format!("unknown dpkg action `{action}`"));
                continue;
            }
        };
        let (Some(pkg), Some(old), Some(new)) = (words.next(), words.next(), words.next()) else {
            out.warn(ctx, line_no, format!("truncated dpkg `{action}` line"));
            continue;
        };
        let (name, arch) = pkg.split_once(':').unwrap_or((pkg, ""));
        let (ts, flags) = local_to_utc(ctx, local);
        let version = if new == "<none>" { old } else { new };
        let ev = Event::new(
            ts,
            SourceKind::Dpkg,
            kind,
            &ctx.artifact,
            line_no,
            format!("dpkg {action} {pkg} {version}"),
        )
        .with_host(ctx.host.clone())
        .with_field("action", action)
        .with_field("package", name)
        .with_field("arch", arch)
        .with_field("version", version)
        .with_field("old_version", if old == "<none>" { "" } else { old })
        .with_raw(&line)
        .with_time_flags(flags);
        out.events.push(ev);
    }
    out
}

/// Splits an apt package list such as
/// `a:amd64 (1.0), b:amd64 (2.0, automatic)` into package names.
pub fn apt_package_names(list: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in list.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                names.push(std::mem::take(&mut current));
                continue;
            }
            _ if depth == 0 => current.push(c),
            _ => {}
        }
    }
    names.push(current);
    names
        .into_iter()
        .map(|n| n.trim().split(':').next().unwrap_or_default().to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

#[derive(Default)]
struct AptBlock {
    line_no: u64,
    start: Option<NaiveDateTime>,
    pairs: Vec<(String, String)>,
    raw: String,
}

/// Parses apt's history.log; each `Start-Date` block becomes one
/// [`EventKind::PackageTransaction`] event.
pub fn parse_apt_history(data: &[u8], ctx: &ParseContext) -> ParseOutput {
    let mut out = ParseOutput::default();
    let mut block = AptBlock::default();
    for (line_no, line) in lines(data) {
        out.records += 1;
        if line.trim().is_empty() {
            flush_apt(&mut out, ctx, std::mem::take(&mut block));
            continue;
        }
        let Some((key, value)) = line.split_once(": ") else {
            out.warn(ctx, line_no, "expected `Key: value`");
            continue;
        };
        if key == "Start-Date" {
            flush_apt(&mut out, ctx, std::mem::take(&mut block));
            block.line_no = line_no;
            let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
            match NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S") {
                Ok(t) => block.start = Some(t),
                Err(_) => out.warn(ctx, line_no, "invalid Start-Date"),
            }
        }
        if !block.raw.is_empty() {
            block.raw.push('\n');
        }
        block.raw.push_str(&line);
        block.pairs.push((key.to_string(), value.to_string()));
    }
    flush_apt(&mut out, ctx, block);
    out
}

fn flush_apt(out: &mut ParseOutput, ctx: &ParseContext, block: AptBlock) {
    if block.pairs.is_empty() {
        return;
    }
    let Some(start) = block.start else {
        out.warn(ctx, block.line_no, "apt block without a valid Start-Date");
        return;
    };
    let get = |k: &str| {
        block
            .pairs
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };
    let commandline = get("Commandline").unwrap_or("(unknown command)");
    let user =
        get("Requested-By").map(|r| r.split_whitespace().next().unwrap_or_default().to_string());
    let mut summary = Vec::new();
    let (ts, flags) = local_to_utc(ctx, start);
    let mut ev = Event::new(
        ts,
        SourceKind::AptHistory,
        EventKind::PackageTransaction,
        &ctx.artifact,
        block.line_no,
        String::new(),
    )
    .with_host(ctx.host.clone())
    .with_user(user)
    .with_field("commandline", commandline)
    .with_raw(&block.raw)
    .with_time_flags(flags);
    for key in [
        "Install",
        "Upgrade",
        "Downgrade",
        "Reinstall",
        "Remove",
        "Purge",
    ] {
        if let Some(list) = get(key) {
            let names = apt_package_names(list).join(", ");
            summary.push(format!("{}: {names}", key.to_ascii_lowercase()));
            ev = ev.with_field(&key.to_ascii_lowercase(), names);
        }
    }
    if let Some(err) = get("Error") {
        ev = ev.with_field("error", err);
    }
    ev.description = if summary.is_empty() {
        format!("apt: {commandline}")
    } else {
        format!("apt: {commandline} ({})", summary.join("; "))
    };
    out.events.push(ev);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_util::ctx;
    use crate::time::TimeZone;
    use chrono::{TimeZone as _, Utc};

    #[test]
    fn dpkg_actions() {
        let data = b"2024-12-31 23:11:33 startup archives unpack\n\
2024-12-31 23:11:33 install netcat-openbsd:amd64 <none> 1.226-1ubuntu2\n\
2024-12-31 23:11:33 status half-installed netcat-openbsd:amd64 1.226-1ubuntu2\n\
2024-12-29 10:15:02 upgrade openssl:amd64 3.0.13-0ubuntu3.3 3.0.13-0ubuntu3.4\n\
2024-12-29 10:15:09 remove telnet:amd64 0.17-44 <none>\n\
2024-12-29 10:15:09 frobnicate x\n\
2024-12-29 10:15:09 install x\n\
garbage\n\
2024-13-29 10:15:09 install a b c\n";
        let mut c = ctx("var/log/dpkg.log");
        c.tz = TimeZone::fixed(-5 * 3600).unwrap();
        let out = parse_dpkg(data, &c);
        assert_eq!(out.events.len(), 3);
        assert_eq!(out.warning_count, 4);
        let e = &out.events[0];
        assert_eq!(e.kind, EventKind::PackageInstall);
        assert_eq!(e.ts, Utc.with_ymd_and_hms(2025, 1, 1, 4, 11, 33).unwrap());
        assert_eq!(e.get("package"), Some("netcat-openbsd"));
        assert_eq!(e.get("arch"), Some("amd64"));
        assert_eq!(e.get("old_version"), None);
        assert!(e.time_flags.local_time);
        assert_eq!(out.events[1].kind, EventKind::PackageUpgrade);
        assert_eq!(out.events[2].get("version"), Some("0.17-44"));
    }

    #[test]
    fn apt_blocks() {
        let data = b"\nStart-Date: 2024-12-31  23:11:31\n\
Commandline: apt-get install -y netcat-openbsd\n\
Install: netcat-openbsd:amd64 (1.226-1ubuntu2), libbsd0:amd64 (0.12.1-1, automatic)\n\
End-Date: 2024-12-31  23:11:34\n\
\n\
Start-Date: 2024-12-29  10:15:00\n\
Commandline: apt upgrade\n\
Requested-By: alice (1000)\n\
Upgrade: openssl:amd64 (3.0.13-0ubuntu3.3, 3.0.13-0ubuntu3.4)\n\
Error: Sub-process returned an error code\n\
bogus line\n\
\n\
Start-Date: not a date\n\
Commandline: x\n\
\n\
Commandline: orphan\n";
        let out = parse_apt_history(data, &ctx("var/log/apt/history.log"));
        assert_eq!(out.events.len(), 2);
        let e = &out.events[0];
        assert_eq!(e.kind, EventKind::PackageTransaction);
        assert_eq!(e.get("install"), Some("netcat-openbsd, libbsd0"));
        assert_eq!(e.user, None);
        assert_eq!(
            e.description,
            "apt: apt-get install -y netcat-openbsd (install: netcat-openbsd, libbsd0)"
        );
        let e = &out.events[1];
        assert_eq!(e.user.as_deref(), Some("alice"));
        assert_eq!(e.get("upgrade"), Some("openssl"));
        assert!(e.get("error").is_some());
        assert_eq!(out.warning_count, 4);
    }

    #[test]
    fn package_name_lists() {
        assert_eq!(apt_package_names("a:amd64 (1, x), b (2)"), vec!["a", "b"]);
        assert!(apt_package_names("").is_empty());
    }
}
