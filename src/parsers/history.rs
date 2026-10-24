//! Shell histories with timestamps.
//!
//! * **bash** with `HISTTIMEFORMAT`: a `#<epoch>` comment line precedes each
//!   entry; all lines up to the next timestamp belong to that entry
//!   (multi-line commands). Lines before the first timestamp carry no time
//!   and are counted as warnings, not events.
//! * **zsh** `EXTENDED_HISTORY`: `: <epoch>:<duration>;<command>`, with a
//!   trailing backslash continuing the command on the next line. zsh
//!   "metafies" bytes ≥ 0x83 (`0x83, byte ^ 0x20`); this is undone.
//! * **fish**: `- cmd: <cmd>` followed by `  when: <epoch>`, with `\\` and
//!   `\n` escapes in the command.

use super::{ParseContext, ParseOutput, epoch_to_utc, lines, user_from_path};
use crate::event::{Event, EventKind, SourceKind};

fn user_for(ctx: &ParseContext) -> Option<String> {
    ctx.user.clone().or_else(|| user_from_path(&ctx.artifact))
}

fn command_event(
    ctx: &ParseContext,
    epoch: i64,
    line_no: u64,
    command: &str,
    shell: &str,
) -> Option<Event> {
    let ts = epoch_to_utc(epoch, 0)?;
    let user = user_for(ctx);
    let who = user.as_deref().unwrap_or("?");
    Some(
        Event::new(
            ts,
            SourceKind::ShellHistory,
            EventKind::ShellCommand,
            &ctx.artifact,
            line_no,
            format!("{shell} command by {who}: {command}"),
        )
        .with_user(user)
        .with_host(ctx.host.clone())
        .with_field("command", command)
        .with_field("shell", shell)
        .with_raw(command),
    )
}

fn parse_epoch_comment(line: &str) -> Option<i64> {
    let digits = line.strip_prefix('#')?;
    if digits.is_empty() || digits.len() > 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Parses a bash history file.
pub fn parse_bash(data: &[u8], ctx: &ParseContext) -> ParseOutput {
    let mut out = ParseOutput::default();
    let mut current: Option<(i64, u64, Vec<String>)> = None;
    let flush = |cur: Option<(i64, u64, Vec<String>)>, out: &mut ParseOutput| {
        if let Some((epoch, line_no, cmd)) = cur {
            if cmd.is_empty() {
                return;
            }
            let command = cmd.join("\n");
            match command_event(ctx, epoch, line_no, &command, "bash") {
                Some(e) => out.events.push(e),
                None => out.warn(ctx, line_no, format!("implausible timestamp {epoch}")),
            }
        }
    };
    let mut untimed = 0u64;
    for (line_no, line) in lines(data) {
        out.records += 1;
        if let Some(epoch) = parse_epoch_comment(&line) {
            flush(current.take(), &mut out);
            current = Some((epoch, line_no + 1, Vec::new()));
        } else if let Some((_, _, cmd)) = current.as_mut() {
            cmd.push(line.into_owned());
        } else if !line.trim().is_empty() {
            untimed += 1;
        }
    }
    flush(current, &mut out);
    if untimed > 0 {
        out.warn(
            ctx,
            0,
            format!(
                "{untimed} history line(s) without a timestamp (HISTTIMEFORMAT unset when written)"
            ),
        );
    }
    out
}

/// Reverses zsh's metafication (`0x83` followed by `byte ^ 0x20`).
pub fn unmetafy(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut it = bytes.iter();
    while let Some(&b) = it.next() {
        if b == 0x83 {
            if let Some(&n) = it.next() {
                out.push(n ^ 0x20);
            }
        } else {
            out.push(b);
        }
    }
    out
}

/// Parses a zsh extended history file.
pub fn parse_zsh(data: &[u8], ctx: &ParseContext) -> ParseOutput {
    let mut out = ParseOutput::default();
    let text = unmetafy(data);
    let mut pending: Option<(i64, u64, String)> = None;
    for (line_no, line) in lines(&text) {
        out.records += 1;
        if let Some((epoch, start, mut cmd)) = pending.take() {
            cmd.push('\n');
            if let Some(stripped) = line.strip_suffix('\\') {
                cmd.push_str(stripped);
                pending = Some((epoch, start, cmd));
            } else {
                cmd.push_str(&line);
                emit_zsh(ctx, &mut out, epoch, start, &cmd);
            }
            continue;
        }
        let Some(rest) = line.strip_prefix(": ") else {
            if !line.trim().is_empty() {
                out.warn(ctx, line_no, "line is not in zsh extended-history format");
            }
            continue;
        };
        let Some((meta, cmd)) = rest.split_once(';') else {
            out.warn(ctx, line_no, "missing ';' in zsh history entry");
            continue;
        };
        let epoch = meta
            .split(':')
            .next()
            .and_then(|s| s.trim().parse::<i64>().ok());
        let Some(epoch) = epoch else {
            out.warn(ctx, line_no, "invalid zsh timestamp");
            continue;
        };
        if let Some(stripped) = cmd.strip_suffix('\\') {
            pending = Some((epoch, line_no, stripped.to_string()));
        } else {
            emit_zsh(ctx, &mut out, epoch, line_no, cmd);
        }
    }
    if let Some((epoch, start, cmd)) = pending {
        emit_zsh(ctx, &mut out, epoch, start, &cmd);
    }
    out
}

fn emit_zsh(ctx: &ParseContext, out: &mut ParseOutput, epoch: i64, line_no: u64, cmd: &str) {
    match command_event(ctx, epoch, line_no, cmd, "zsh") {
        Some(e) => out.events.push(e),
        None => out.warn(ctx, line_no, format!("implausible timestamp {epoch}")),
    }
}

fn fish_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(o) => {
                    out.push('\\');
                    out.push(o);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses a fish history file.
pub fn parse_fish(data: &[u8], ctx: &ParseContext) -> ParseOutput {
    let mut out = ParseOutput::default();
    let mut cmd: Option<(u64, String)> = None;
    for (line_no, line) in lines(data) {
        out.records += 1;
        if let Some(c) = line.strip_prefix("- cmd: ") {
            if let Some((l, _)) = cmd.replace((line_no, fish_unescape(c))) {
                out.warn(ctx, l, "fish entry without `when:`");
            }
        } else if let Some(w) = line.trim_start().strip_prefix("when: ") {
            let Some((start, c)) = cmd.take() else {
                out.warn(ctx, line_no, "`when:` without a preceding `- cmd:`");
                continue;
            };
            match w.trim().parse::<i64>() {
                Ok(epoch) => match command_event(ctx, epoch, start, &c, "fish") {
                    Some(e) => out.events.push(e),
                    None => out.warn(ctx, line_no, format!("implausible timestamp {epoch}")),
                },
                Err(_) => out.warn(ctx, line_no, "invalid fish timestamp"),
            }
        }
    }
    if let Some((l, _)) = cmd {
        out.warn(ctx, l, "fish entry without `when:`");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_util::ctx;

    #[test]
    fn bash_entries_multiline_and_untimed() {
        let data =
            b"ls\n#1735704485\nid\n#1735704500\nfor i in 1 2; do\n  echo $i\ndone\n#1735704600\n";
        let out = parse_bash(data, &ctx("home/deploy/.bash_history"));
        assert_eq!(
            out.events.len(),
            2,
            "trailing timestamp without command is dropped"
        );
        let e = &out.events[0];
        assert_eq!(e.ts.timestamp(), 1_735_704_485);
        assert_eq!(e.user.as_deref(), Some("deploy"));
        assert_eq!(e.get("command"), Some("id"));
        assert_eq!(e.location, 3);
        assert_eq!(
            out.events[1].get("command"),
            Some("for i in 1 2; do\n  echo $i\ndone")
        );
        assert_eq!(out.warning_count, 1); // untimed "ls"
        assert!(out.warnings[0].message.contains("1 history line"));
        assert_eq!(parse_epoch_comment("#99999999999999"), None);
        assert_eq!(parse_epoch_comment("#12a"), None);
    }

    #[test]
    fn bash_implausible_epoch() {
        let out = parse_bash(b"#99999999999\nls\n", &ctx("root/.bash_history"));
        assert!(out.events.is_empty());
        assert_eq!(out.warning_count, 1);
    }

    #[test]
    fn zsh_entries() {
        let mut data = b": 1735704485:0;echo one\n: 1735704490:3;echo two \\\nthree\nnoise\n: x:0;bad\n: 1735704495:0 nosemicolon\n".to_vec();
        data.extend_from_slice(b": 1735704499:0;caf\xc3\x83\x82\n: 1735704500:0;trailing \\\n");
        let out = parse_zsh(&data, &ctx("home/alice/.zsh_history"));
        let cmds: Vec<_> = out
            .events
            .iter()
            .map(|e| e.get("command").unwrap().to_string())
            .collect();
        assert_eq!(cmds[0], "echo one");
        assert_eq!(cmds[1], "echo two \nthree");
        assert_eq!(cmds[2], "caf\u{e2}");
        assert_eq!(cmds[3], "trailing ");
        assert_eq!(out.warning_count, 3);
        assert_eq!(unmetafy(&[0x83]), Vec::<u8>::new());
    }

    #[test]
    fn fish_entries() {
        let data = b"- cmd: echo a\\nb \\\\ \\x\n  when: 1735704485\n  paths:\n    - /tmp\n- cmd: orphan\n- cmd: bad\n  when: zz\n  when: 5\n- cmd: last\n";
        let out = parse_fish(data, &ctx("home/sysbackup/.local/share/fish/fish_history"));
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].get("command"), Some("echo a\nb \\ \\x"));
        assert_eq!(out.events[0].user.as_deref(), Some("sysbackup"));
        assert_eq!(out.warning_count, 4);
        assert_eq!(fish_unescape("end\\"), "end\\");
    }
}
