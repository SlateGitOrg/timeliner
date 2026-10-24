//! systemd journal *export format* (`journalctl -o export`), documented at
//! <https://systemd.io/JOURNAL_EXPORT_FORMATS/>.
//!
//! Entries are separated by an empty line. A field is either `NAME=value\n`
//! or, for values containing newlines / binary data, `NAME\n` followed by a
//! little-endian u64 length, the raw bytes and `\n`. Messages are classified
//! with the same semantics as syslog lines, so an sshd login seen in both
//! `auth.log` and the journal normalizes to the same event and deduplicates.

use std::collections::HashMap;

use super::semantics;
use super::{ParseContext, ParseOutput, epoch_to_utc};
use crate::event::{Event, SourceKind};

/// Maximum accepted binary field size (larger values indicate corruption).
pub const MAX_FIELD: u64 = 16 * 1024 * 1024;

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// Parses a journal export stream.
pub fn parse(data: &[u8], ctx: &ParseContext) -> ParseOutput {
    let mut out = ParseOutput::default();
    let mut fields: HashMap<String, Vec<u8>> = HashMap::new();
    let mut entry_no: u64 = 1;
    let mut pos = 0usize;
    while pos < data.len() {
        let rest = &data[pos..];
        let nl = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
        let line = &rest[..nl];
        if line.is_empty() {
            pos += 1;
            if !fields.is_empty() {
                emit(&mut out, ctx, &fields, entry_no);
                fields.clear();
                entry_no += 1;
            }
            continue;
        }
        if let Some(eq) = line.iter().position(|&c| c == b'=') {
            let name = &line[..eq];
            if valid_name(name) {
                fields
                    .entry(String::from_utf8_lossy(name).into_owned())
                    .or_insert_with(|| line[eq + 1..].to_vec());
            } else {
                out.warn(ctx, entry_no, "invalid field name");
            }
            pos += nl + 1;
            continue;
        }
        // Binary field: NAME\n <u64 le len> <bytes> \n
        if !valid_name(line) {
            out.warn(ctx, entry_no, "invalid field name");
            pos += nl + 1;
            continue;
        }
        let len_start = pos + nl + 1;
        let Some(len_bytes) = data.get(len_start..len_start + 8) else {
            out.warn(ctx, entry_no, "truncated binary field length");
            break;
        };
        let len = u64::from_le_bytes(len_bytes.try_into().unwrap_or([0; 8]));
        let start = len_start + 8;
        let end = usize::try_from(len)
            .ok()
            .filter(|_| len <= MAX_FIELD)
            .and_then(|l| start.checked_add(l));
        let Some(value) = end.and_then(|e| data.get(start..e)) else {
            out.warn(
                ctx,
                entry_no,
                format!("binary field length {len} exceeds data"),
            );
            break;
        };
        fields
            .entry(String::from_utf8_lossy(line).into_owned())
            .or_insert_with(|| value.to_vec());
        pos = start + value.len();
        if data.get(pos) == Some(&b'\n') {
            pos += 1;
        } else {
            out.warn(ctx, entry_no, "binary field not followed by newline");
        }
    }
    if !fields.is_empty() {
        emit(&mut out, ctx, &fields, entry_no);
    }
    out
}

fn emit(out: &mut ParseOutput, ctx: &ParseContext, f: &HashMap<String, Vec<u8>>, entry_no: u64) {
    out.records += 1;
    let text = |k: &str| f.get(k).map(|v| String::from_utf8_lossy(v).into_owned());
    let micros = text("_SOURCE_REALTIME_TIMESTAMP")
        .or_else(|| text("__REALTIME_TIMESTAMP"))
        .and_then(|s| s.trim().parse::<i64>().ok());
    let Some(micros) = micros else {
        out.warn(ctx, entry_no, "entry without a realtime timestamp");
        return;
    };
    let nanos = (micros.rem_euclid(1_000_000) * 1000) as u32;
    let Some(ts) = epoch_to_utc(micros.div_euclid(1_000_000), nanos) else {
        out.warn(ctx, entry_no, format!("implausible timestamp {micros}"));
        return;
    };
    let program = text("SYSLOG_IDENTIFIER").or_else(|| text("_COMM"));
    let message = text("MESSAGE").unwrap_or_default();
    let c = semantics::classify(program.as_deref(), &message);
    let pid = text("SYSLOG_PID").or_else(|| text("_PID"));
    let raw = match (&program, &pid) {
        (Some(p), Some(id)) => format!("{p}[{id}]: {message}"),
        (Some(p), None) => format!("{p}: {message}"),
        _ => message.clone(),
    };
    let mut ev = Event::new(
        ts,
        SourceKind::Journal,
        c.kind,
        &ctx.artifact,
        entry_no,
        c.description,
    )
    .with_host(text("_HOSTNAME").or_else(|| ctx.host.clone()))
    .with_user(c.user)
    .with_raw(&raw)
    .with_field("program", program.unwrap_or_default())
    .with_field("pid", pid.unwrap_or_default())
    .with_field("unit", text("_SYSTEMD_UNIT").unwrap_or_default())
    .with_field("priority", text("PRIORITY").unwrap_or_default())
    .with_field("boot_id", text("_BOOT_ID").unwrap_or_default())
    .with_field("transport", text("_TRANSPORT").unwrap_or_default())
    .with_field("uid", text("_UID").unwrap_or_default());
    for (k, v) in c.fields {
        ev.fields.insert(k.to_string(), v);
    }
    out.events.push(ev);
}

/// Serializes one entry in export format (used by the fixture generator).
/// Values containing a newline or control bytes use the binary encoding.
pub fn write_entry(out: &mut Vec<u8>, fields: &[(&str, &str)]) {
    for (k, v) in fields {
        if v.bytes().any(|b| b == b'\n' || (b < 0x20 && b != b'\t')) {
            out.extend_from_slice(k.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(&(v.len() as u64).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        } else {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        }
    }
    out.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;
    use crate::parsers::test_util::ctx;

    #[test]
    fn text_and_binary_fields() {
        let mut data = Vec::new();
        write_entry(
            &mut data,
            &[
                ("__REALTIME_TIMESTAMP", "1735704432123456"),
                ("_HOSTNAME", "web01"),
                ("SYSLOG_IDENTIFIER", "sshd"),
                ("_PID", "4242"),
                (
                    "MESSAGE",
                    "Accepted password for deploy from 203.0.113.45 port 50122 ssh2",
                ),
            ],
        );
        write_entry(
            &mut data,
            &[
                ("__REALTIME_TIMESTAMP", "1735704500000000"),
                ("_SOURCE_REALTIME_TIMESTAMP", "1735704499000001"),
                ("_COMM", "bash"),
                ("MESSAGE", "line one\nline two"),
            ],
        );
        let out = parse(&data, &ctx("journal.export"));
        assert_eq!(out.warning_count, 0, "{:?}", out.warnings);
        assert_eq!(out.events.len(), 2);
        let e = &out.events[0];
        assert_eq!(e.kind, EventKind::SshLoginSuccess);
        assert_eq!(e.ts.timestamp_subsec_micros(), 123_456);
        assert_eq!(e.get("pid"), Some("4242"));
        assert_eq!(
            e.raw,
            "sshd[4242]: Accepted password for deploy from 203.0.113.45 port 50122 ssh2"
        );
        let e = &out.events[1];
        assert_eq!(e.ts.timestamp(), 1_735_704_499);
        assert!(e.description.contains("line one\nline two"));
        assert_eq!(e.location, 2);
        assert_eq!(
            e.host.as_deref(),
            Some("web01"),
            "falls back to context host"
        );
    }

    #[test]
    fn malformed_streams() {
        // Missing timestamp, bad names, no trailing blank line.
        let data = b"MESSAGE=no time\n\nbad name=x\nlower\n__REALTIME_TIMESTAMP=1735704432000000\nMESSAGE=ok";
        let out = parse(data, &ctx("j"));
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.warning_count, 3);
        // Binary length beyond the data.
        let mut data = b"MESSAGE\n".to_vec();
        data.extend_from_slice(&1000u64.to_le_bytes());
        data.extend_from_slice(b"short");
        assert_eq!(parse(&data, &ctx("j")).warning_count, 1);
        // Truncated length.
        assert_eq!(parse(b"MESSAGE\n\x01\x02", &ctx("j")).warning_count, 1);
        // Binary value not followed by newline; implausible timestamp.
        let mut data = b"MESSAGE\n".to_vec();
        data.extend_from_slice(&2u64.to_le_bytes());
        data.extend_from_slice(b"hiX__REALTIME_TIMESTAMP=-5\n\n");
        let out = parse(&data, &ctx("j"));
        assert_eq!(out.warning_count, 2);
        assert!(out.events.is_empty());
    }
}
