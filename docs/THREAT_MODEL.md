# Threat model

timeliner is a **defensive, offline** analysis tool. It reads copies of
evidence from a possibly compromised Linux host and produces reports that an
analyst opens on their own workstation. It never contacts the host, never
executes anything from the evidence, and has no network code.

## Assets

- The analyst's workstation (shell, spreadsheet application, browser).
- The integrity of the timeline: correct order, correct attribution, nothing silently dropped.

## Adversary

An attacker who controlled the suspect host and can therefore write
**arbitrary bytes into any artifact**:

- forged log lines
- crafted usernames such as `<script>`, `=HYPERLINK(...)` or ANSI escapes
- malformed binary records
- huge or compressed files
- symlinks inside the evidence tree
- timestomped file-system times

## Threats and mitigations

| threat | mitigation | where |
|---|---|---|
| Parser crash or hang on malformed input (DoS of the investigation) | No `unsafe`. Bounds-checked parsing; every length/count is validated against the remaining input before allocation (TZif, journal binary fields ≤ 16 MiB, utmp fixed records). Per-line errors become warnings. Property tests feed arbitrary and mutated bytes to every parser. | `parsers/*`, `time/tzif.rs`, `tests/prop_parsers.rs` |
| Decompression bomb in `*.gz` | `MultiGzDecoder` output capped (1 GiB default), error instead of OOM | `discover::read_artifact` |
| Stored XSS in the HTML report via log content | Server-rendered text is HTML-escaped. Event data is embedded as JSON with `< > &` U+2028/2029 escaped, inside `type="application/json"`. Rows are rendered with `textContent` only. A CSP allows only the hashed inline CSS/JS, with `default-src 'none'` and no network. Tested with `<script>` / `</script><img onerror>` payloads. | `output/html.rs` |
| CSV / formula injection when the analyst opens CSV/l2tcsv in a spreadsheet | Attacker-influenced cells starting with `= + - @ TAB CR` get a `'` prefix (default on) | `output/csv.rs` |
| Terminal escape injection via `-f text` or `--summary` | Control characters are escaped in text output | `output::terminal_safe` |
| Evidence symlinks pointing outside the evidence (e.g. `etc/localtime → /usr/share/zoneinfo/...`, `usr → /usr`, `etc → /etc`, or `→ /etc/shadow` of the analyst) | The directory walk does not follow symlinks. `etc/localtime`, `etc/timezone` and `etc/hostname` are resolved *inside* the evidence root component by component: a symlink at **any** position (final or intermediate directory) is expanded with absolute targets re-rooted under the evidence root and `..` clamped at it, 8-hop limit. A link that cannot be resolved inside the evidence yields nothing (UTC/"unverified" fallback), never the analyst's file. Tested with `usr → /usr` and `etc → /etc` | `discover::walk`, `discover::resolve_in_root` |
| Path traversal through `--tz ../../x` | IANA names must consist of normal path components only | `TimeZone::parse` |
| Timestomped file times skewing year inference | The bodyfile is excluded from the year anchor. Anchoring uses wtmp/journal/history/package logs only | `ArtifactKind::anchors_years` |
| Forged log lines (fake events) | Out of scope to *prevent*. Mitigated by provenance: every event carries artifact + line/record, the original line (`raw`), and every corroborating copy (`also_seen`). Corroboration across artifacts is visible | `Event` |
| Deleted or tampered logs hiding activity | Out of scope to recover. Rules flag tampering commands (`history-tampering`, `log-tampering`), and gaps can be cross-checked against wtmp/journal | `rules/default.yml` |

## Non-goals

- Live response, remote collection, or acquisition (use a write blocker and
  imaging tools; feed timeliner the copies).
- Malware analysis. No sample is shipped, executed or emulated. The fixture's
  `/tmp/.x.sh` exists only as a bodyfile line.
- Anti-forensics detection beyond the simple command-pattern rules.

## Ethics

The fixture story is fully synthetic and uses documentation IP ranges. The
project contains no offensive capability: no exploitation, no credential
access, no evasion or persistence code. It only reads files the analyst
already holds.
