//! Self-contained static HTML report.
//!
//! One file, no external requests: CSS and JS are inline and pinned by a
//! Content-Security-Policy that allows only their SHA-256 hashes. Event data
//! (attacker-controlled log text) is embedded as JSON inside a
//! `<script type="application/json">` block with `<`, `>`, `&`, U+2028 and
//! U+2029 escaped, and the table is rendered with `textContent` only, so a
//! log line containing `<script>` stays inert. The report contains no
//! generation timestamp, so the same timeline always renders byte-identically.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Write};

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use super::OutputOptions;
use crate::event::{Event, Severity, format_ts};
use crate::pipeline::Timeline;

const STYLE: &str = r#"
:root{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#5f6368;--card:#fff;--line:#e2e2de;--accent:#1f5fbf;
--crit:#8b0000;--high:#c0392b;--medium:#b9770e;--low:#2e7d32;--info:#546e7a;--bar:#9db4d6;--barhit:#c0392b}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8e8e6;--muted:#a0a4a8;--card:#1b1e22;
--line:#2c3036;--accent:#7fb0ff;--bar:#3d5a80;--barhit:#ff6b5b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px}
.sub{color:var(--muted);margin:0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.card b{display:block;font-size:22px}.card span{color:var(--muted);font-size:12px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--card);font-weight:600}
td.ts{white-space:nowrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
td.d{word-break:break-word;min-width:280px}
.sev{display:inline-block;padding:1px 7px;border-radius:10px;color:#fff;font-size:11px;font-weight:600}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}
.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.tag{display:inline-block;margin:1px 3px 1px 0;padding:0 6px;border:1px solid var(--line);border-radius:4px;font-size:11px;color:var(--muted)}
svg{width:100%;height:auto;display:block}.axis{fill:var(--muted);font-size:10px}
.b{fill:var(--bar)}.bh{fill:var(--barhit)}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px}
input[type=search],select{padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);font:inherit}
input[type=search]{flex:1;min-width:200px}
button{padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);cursor:pointer;font:inherit}
button:disabled{opacity:.4;cursor:default}
.note{color:var(--muted);font-size:12px}
footer{margin-top:40px;color:var(--muted);font-size:12px}
@media print{.controls,#pager{display:none}th{position:static}body{background:#fff;color:#000}}
"#;

const SCRIPT: &str = r#"
(function(){
var raw=document.getElementById('tl-data').textContent;var rows=JSON.parse(raw);
var q=document.getElementById('q'),src=document.getElementById('src'),flag=document.getElementById('flag');
var body=document.getElementById('rows'),info=document.getElementById('info');
var prev=document.getElementById('prev'),next=document.getElementById('next');
var PAGE=250,page=0,view=rows;
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
function apply(){var t=q.value.toLowerCase(),s=src.value,f=flag.checked;
view=rows.filter(function(r){if(s&&r[1]!==s)return false;if(f&&!r[7])return false;
if(t){var h=(r[0]+' '+r[2]+' '+r[3]+' '+r[4]+' '+r[5]+' '+r[6]+' '+r[8]).toLowerCase();if(h.indexOf(t)<0)return false;}return true;});
page=0;render();}
function render(){while(body.firstChild)body.removeChild(body.firstChild);
var start=page*PAGE,end=Math.min(view.length,start+PAGE);
for(var i=start;i<end;i++){var r=view[i],tr=el('tr');
tr.appendChild(el('td','ts',r[0]));tr.appendChild(el('td','',r[1]));tr.appendChild(el('td','',r[2]));
tr.appendChild(el('td','',r[3]));var d=el('td','d',r[5]);
if(r[6]){r[6].split(' ').forEach(function(g){d.appendChild(document.createTextNode(' '));d.appendChild(el('span','tag',g));});}
tr.appendChild(d);var sv=el('td');if(r[7]){sv.appendChild(el('span','sev sev-'+r[7],r[7]));}tr.appendChild(sv);
tr.appendChild(el('td','',r[8]));body.appendChild(tr);}
info.textContent=view.length?('Showing '+(start+1)+'-'+end+' of '+view.length+' events'):'No matching events';
prev.disabled=page===0;next.disabled=end>=view.length;}
q.addEventListener('input',apply);src.addEventListener('change',apply);flag.addEventListener('change',apply);
prev.addEventListener('click',function(){if(page>0){page--;render();}});
next.addEventListener('click',function(){if((page+1)*PAGE<view.length){page++;render();}});
apply();})();
"#;

/// Escapes text for HTML element content and attribute values.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Makes JSON safe to embed inside a `<script>` element.
pub fn script_safe_json(json: &str) -> String {
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn csp_hash(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn sev_badge(s: Severity) -> String {
    format!("<span class=\"sev sev-{s}\">{s}</span>")
}

fn short_ts(ts: &DateTime<Utc>) -> String {
    ts.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Picks a histogram bucket width so that the range fits in at most ~120 bars.
fn bucket_width(span: Duration) -> Duration {
    const STEPS: [i64; 10] = [
        60,
        300,
        900,
        1800,
        3600,
        3 * 3600,
        6 * 3600,
        12 * 3600,
        86_400,
        7 * 86_400,
    ];
    let secs = span.num_seconds().max(1);
    for s in STEPS {
        if secs / s <= 120 {
            return Duration::seconds(s);
        }
    }
    Duration::seconds((secs / 120).max(1))
}

fn histogram(events: &[Event]) -> String {
    let (Some(first), Some(last)) = (events.first(), events.last()) else {
        return String::new();
    };
    let width = bucket_width(last.ts - first.ts);
    let w = width.num_seconds();
    let origin = first.ts.timestamp().div_euclid(w) * w;
    let n = ((last.ts.timestamp() - origin) / w + 1) as usize;
    let mut all = vec![0u64; n];
    let mut hit = vec![0u64; n];
    for e in events {
        let i = ((e.ts.timestamp() - origin) / w) as usize;
        all[i] += 1;
        if !e.rule_hits.is_empty() {
            hit[i] += 1;
        }
    }
    let max = all.iter().copied().max().unwrap_or(1).max(1) as f64;
    let (vw, vh, top, bottom) = (1000.0, 180.0, 10.0, 24.0);
    let bw = vw / n as f64;
    let mut svg = format!(
        "<svg viewBox=\"0 0 {vw} {vh}\" role=\"img\" aria-label=\"Events per {} bucket\">",
        human_width(w)
    );
    let plot = vh - top - bottom;
    for i in 0..n {
        let x = i as f64 * bw;
        let h = all[i] as f64 / max * plot;
        let hh = hit[i] as f64 / max * plot;
        let start = DateTime::<Utc>::from_timestamp(origin + i as i64 * w, 0).unwrap_or_default();
        let _ = write!(
            svg,
            "<rect class=\"b\" x=\"{x:.2}\" y=\"{:.2}\" width=\"{:.2}\" height=\"{h:.2}\"><title>{} UTC: {} events, {} flagged</title></rect>",
            top + plot - h,
            (bw - 1.0).max(0.5),
            short_ts(&start),
            all[i],
            hit[i]
        );
        if hit[i] > 0 {
            let _ = write!(
                svg,
                "<rect class=\"bh\" x=\"{x:.2}\" y=\"{:.2}\" width=\"{:.2}\" height=\"{:.2}\"/>",
                top + plot - hh,
                (bw - 1.0).max(0.5),
                hh.max(1.5)
            );
        }
    }
    let labels = 6.min(n);
    for k in 0..labels {
        let i = if labels > 1 {
            k * (n - 1) / (labels - 1)
        } else {
            0
        };
        let start = DateTime::<Utc>::from_timestamp(origin + i as i64 * w, 0).unwrap_or_default();
        let anchor = if k == 0 {
            "start"
        } else if k + 1 == labels {
            "end"
        } else {
            "middle"
        };
        let x = if k + 1 == labels { vw } else { i as f64 * bw };
        let _ = write!(
            svg,
            "<text class=\"axis\" x=\"{x:.1}\" y=\"{}\" text-anchor=\"{anchor}\">{}</text>",
            vh - 6.0,
            start.format("%m-%d %H:%M")
        );
    }
    svg.push_str("</svg>");
    format!(
        "<p class=\"note\">Bucket width: {} (UTC). Red: events with a rule hit.</p>{svg}",
        human_width(w)
    )
}

fn human_width(secs: i64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{} day(s)", s / 86_400),
        s if s % 3600 == 0 => format!("{} hour(s)", s / 3600),
        s if s % 60 == 0 => format!("{} minute(s)", s / 60),
        s => format!("{s} s"),
    }
}

fn row_json(e: &Event) -> serde_json::Value {
    serde_json::json!([
        format_ts(&e.ts),
        e.source.as_str(),
        e.kind.as_str(),
        e.user.clone().unwrap_or_default(),
        e.host.clone().unwrap_or_default(),
        e.description,
        e.tags.join(" "),
        e.max_severity().map(|s| s.as_str()).unwrap_or(""),
        format!("{}:{}", e.artifact, e.location),
    ])
}

/// Writes the HTML report.
pub fn write_html(tl: &Timeline, opts: &OutputOptions, w: &mut dyn Write) -> io::Result<()> {
    let r = &tl.report;
    let flagged: Vec<&Event> = tl
        .events
        .iter()
        .filter(|e| !e.rule_hits.is_empty())
        .collect();
    let mut html = String::with_capacity(64 * 1024 + tl.events.len() * 160);
    let csp = format!(
        "default-src 'none'; style-src {}; script-src {}; img-src data:; base-uri 'none'; form-action 'none'",
        csp_hash(STYLE),
        csp_hash(SCRIPT)
    );
    let _ = write!(
        html,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"{}\">\
<meta name=\"referrer\" content=\"no-referrer\"><title>{}</title><style>{STYLE}</style></head><body><main>",
        esc(&csp),
        esc(&opts.title)
    );
    let range = match (&r.first, &r.last) {
        (Some(a), Some(b)) => format!("{a} → {b}"),
        _ => "no events".into(),
    };
    let _ = write!(
        html,
        "<h1>{}</h1><p class=\"sub\">Host <b>{}</b> · {} · all times UTC</p>\
<p class=\"sub\">Local-time artifacts interpreted in <b>{}</b> ({}). Years: {}.</p>",
        esc(&opts.title),
        esc(r.host.as_deref().unwrap_or("unknown")),
        esc(&range),
        esc(&r.timezone),
        esc(&r.timezone_source),
        esc(&r.year_anchor)
    );
    let warn_total: u64 = r.artifacts.iter().map(|a| a.warnings).sum();
    let _ = write!(html, "<div class=\"cards\">");
    for (value, label) in [
        (r.events, "events in timeline"),
        (flagged.len() as u64, "events with rule hits"),
        (r.artifacts.len() as u64, "artifacts parsed"),
        (r.duplicates_merged, "duplicates merged"),
        (warn_total, "parser warnings"),
    ] {
        let _ = write!(
            html,
            "<div class=\"card\"><b>{value}</b><span>{label}</span></div>"
        );
    }
    html.push_str("</div>");

    // Findings.
    html.push_str("<h2>Findings</h2>");
    if flagged.is_empty() {
        html.push_str("<p class=\"note\">No rule fired.</p>");
    } else {
        html.push_str("<div class=\"wrap\"><table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Rule</th><th>What happened</th><th>User</th><th>Source</th></tr></thead><tbody>");
        for e in flagged.iter().take(2000) {
            let rules: Vec<String> = e
                .rule_hits
                .iter()
                .map(|h| {
                    opts.rule_info
                        .get(&h.rule)
                        .map_or_else(|| h.rule.clone(), |(t, _)| t.clone())
                })
                .collect();
            let _ = write!(
                html,
                "<tr><td class=\"ts\">{}</td><td>{}</td><td>{}</td><td class=\"d\">{}</td><td>{}</td><td>{}</td></tr>",
                esc(&format_ts(&e.ts)),
                e.max_severity().map(sev_badge).unwrap_or_default(),
                esc(&rules.join("; ")),
                esc(&e.description),
                esc(e.user.as_deref().unwrap_or("")),
                esc(&format!("{}:{}", e.artifact, e.location))
            );
        }
        html.push_str("</tbody></table></div>");
        if flagged.len() > 2000 {
            let _ = write!(
                html,
                "<p class=\"note\">Showing the first 2000 of {} flagged events.</p>",
                flagged.len()
            );
        }
    }

    // Activity histogram.
    html.push_str("<h2>Activity</h2><div class=\"wrap\">");
    html.push_str(&histogram(&tl.events));
    html.push_str("</div>");

    // Rule hit summary.
    if !r.rule_hits.is_empty() {
        html.push_str("<h2>Rule hits</h2><div class=\"wrap\"><table><thead><tr><th>Rule</th><th>Title</th><th>Severity</th><th>Events</th></tr></thead><tbody>");
        let mut hits: Vec<(&String, &u64)> = r.rule_hits.iter().collect();
        hits.sort_by(|a, b| {
            let sa = opts.rule_info.get(a.0).map(|x| x.1);
            let sb = opts.rule_info.get(b.0).map(|x| x.1);
            sb.cmp(&sa).then(a.0.cmp(b.0))
        });
        for (id, n) in hits {
            let (title, sev) = opts
                .rule_info
                .get(id)
                .map_or((String::new(), None), |(t, s)| (t.clone(), Some(*s)));
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{n}</td></tr>",
                esc(id),
                esc(&title),
                sev.map(sev_badge).unwrap_or_default()
            );
        }
        html.push_str("</tbody></table></div>");
    }

    // Artifacts.
    html.push_str("<h2>Artifacts</h2><div class=\"wrap\"><table><thead><tr><th>Path</th><th>Format</th><th>Records</th><th>Events</th><th>Warnings</th></tr></thead><tbody>");
    for a in &r.artifacts {
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
            esc(&a.path),
            a.kind,
            a.records,
            a.events,
            a.warnings,
            a.error
                .as_deref()
                .map(|e| format!(" — {}", esc(e)))
                .unwrap_or_default()
        );
    }
    html.push_str("</tbody></table></div>");

    // Full timeline (client-side rendering from embedded JSON).
    let mut embedded: Vec<&Event> = Vec::new();
    let mut dropped = 0usize;
    for e in &tl.events {
        if embedded.len() < opts.html_max_events || !e.rule_hits.is_empty() {
            embedded.push(e);
        } else {
            dropped += 1;
        }
    }
    let mut sources: BTreeMap<&str, u64> = BTreeMap::new();
    for e in &embedded {
        *sources.entry(e.source.as_str()).or_default() += 1;
    }
    html.push_str("<h2>Timeline</h2><div class=\"controls\"><input id=\"q\" type=\"search\" placeholder=\"Filter: text, user, IP, path…\" aria-label=\"Filter events\"><select id=\"src\" aria-label=\"Source\"><option value=\"\">All sources</option>");
    for (s, n) in &sources {
        let _ = write!(html, "<option value=\"{s}\">{s} ({n})</option>");
    }
    html.push_str(
        "</select><label><input id=\"flag\" type=\"checkbox\"> rule hits only</label></div>",
    );
    if dropped > 0 {
        let _ = write!(
            html,
            "<p class=\"note\">{dropped} unflagged events beyond the first {} are omitted from this table; use the JSONL/CSV outputs for the full timeline.</p>",
            opts.html_max_events
        );
    }
    html.push_str("<div class=\"wrap\"><table><thead><tr><th>Time (UTC)</th><th>Source</th><th>Kind</th><th>User</th><th>Description</th><th>Severity</th><th>Artifact</th></tr></thead><tbody id=\"rows\"></tbody></table></div>");
    html.push_str("<div class=\"controls\" id=\"pager\"><button id=\"prev\" type=\"button\">← Previous</button><button id=\"next\" type=\"button\">Next →</button><span id=\"info\" class=\"note\"></span></div>");
    html.push_str("<noscript><p class=\"note\">The interactive table needs JavaScript; the findings above are static.</p></noscript>");

    // Warnings.
    if !r.warnings.is_empty() {
        html.push_str("<h2>Parser warnings (sample)</h2><div class=\"wrap\"><table><thead><tr><th>Artifact</th><th>Location</th><th>Message</th></tr></thead><tbody>");
        for wn in r.warnings.iter().take(100) {
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&wn.artifact),
                wn.location,
                esc(&wn.message)
            );
        }
        html.push_str("</tbody></table></div>");
    }
    let _ = write!(
        html,
        "<footer>Generated by timeliner {} · every timestamp is UTC · event data is untrusted log content and is rendered as text only.</footer></main>",
        env!("CARGO_PKG_VERSION")
    );
    let rows: Vec<serde_json::Value> = embedded.iter().map(|e| row_json(e)).collect();
    let json = serde_json::to_string(&rows).map_err(io::Error::other)?;
    let _ = writeln!(
        html,
        "<script type=\"application/json\" id=\"tl-data\">{}</script><script>{SCRIPT}</script></body></html>",
        script_safe_json(&json)
    );
    w.write_all(html.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Warning;
    use crate::event::{EventKind, RuleHit, SourceKind};
    use crate::parsers::ArtifactKind;
    use crate::pipeline::{ArtifactReport, BuildReport};
    use chrono::TimeZone;

    fn timeline(n: usize) -> Timeline {
        let base = Utc.with_ymd_and_hms(2025, 1, 1, 4, 0, 0).unwrap();
        let mut events: Vec<Event> = (0..n)
            .map(|i| {
                Event::new(
                    base + Duration::seconds(i as i64 * 37),
                    SourceKind::AuthLog,
                    EventKind::SshInvalidUser,
                    "var/log/auth.log",
                    i as u64 + 1,
                    "SSH connection for invalid user <script>alert(1)</script> from 203.0.113.45",
                )
                .with_user(Some("</script><img src=x onerror=alert(1)>"))
            })
            .collect();
        events[0].rule_hits.push(RuleHit {
            rule: "ssh-bruteforce".into(),
            severity: Severity::High,
        });
        events[0].add_tag("ssh-bruteforce");
        events[1].rule_hits.push(RuleHit {
            rule: "unknown-rule".into(),
            severity: Severity::Low,
        });
        let mut report = BuildReport {
            events: n as u64,
            first: Some(format_ts(&events[0].ts)),
            last: Some(format_ts(&events[n - 1].ts)),
            timezone: "America/New_York".into(),
            timezone_source: "evidence etc/localtime".into(),
            host: Some("web01".into()),
            ..BuildReport::default()
        };
        report.rule_hits.insert("ssh-bruteforce".into(), 1);
        report.rule_hits.insert("unknown-rule".into(), 1);
        report.artifacts.push(ArtifactReport {
            path: "var/log/auth.log".into(),
            kind: ArtifactKind::AuthLog,
            records: n as u64,
            events: n as u64,
            warnings: 1,
            error: Some("<bad>".into()),
        });
        report.warnings.push(Warning {
            artifact: "var/log/auth.log".into(),
            location: 3,
            message: "unrecognized <b>".into(),
        });
        Timeline { events, report }
    }

    fn render(tl: &Timeline, max: usize) -> String {
        let opts = OutputOptions {
            html_max_events: max,
            ..OutputOptions::default()
        }
        .with_rules(&crate::rules::RuleSet::default_rules());
        let mut out = Vec::new();
        write_html(tl, &opts, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn untrusted_text_is_inert() {
        let html = render(&timeline(10), 50_000);
        // Only the two inline script elements of the template exist.
        assert_eq!(html.matches("<script").count(), 2);
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("\\u003c/script\\u003e"));
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains(&esc(&csp_hash(SCRIPT))));
        assert!(html.contains("SSH brute force"));
        assert!(html.contains("unknown-rule"));
        assert!(html.contains("&lt;bad&gt;"));
        assert!(html.contains("unrecognized &lt;b&gt;"));
    }

    #[test]
    fn deterministic_and_capped() {
        let tl = timeline(400);
        let a = render(&tl, 100);
        assert_eq!(a, render(&tl, 100));
        assert!(a.contains("300 unflagged events beyond the first 100"));
        let empty = Timeline {
            events: Vec::new(),
            report: BuildReport::default(),
        };
        let html = render(&empty, 10);
        assert!(html.contains("No rule fired"));
    }

    #[test]
    fn helpers() {
        assert_eq!(
            esc("<a href='x'>&\"</a>"),
            "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;"
        );
        assert_eq!(
            script_safe_json("\"</script>&\u{2028}\""),
            "\"\\u003c/script\\u003e\\u0026\\u2028\""
        );
        assert_eq!(bucket_width(Duration::seconds(30)), Duration::seconds(60));
        assert_eq!(bucket_width(Duration::hours(5)), Duration::seconds(300));
        assert_eq!(
            bucket_width(Duration::days(10)),
            Duration::seconds(3 * 3600)
        );
        assert_eq!(
            bucket_width(Duration::days(10_000)).num_seconds(),
            7_200_000
        );
        assert_eq!(human_width(86_400), "1 day(s)");
        assert_eq!(human_width(7), "7 s");
        assert_eq!(human_width(120), "2 minute(s)");
        assert_eq!(human_width(7200), "2 hour(s)");
    }
}
