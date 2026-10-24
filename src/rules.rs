//! YAML tagging rules.
//!
//! A rule selects events with field matchers (`when`, minus `unless`) and
//! optionally adds state:
//!
//! * `threshold` — fire when at least `count` matching events with the same
//!   `group_by` values occur within `window` (e.g. SSH brute force);
//! * `first_seen` — fire the first time `value` is seen within a `group_by`
//!   group (e.g. "SSH login from a new IP *for this user*"); with
//!   `require_history: true` it fires only for groups that already had
//!   history, and `learn_until` turns the earlier period into a baseline.
//!
//! ```yaml
//! rules:
//!   - id: ssh-bruteforce
//!     title: SSH brute force
//!     severity: high
//!     tags: [bruteforce]
//!     when:
//!       kind: { in: [ssh_login_failure, ssh_invalid_user] }
//!     threshold: { count: 5, window: 5m, group_by: [src_ip] }
//! ```
//!
//! Matchers: a string (equals), a list (in), or a map of operators
//! `equals`, `in`, `contains`, `starts_with`, `ends_with`, `regex`, `cidr`,
//! `exists`, `not` (all must hold). Field names are the built-ins
//! (`kind`, `source`, `user`, `host`, `description`, `artifact`, `raw`) or any
//! structured field (`src_ip`, `fields.command`, ...).
//!
//! Rules run over the time-sorted, de-duplicated timeline in one pass:
//! O(n · r) time; state is O(distinct groups).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::Deserialize;
use serde_yaml::Value;

use crate::error::{Error, Result};
use crate::event::{Event, RuleHit, Severity};

/// The ruleset shipped with timeliner.
pub const DEFAULT_RULES_YAML: &str = include_str!("../rules/default.yml");

/// An IPv4/IPv6 network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `10.0.0.0/8`, `2001:db8::/32` or a bare address.
    pub fn parse(s: &str) -> Result<Self> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let net: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| Error::Rule(format!("invalid CIDR `{s}`")))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| Error::Rule(format!("invalid CIDR prefix in `{s}`")))?,
            None => max,
        };
        Ok(Cidr { net, prefix })
    }

    /// True when `ip` is inside the network.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let mask_bits = |a: u128, b: u128, width: u32| {
            if self.prefix == 0 {
                return true;
            }
            let shift = width - u32::from(self.prefix);
            (a >> shift) == (b >> shift)
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                mask_bits(u128::from(u32::from(n)), u128::from(u32::from(*i)), 32)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => mask_bits(u128::from(n), u128::from(*i), 128),
            _ => false,
        }
    }
}

/// A compiled field matcher.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Exact string equality.
    Equals(String),
    /// Membership.
    In(Vec<String>),
    /// Substring.
    Contains(String),
    /// Prefix.
    StartsWith(String),
    /// Suffix.
    EndsWith(String),
    /// Regular expression (Rust `regex` syntax).
    Regex(Regex),
    /// Value parses as an IP inside any network.
    Cidr(Vec<Cidr>),
    /// Field presence (`true`) or absence (`false`).
    Exists(bool),
    /// Negation.
    Not(Box<Matcher>),
    /// Conjunction.
    All(Vec<Matcher>),
}

impl Matcher {
    /// Evaluates against an optional field value.
    pub fn matches(&self, value: Option<&str>) -> bool {
        match self {
            Matcher::Exists(want) => value.is_some() == *want,
            Matcher::Not(inner) => !inner.matches(value),
            Matcher::All(ms) => ms.iter().all(|m| m.matches(value)),
            _ => {
                let Some(v) = value else { return false };
                match self {
                    Matcher::Equals(s) => v == s,
                    Matcher::In(list) => list.iter().any(|s| s == v),
                    Matcher::Contains(s) => v.contains(s.as_str()),
                    Matcher::StartsWith(s) => v.starts_with(s.as_str()),
                    Matcher::EndsWith(s) => v.ends_with(s.as_str()),
                    Matcher::Regex(r) => r.is_match(v),
                    Matcher::Cidr(nets) => v
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| nets.iter().any(|n| n.contains(&ip))),
                    Matcher::Exists(_) | Matcher::Not(_) | Matcher::All(_) => unreachable!(),
                }
            }
        }
    }

    /// Compiles a YAML matcher specification.
    pub fn compile(spec: &Value, ctx: &str) -> Result<Self> {
        let err = |m: String| Error::Rule(format!("{ctx}: {m}"));
        match spec {
            Value::String(s) => Ok(Matcher::Equals(s.clone())),
            Value::Number(n) => Ok(Matcher::Equals(n.to_string())),
            Value::Bool(b) => Ok(Matcher::Equals(b.to_string())),
            Value::Sequence(_) => Ok(Matcher::In(string_list(spec, ctx)?)),
            Value::Mapping(map) => {
                let mut parts = Vec::new();
                for (k, v) in map {
                    let key = k
                        .as_str()
                        .ok_or_else(|| err("operator must be a string".into()))?;
                    let scalar =
                        || scalar_string(v).ok_or_else(|| err(format!("`{key}` needs a string")));
                    parts.push(match key {
                        "equals" => Matcher::Equals(scalar()?),
                        "in" => Matcher::In(string_list(v, ctx)?),
                        "contains" => Matcher::Contains(scalar()?),
                        "starts_with" => Matcher::StartsWith(scalar()?),
                        "ends_with" => Matcher::EndsWith(scalar()?),
                        "regex" => Matcher::Regex(
                            Regex::new(&scalar()?).map_err(|e| err(format!("bad regex: {e}")))?,
                        ),
                        "cidr" => Matcher::Cidr(
                            string_list(v, ctx)?
                                .iter()
                                .map(|c| Cidr::parse(c))
                                .collect::<Result<_>>()?,
                        ),
                        "exists" => Matcher::Exists(
                            v.as_bool()
                                .ok_or_else(|| err("`exists` needs a boolean".into()))?,
                        ),
                        "not" => Matcher::Not(Box::new(Matcher::compile(v, ctx)?)),
                        other => return Err(err(format!("unknown operator `{other}`"))),
                    });
                }
                if parts.is_empty() {
                    return Err(err("empty matcher".into()));
                }
                Ok(if parts.len() == 1 {
                    parts.remove(0)
                } else {
                    Matcher::All(parts)
                })
            }
            _ => Err(err("unsupported matcher value".into())),
        }
    }
}

fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn string_list(v: &Value, ctx: &str) -> Result<Vec<String>> {
    match v {
        Value::Sequence(items) => items
            .iter()
            .map(|i| {
                scalar_string(i)
                    .ok_or_else(|| Error::Rule(format!("{ctx}: list items must be scalars")))
            })
            .collect(),
        other => scalar_string(other)
            .map(|s| vec![s])
            .ok_or_else(|| Error::Rule(format!("{ctx}: expected a list"))),
    }
}

/// Parses durations like `90s`, `5m`, `2h`, `1d`.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(split);
    let n: i64 = n
        .parse()
        .map_err(|_| Error::Rule(format!("invalid duration `{s}`")))?;
    let secs = match unit {
        "s" | "" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(Error::Rule(format!("invalid duration unit in `{s}`"))),
    };
    if secs <= 0 {
        return Err(Error::Rule(format!("duration must be positive: `{s}`")));
    }
    Ok(Duration::seconds(secs))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<u32>,
    rules: Vec<RuleSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    id: String,
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    when: BTreeMap<String, Value>,
    #[serde(default)]
    unless: BTreeMap<String, Value>,
    #[serde(default)]
    threshold: Option<ThresholdSpec>,
    #[serde(default)]
    first_seen: Option<FirstSeenSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdSpec {
    count: usize,
    window: String,
    #[serde(default)]
    group_by: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstSeenSpec {
    value: String,
    #[serde(default)]
    group_by: Vec<String>,
    #[serde(default)]
    require_history: bool,
    #[serde(default)]
    learn_until: Option<String>,
}

/// Stateful behaviour of a rule.
#[derive(Debug, Clone)]
pub enum Stateful {
    /// Plain filter.
    None,
    /// Count-in-window.
    Threshold {
        /// Minimum count.
        count: usize,
        /// Sliding window.
        window: Duration,
        /// Grouping fields.
        group_by: Vec<String>,
    },
    /// First occurrence of a value per group.
    FirstSeen {
        /// Field whose novelty is tested.
        value: String,
        /// Grouping fields.
        group_by: Vec<String>,
        /// Only fire for groups with prior history.
        require_history: bool,
        /// Events before this instant only train the baseline.
        learn_until: Option<DateTime<Utc>>,
    },
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique identifier.
    pub id: String,
    /// Title shown in reports.
    pub title: String,
    /// Longer explanation.
    pub description: String,
    /// Severity.
    pub severity: Severity,
    /// Tags added on match (defaults to `[id]`).
    pub tags: Vec<String>,
    /// Conjunction of field matchers.
    pub when: Vec<(String, Matcher)>,
    /// Exclusion: if all of these match, the rule does not fire.
    pub unless: Vec<(String, Matcher)>,
    /// Stateful behaviour.
    pub stateful: Stateful,
}

impl Rule {
    fn selects(&self, e: &Event) -> bool {
        self.when.iter().all(|(f, m)| m.matches(e.get(f)))
            && (self.unless.is_empty() || !self.unless.iter().all(|(f, m)| m.matches(e.get(f))))
    }
}

/// A set of compiled rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Rules in file order.
    pub rules: Vec<Rule>,
}

fn compile_map(map: &BTreeMap<String, Value>, ctx: &str) -> Result<Vec<(String, Matcher)>> {
    map.iter()
        .map(|(field, spec)| {
            Ok((
                field.clone(),
                Matcher::compile(spec, &format!("{ctx}.{field}"))?,
            ))
        })
        .collect()
}

impl RuleSet {
    /// Parses a YAML rule document.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let file: RuleFile =
            serde_yaml::from_str(text).map_err(|e| Error::Rule(format!("invalid YAML: {e}")))?;
        let mut set = RuleSet::default();
        for spec in file.rules {
            set.push(compile_rule(spec)?)?;
        }
        Ok(set)
    }

    /// The built-in ruleset.
    pub fn default_rules() -> Self {
        Self::from_yaml(DEFAULT_RULES_YAML).expect("built-in rules must be valid")
    }

    /// Loads a rule file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        Self::from_yaml(&text).map_err(|e| Error::Rule(format!("{}: {e}", path.display())))
    }

    /// Adds a rule, rejecting duplicate ids.
    pub fn push(&mut self, rule: Rule) -> Result<()> {
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(Error::Rule(format!("duplicate rule id `{}`", rule.id)));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Merges another set (duplicate ids are an error).
    pub fn extend(&mut self, other: RuleSet) -> Result<()> {
        other.rules.into_iter().try_for_each(|r| self.push(r))
    }

    /// Applies every rule to a time-sorted timeline; returns hits per rule id.
    pub fn apply(&self, events: &mut [Event]) -> BTreeMap<String, u64> {
        let mut hits: BTreeMap<String, u64> = BTreeMap::new();
        let mut windows: Vec<HashMap<Vec<String>, VecDeque<DateTime<Utc>>>> =
            vec![HashMap::new(); self.rules.len()];
        let mut seen: Vec<HashMap<Vec<String>, HashSet<String>>> =
            vec![HashMap::new(); self.rules.len()];
        for e in events.iter_mut() {
            for (ri, rule) in self.rules.iter().enumerate() {
                if !rule.selects(e) {
                    continue;
                }
                let fired = match &rule.stateful {
                    Stateful::None => true,
                    Stateful::Threshold {
                        count,
                        window,
                        group_by,
                    } => {
                        let Some(key) = group_key(e, group_by) else {
                            continue;
                        };
                        let q = windows[ri].entry(key).or_default();
                        while q.front().is_some_and(|t| e.ts - *t > *window) {
                            q.pop_front();
                        }
                        q.push_back(e.ts);
                        q.len() >= *count
                    }
                    Stateful::FirstSeen {
                        value,
                        group_by,
                        require_history,
                        learn_until,
                    } => {
                        let (Some(key), Some(v)) = (group_key(e, group_by), e.get(value)) else {
                            continue;
                        };
                        let set = seen[ri].entry(key).or_default();
                        let had_history = !set.is_empty();
                        let new = set.insert(v.to_string());
                        let learning = learn_until.is_some_and(|l| e.ts < l);
                        new && !learning && (had_history || !require_history)
                    }
                };
                if fired {
                    for t in &rule.tags {
                        e.add_tag(t);
                    }
                    e.rule_hits.push(RuleHit {
                        rule: rule.id.clone(),
                        severity: rule.severity,
                    });
                    *hits.entry(rule.id.clone()).or_default() += 1;
                }
            }
        }
        hits
    }

    /// Overrides `learn_until` on every `first_seen` rule.
    pub fn set_baseline_until(&mut self, until: DateTime<Utc>) {
        for r in &mut self.rules {
            if let Stateful::FirstSeen { learn_until, .. } = &mut r.stateful {
                *learn_until = Some(until);
            }
        }
    }

    /// Looks up a rule by id.
    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }
}

fn group_key(e: &Event, fields: &[String]) -> Option<Vec<String>> {
    fields
        .iter()
        .map(|f| e.get(f).map(str::to_string))
        .collect()
}

fn compile_rule(spec: RuleSpec) -> Result<Rule> {
    let ctx = format!("rule `{}`", spec.id);
    if spec.id.trim().is_empty() {
        return Err(Error::Rule("rule with empty id".into()));
    }
    let severity = match &spec.severity {
        Some(s) => s
            .parse::<Severity>()
            .map_err(|e| Error::Rule(format!("{ctx}: {e}")))?,
        None => Severity::Medium,
    };
    let when = compile_map(&spec.when, &format!("{ctx}.when"))?;
    let unless = compile_map(&spec.unless, &format!("{ctx}.unless"))?;
    let stateful = match (spec.threshold, spec.first_seen) {
        (Some(_), Some(_)) => {
            return Err(Error::Rule(format!(
                "{ctx}: `threshold` and `first_seen` are mutually exclusive"
            )));
        }
        (Some(t), None) => {
            if t.count < 1 {
                return Err(Error::Rule(format!("{ctx}: threshold count must be >= 1")));
            }
            Stateful::Threshold {
                count: t.count,
                window: parse_duration(&t.window)
                    .map_err(|e| Error::Rule(format!("{ctx}: {e}")))?,
                group_by: t.group_by,
            }
        }
        (None, Some(f)) => Stateful::FirstSeen {
            value: f.value,
            group_by: f.group_by,
            require_history: f.require_history,
            learn_until: f
                .learn_until
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|t| t.with_timezone(&Utc))
                        .map_err(|e| Error::Rule(format!("{ctx}: learn_until: {e}")))
                })
                .transpose()?,
        },
        (None, None) => Stateful::None,
    };
    if when.is_empty() {
        return Err(Error::Rule(format!("{ctx}: `when` must not be empty")));
    }
    let tags = if spec.tags.is_empty() {
        vec![spec.id.clone()]
    } else {
        spec.tags
    };
    Ok(Rule {
        id: spec.id,
        title: spec.title,
        description: spec.description,
        severity,
        tags,
        when,
        unless,
        stateful,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, SourceKind};
    use chrono::TimeZone;

    fn ev(secs: i64, kind: EventKind, user: &str, ip: &str) -> Event {
        Event::new(
            Utc.timestamp_opt(1_735_700_000 + secs, 0).unwrap(),
            SourceKind::AuthLog,
            kind,
            "a",
            secs as u64,
            "d",
        )
        .with_user(Some(user))
        .with_field("src_ip", ip)
    }

    #[test]
    fn default_rules_compile() {
        let set = RuleSet::default_rules();
        assert!(set.rules.len() >= 12);
        assert!(set.get("ssh-bruteforce").is_some());
        assert!(set.get("nope").is_none());
    }

    #[test]
    fn matchers() {
        let m = |y: &str| Matcher::compile(&serde_yaml::from_str(y).unwrap(), "t").unwrap();
        assert!(m("root").matches(Some("root")));
        assert!(m("[a, b]").matches(Some("b")));
        assert!(m("{contains: tmp}").matches(Some("/tmp/x")));
        assert!(m("{starts_with: /tmp, ends_with: .sh}").matches(Some("/tmp/x.sh")));
        assert!(!m("{starts_with: /tmp, ends_with: .sh}").matches(Some("/tmp/x.py")));
        assert!(m("{regex: '^a+$'}").matches(Some("aaa")));
        assert!(m("{cidr: [10.0.0.0/8, '2001:db8::/32']}").matches(Some("10.1.2.3")));
        assert!(m("{cidr: '2001:db8::/32'}").matches(Some("2001:db8::5")));
        assert!(!m("{cidr: 10.0.0.0/8}").matches(Some("2001:db8::5")));
        assert!(!m("{cidr: 10.0.0.0/8}").matches(Some("not-an-ip")));
        assert!(m("{cidr: 0.0.0.0/0}").matches(Some("8.8.8.8")));
        assert!(m("{exists: false}").matches(None));
        assert!(m("{not: {in: [a]}}").matches(Some("b")));
        assert!(m("{not: x}").matches(None));
        assert!(!m("x").matches(None));
        assert!(m("5").matches(Some("5")));
        assert!(m("true").matches(Some("true")));
        for bad in [
            "{bogus: 1}",
            "{}",
            "{regex: '('}",
            "{cidr: 10.0.0.0/33}",
            "{exists: x}",
            "~",
            "{equals: [a]}",
            "{in: {a: b}}",
        ] {
            assert!(
                Matcher::compile(&serde_yaml::from_str(bad).unwrap(), "t").is_err(),
                "{bad}"
            );
        }
        assert!(
            Cidr::parse("1.2.3.4")
                .unwrap()
                .contains(&"1.2.3.4".parse().unwrap())
        );
        assert!(Cidr::parse("x/1").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), Duration::seconds(90));
        assert_eq!(parse_duration("5m").unwrap(), Duration::seconds(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::seconds(7200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::seconds(86_400));
        for bad in ["", "0s", "5y", "m"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn threshold_rule() {
        let set = RuleSet::from_yaml(
            "rules:\n  - id: bf\n    title: t\n    when: {kind: ssh_login_failure}\n    threshold: {count: 3, window: 60s, group_by: [src_ip]}\n",
        )
        .unwrap();
        let mut evs = vec![
            ev(0, EventKind::SshLoginFailure, "a", "1.1.1.1"),
            ev(10, EventKind::SshLoginFailure, "a", "2.2.2.2"),
            ev(20, EventKind::SshLoginFailure, "b", "1.1.1.1"),
            ev(100, EventKind::SshLoginFailure, "c", "1.1.1.1"), // window expired
            ev(110, EventKind::SshLoginFailure, "c", "1.1.1.1"),
            ev(115, EventKind::SshLoginFailure, "c", "1.1.1.1"), // 3 within 60s
            ev(116, EventKind::SshLoginSuccess, "c", "1.1.1.1"),
        ];
        let hits = set.apply(&mut evs);
        assert_eq!(hits.get("bf"), Some(&1));
        assert_eq!(evs[5].tags, vec!["bf"]);
        assert_eq!(evs[5].max_severity(), Some(Severity::Medium));
    }

    #[test]
    fn first_seen_rule_with_history_and_baseline() {
        let yaml = "rules:\n  - id: new-ip\n    title: t\n    severity: high\n    tags: [ssh, new-ip]\n    when: {kind: ssh_login_success}\n    unless: {src_ip: {cidr: 192.168.0.0/16}}\n    first_seen: {value: src_ip, group_by: [user], require_history: true}\n";
        let mut set = RuleSet::from_yaml(yaml).unwrap();
        let mk = || {
            vec![
                ev(0, EventKind::SshLoginSuccess, "deploy", "198.51.100.7"),
                ev(10, EventKind::SshLoginSuccess, "deploy", "198.51.100.7"),
                ev(20, EventKind::SshLoginSuccess, "deploy", "203.0.113.45"),
                ev(30, EventKind::SshLoginSuccess, "deploy", "192.168.1.5"),
                ev(40, EventKind::SshLoginSuccess, "newbie", "192.0.2.99"),
            ]
        };
        let mut evs = mk();
        set.apply(&mut evs);
        let tagged: Vec<bool> = evs.iter().map(|e| !e.tags.is_empty()).collect();
        assert_eq!(tagged, vec![false, false, true, false, false]);
        assert_eq!(evs[2].tags, vec!["new-ip", "ssh"]);

        // Without require_history but with a baseline, only post-baseline novelty fires.
        let yaml2 = yaml.replace("require_history: true", "require_history: false");
        let mut set2 = RuleSet::from_yaml(&yaml2).unwrap();
        set2.set_baseline_until(Utc.timestamp_opt(1_735_700_015, 0).unwrap());
        let mut evs = mk();
        set2.apply(&mut evs);
        let tagged: Vec<bool> = evs.iter().map(|e| !e.tags.is_empty()).collect();
        assert_eq!(tagged, vec![false, false, true, false, true]);
        set.set_baseline_until(Utc.timestamp_opt(0, 0).unwrap());
    }

    #[test]
    fn invalid_rule_files() {
        let cases = [
            "rules: [{id: a, title: t, when: {}}]",
            "rules: [{id: '', title: t, when: {kind: x}}]",
            "rules: [{id: a, title: t, severity: extreme, when: {kind: x}}]",
            "rules: [{id: a, title: t, when: {kind: x}, threshold: {count: 0, window: 1m}}]",
            "rules: [{id: a, title: t, when: {kind: x}, threshold: {count: 2, window: 1y}}]",
            "rules: [{id: a, title: t, when: {kind: x}, first_seen: {value: v, learn_until: nope}}]",
            "rules: [{id: a, title: t, when: {kind: x}, threshold: {count: 2, window: 1m}, first_seen: {value: v}}]",
            "rules: [{id: a, title: t, when: {kind: x}}, {id: a, title: t, when: {kind: y}}]",
            "rules: [{id: a, title: t, bogus: 1, when: {kind: x}}]",
            "not yaml: [",
        ];
        for c in cases {
            assert!(RuleSet::from_yaml(c).is_err(), "{c}");
        }
        let ok = RuleSet::from_yaml(
            "version: 1\nrules: [{id: a, title: t, when: {kind: x}, first_seen: {value: v, learn_until: '2025-01-01T00:00:00Z'}}]",
        );
        assert!(ok.is_ok());
        let mut base = RuleSet::default_rules();
        assert!(base.extend(RuleSet::default_rules()).is_err());
        assert!(RuleSet::from_file(Path::new("/definitely/missing.yml")).is_err());
    }
}
