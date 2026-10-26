//! Scanner reports into review notes. Parsers only build [`RawFinding`]s;
//! confining paths and reading snippets is left to [`ingest`].

use anyhow::{Context, bail};
use chrono::{SubsecRound, Utc};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::anchor::{self, Code};
use crate::config::Config;
use crate::markdown::{inline_code, md_escape};
use crate::note::{MAX_TAGS, Meta, Note, tag_from_scanner};
use crate::safety::{self, MAX_IMPORT_BYTES, MAX_SOURCE_BYTES};
use crate::store::Store;

#[derive(Debug, Clone, PartialEq)]
pub struct RawFinding {
    pub tool: String,
    /// Untrusted, checked in `ingest`
    pub uri: String,
    /// `uri` relative to a root the report names, for reports made on another
    /// machine. Fallback when `uri` isn't in the project.
    pub stripped: Option<String>,
    pub start_line: u32,
    pub end_line: u32,
    pub rule: String,
    pub message: String,
    pub level: Option<String>,
    pub tags: Vec<String>,
    pub flow: Vec<FlowStep>,
}

/// Display only. `location` is whatever the report said, never a checked path.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowStep {
    pub location: String,
    pub message: Option<String>,
}

/// Steps past this are just counted
const MAX_FLOW_STEPS: usize = 20;
/// chars, per location or message
const MAX_STEP_CHARS: usize = 200;

#[derive(Debug, Default)]
pub struct Summary {
    pub tools: Vec<String>,
    pub imported: usize,
    pub skipped: usize,
    /// suppressed, `pass`/`notApplicable`, or absent per the baseline
    pub ignored: usize,
    pub rejected: Vec<String>,
    /// `None` unless [`Options::resolve_missing`] was set. Entries are `id file:line title`.
    pub resolved: Option<Vec<String>>,
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: imported {}, skipped {} (already present), ignored {} (suppressed or not a failure), rejected {}",
            if self.tools.is_empty() {
                "scanner report".to_string()
            } else {
                self.tools.join(", ")
            },
            self.imported,
            self.skipped,
            self.ignored,
            self.rejected.len()
        )?;
        if let Some(resolved) = &self.resolved {
            write!(f, ", resolved {} (no longer reported)", resolved.len())?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Options {
    /// Notes from this report's tools that it no longer reports get `resolved_status`.
    pub resolve_missing: bool,
}

const FORMAT_HINT: &str = "expected SARIF, a GitLab security report or brakeman JSON. Ask your scanner for SARIF: \
    `semgrep --sarif`, `codeql database analyze --format=sarif-latest`, \
    `snyk code test --sarif-file-output=FILE`, `bandit -f sarif`, `gosec -fmt sarif`, `checkov -o sarif`, `brakeman -f json`";

pub fn import_file(store: &Store, config: &Config, path: &Path) -> anyhow::Result<Summary> {
    import_file_with(store, config, path, Options::default())
}

pub fn import_file_with(
    store: &Store,
    config: &Config,
    path: &Path,
    options: Options,
) -> anyhow::Result<Summary> {
    let text = safety::read_limited(path, MAX_IMPORT_BYTES, "scanner report")
        .with_context(|| format!("reading {}", path.display()))?;
    import_text_with(store, config, &text, options)
}

pub fn import_text(store: &Store, config: &Config, text: &str) -> anyhow::Result<Summary> {
    import_text_with(store, config, text, Options::default())
}

pub fn import_text_with(
    store: &Store,
    config: &Config,
    text: &str,
    options: Options,
) -> anyhow::Result<Summary> {
    ingest(store, config, parse(text)?, options)
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub tools: Vec<String>,
    /// Includes runs with zero results. Those still matter when resolving old findings.
    pub ran: Vec<String>,
    pub findings: Vec<RawFinding>,
    pub ignored: usize,
    pub rejected: Vec<String>,
}

pub fn parse(text: &str) -> anyhow::Result<Parsed> {
    let doc: Value =
        serde_json::from_str(text).with_context(|| format!("not valid JSON; {FORMAT_HINT}"))?;
    let shape = |key: &str| match doc.get(key) {
        Some(Value::Array(_)) => Shape::Array,
        Some(Value::Object(_)) => Shape::Object,
        _ => Shape::Other,
    };
    match format_of(shape) {
        Some(Format::Sarif) => Ok(parse_sarif(&doc)),
        Some(Format::Gitlab) => Ok(parse_gitlab(&doc)),
        Some(Format::Brakeman) => Ok(parse_brakeman(&doc)),
        None => bail!("unrecognised report format; {FORMAT_HINT}"),
    }
}

/// Cheap shape check, nothing gets built. Decides whether an open `.json` is
/// offered for import.
pub fn is_report(text: &str) -> bool {
    serde_json::from_str::<HashMap<String, Shape>>(text)
        .is_ok_and(|top| format_of(|key| top.get(key).copied().unwrap_or(Shape::Other)).is_some())
}

enum Format {
    Sarif,
    Gitlab,
    Brakeman,
}

/// Shared by [`parse`] and [`is_report`] so the two can't disagree.
fn format_of(shape: impl Fn(&str) -> Shape) -> Option<Format> {
    if shape("runs") == Shape::Array {
        Some(Format::Sarif)
    } else if shape("vulnerabilities") == Shape::Array && shape("scan") == Shape::Object {
        Some(Format::Gitlab)
    } else if shape("warnings") == Shape::Array {
        Some(Format::Brakeman)
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    Array,
    Object,
    Other,
}

impl<'de> serde::Deserialize<'de> for Shape {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Shape, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Shape;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Shape, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Shape::Array)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Shape, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Shape::Object)
            }
            fn visit_bool<E>(self, _: bool) -> Result<Shape, E> {
                Ok(Shape::Other)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Shape, E> {
                Ok(Shape::Other)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Shape, E> {
                Ok(Shape::Other)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Shape, E> {
                Ok(Shape::Other)
            }
            fn visit_str<E>(self, _: &str) -> Result<Shape, E> {
                Ok(Shape::Other)
            }
            fn visit_unit<E>(self) -> Result<Shape, E> {
                Ok(Shape::Other)
            }
        }
        d.deserialize_any(V)
    }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn line(v: Option<&Value>) -> Option<u32> {
    v?.as_u64()
        .filter(|&n| n >= 1)
        .and_then(|n| u32::try_from(n).ok())
}

/// SARIF 2.1.0 (the § numbers are spec sections). Only reads what's needed to
/// place a finding on a line and describe it.
fn parse_sarif(doc: &Value) -> Parsed {
    let mut out = Parsed::default();
    for run in doc["runs"].as_array().into_iter().flatten() {
        let tool = str_at(run, &["tool", "driver", "name"])
            .unwrap_or("sarif")
            .to_string();
        if !out.ran.contains(&tool) {
            out.ran.push(tool.clone());
        }
        if run["results"].as_array().is_some_and(|r| !r.is_empty()) && !out.tools.contains(&tool) {
            out.tools.push(tool.clone());
        }
        let roots = report_roots(run);
        let rules = RuleIndex::new(run);
        for (i, result) in run["results"].as_array().into_iter().flatten().enumerate() {
            if !is_live_failure(result) {
                out.ignored += 1;
                continue;
            }
            let what = || {
                let rule = str_at(result, &["ruleId"]).unwrap_or("no rule");
                format!("{tool} result {} ({rule})", i + 1)
            };

            // first location with both a file and a line (§3.27.12)
            let mut unlined = None;
            let mut found = None;
            for loc in result["locations"].as_array().into_iter().flatten() {
                let loc = &loc["physicalLocation"];
                let Some(uri) = artifact_uri(run, &loc["artifactLocation"]) else {
                    continue;
                };
                match line(loc["region"].get("startLine")) {
                    Some(start) => {
                        let end = line(loc["region"].get("endLine"))
                            .unwrap_or(start)
                            .max(start);
                        found = Some((uri, start, end));
                        break;
                    }
                    None => {
                        unlined.get_or_insert(uri);
                    }
                }
            }
            let Some((uri, start, end)) = found else {
                out.rejected.push(match unlined {
                    Some(uri) => format!("{}: {uri} has no start line", what()),
                    None => format!("{}: no file location", what()),
                });
                continue;
            };

            let rule_entry = rules.entry(run, result);
            let rule = str_at(result, &["ruleId"])
                .or_else(|| str_at(result, &["rule", "id"]))
                .or_else(|| rule_entry.and_then(|r| str_at(r, &["id"])))
                .unwrap_or("")
                .to_string();
            let message = message_text(run, result, rule_entry).unwrap_or_else(|| {
                rule_entry
                    .and_then(|r| {
                        str_at(r, &["shortDescription", "text"])
                            .or_else(|| str_at(r, &["fullDescription", "text"]))
                            .or_else(|| str_at(r, &["name"]))
                    })
                    .unwrap_or("Scanner finding")
                    .to_string()
            });
            let level = str_at(result, &["level"])
                .or_else(|| rule_entry.and_then(|r| str_at(r, &["defaultConfiguration", "level"])))
                .map(str::to_string);
            out.findings.push(RawFinding {
                tool: tool.clone(),
                stripped: strip_root(&uri, &roots),
                uri,
                start_line: start,
                end_line: end,
                rule,
                message,
                level,
                tags: note_tags(
                    [rule_entry, Some(result)]
                        .into_iter()
                        .flatten()
                        .flat_map(|v| v["properties"]["tags"].as_array().into_iter().flatten())
                        .filter_map(Value::as_str),
                ),
                flow: data_flow(run, result, &roots),
            });
        }
    }
    out
}

/// First thread flow of the first code flow (§3.36, §3.37)
fn data_flow(run: &Value, result: &Value, roots: &[String]) -> Vec<FlowStep> {
    let one_line = |s: &str, max| capped(&s.split_whitespace().collect::<Vec<_>>().join(" "), max);
    result["codeFlows"][0]["threadFlows"][0]["locations"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|step| {
            let loc = &step["location"];
            let physical = &loc["physicalLocation"];
            let file = artifact_uri(run, &physical["artifactLocation"])
                .map(|uri| strip_root(&uri, roots).unwrap_or(uri));
            let location = match (file, line(physical["region"].get("startLine"))) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                (Some(file), None) => file,
                (None, _) => "(no location)".to_string(),
            };
            FlowStep {
                location: one_line(&location, MAX_STEP_CHARS),
                message: str_at(loc, &["message", "text"])
                    .map(|m| one_line(&strip_location_links(m), MAX_STEP_CHARS))
                    .filter(|m| !m.is_empty()),
            }
        })
        .collect()
}

/// Drops suppressed (§3.27.23, §3.35.3), absent (§3.27.24) and non-failure
/// (§3.27.9) results. `informational` and `review` stay, a reviewer may want them.
fn is_live_failure(result: &Value) -> bool {
    let suppressed = result["suppressions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|s| matches!(str_at(s, &["status"]), None | Some("accepted")));
    let gone = str_at(result, &["baselineState"]) == Some("absent");
    let not_failure = matches!(str_at(result, &["kind"]), Some("pass" | "notApplicable"));
    !(suppressed || gone || not_failure)
}

/// Absolute uris (`/x`, `file:///x`) and anything with a scheme ignore `uriBaseId`.
fn is_absolute_uri(uri: &str) -> bool {
    uri.starts_with('/') || safety::has_scheme_or_drive(uri)
}

/// Resolves through `originalUriBaseIds`, which can chain (§3.14.14). An unknown
/// base leaves `uri` relative to the project root. Usually what the report meant.
fn resolve_uri(run: &Value, uri: &str, base: Option<&str>) -> String {
    let mut uri = uri.to_string();
    let mut base = base.map(str::to_string);
    // bases can refer to each other; don't loop forever
    let mut seen = HashSet::new();
    while let Some(b) = base.take() {
        if is_absolute_uri(&uri) || !seen.insert(b.clone()) {
            break;
        }
        let entry = &run["originalUriBaseIds"][b.as_str()];
        let Some(prefix) = str_at(entry, &["uri"]) else {
            break;
        };
        uri = if uri.is_empty() {
            prefix.to_string()
        } else {
            format!("{}/{}", prefix.trim_end_matches('/'), uri)
        };
        base = str_at(entry, &["uriBaseId"]).map(str::to_string);
    }
    uri
}

fn artifact_uri(run: &Value, al: &Value) -> Option<String> {
    let artifact = al["index"]
        .as_u64()
        .and_then(|i| run["artifacts"].get(usize::try_from(i).ok()?))
        .map(|a| &a["location"]);
    let artifact_uri = artifact.and_then(|a| str_at(a, &["uri"]));
    let uri = str_at(al, &["uri"]).or(artifact_uri)?;
    // Inherit the artifact's base only if this names the same file and has
    // no base of its own.
    let base = str_at(al, &["uriBaseId"]).or_else(|| {
        artifact
            .filter(|_| artifact_uri == Some(uri))
            .and_then(|a| str_at(a, &["uriBaseId"]))
    });
    Some(resolve_uri(run, uri, base))
}

fn local_path(uri: &str) -> Option<String> {
    if uri.starts_with("file:") {
        return safety::file_uri_path(uri)?.to_str().map(str::to_string);
    }
    percent_decode(uri).filter(|p| p.starts_with('/'))
}

/// Absolute dirs the report claims it ran in (base uris, invocation working dirs).
/// Anything shallower than two levels (`/`, `/home`) is dropped. It would match
/// nearly any path.
fn report_roots(run: &Value) -> Vec<String> {
    let bases = run["originalUriBaseIds"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys())
        .map(|k| resolve_uri(run, "", Some(k)));
    let dirs = run["invocations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|inv| {
            let wd = &inv["workingDirectory"];
            Some(resolve_uri(
                run,
                str_at(wd, &["uri"])?,
                str_at(wd, &["uriBaseId"]),
            ))
        });
    let mut roots: Vec<String> = bases
        .chain(dirs)
        .filter_map(|r| local_path(&r))
        .filter(|r| {
            Path::new(r)
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .count()
                >= 2
        })
        .collect();
    // most specific root first
    roots.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    roots.dedup();
    roots
}

/// Result still goes through the usual checks in `ingest`.
fn strip_root(uri: &str, roots: &[String]) -> Option<String> {
    let path = local_path(uri)?;
    roots.iter().find_map(|root| {
        let rel = Path::new(&path).strip_prefix(root).ok()?;
        let parts = rel
            .components()
            .map(|c| c.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()?;
        (!parts.is_empty()).then(|| parts.join("/"))
    })
}

/// §3.54
fn component<'a>(run: &'a Value, reference: &Value) -> Option<&'a Value> {
    let tool = &run["tool"];
    if reference.is_null() {
        return Some(&tool["driver"]);
    }
    let extensions = tool["extensions"].as_array();
    if let Some(i) = reference["index"].as_u64() {
        return extensions?.get(usize::try_from(i).ok()?);
    }
    let named = |key: &str| {
        let want = str_at(reference, &[key])?;
        if str_at(&tool["driver"], &[key]) == Some(want) {
            return Some(&tool["driver"]);
        }
        extensions?.iter().find(|e| str_at(e, &[key]) == Some(want))
    };
    named("guid").or_else(|| named("name"))
}

/// Rules by id across the driver and all extensions. Recent CodeQL puts each
/// query pack in its own extension (§3.52.4). First rule with a given id wins.
struct RuleIndex<'a>(HashMap<&'a str, &'a Value>);

impl<'a> RuleIndex<'a> {
    fn new(run: &'a Value) -> Self {
        let mut by_id = HashMap::new();
        let components = std::iter::once(&run["tool"]["driver"])
            .chain(run["tool"]["extensions"].as_array().into_iter().flatten());
        for rule in components.flat_map(|c| c["rules"].as_array().into_iter().flatten()) {
            if let Some(id) = str_at(rule, &["id"]) {
                by_id.entry(id).or_insert(rule);
            }
        }
        RuleIndex(by_id)
    }

    /// ruleId may be `rule/sub` (§3.27.5). Falls back to the longest known prefix.
    fn by_id(&self, id: &str) -> Option<&'a Value> {
        let mut id = id;
        loop {
            if let Some(rule) = self.0.get(id) {
                return Some(rule);
            }
            id = &id[..id.rfind('/')?];
        }
    }

    /// §3.27.6. An index lookup only counts if that rule's id agrees with the
    /// result's; otherwise look it up by id.
    fn entry(&self, run: &'a Value, result: &Value) -> Option<&'a Value> {
        let id = str_at(result, &["ruleId"]).or_else(|| str_at(result, &["rule", "id"]));
        let agrees = |r: &Value| {
            let Some(id) = id else { return true };
            str_at(r, &["id"]).is_some_and(|rid| {
                id == rid || id.strip_prefix(rid).is_some_and(|s| s.starts_with('/'))
            })
        };
        let by_index = result["rule"]["index"]
            .as_u64()
            .or_else(|| result["ruleIndex"].as_u64())
            .and_then(|i| {
                component(run, &result["rule"]["toolComponent"])?["rules"]
                    .get(usize::try_from(i).ok()?)
            })
            .filter(|r| agrees(r));
        by_index.or_else(|| self.by_id(id?))
    }
}

/// Plain-text message (§3.11), templates filled in, location links stripped.
fn message_text(run: &Value, result: &Value, rule: Option<&Value>) -> Option<String> {
    let msg = &result["message"];
    let template = || {
        let id = str_at(msg, &["id"])?;
        let lookup = |strings| message_string(strings, id);
        rule.and_then(|r| lookup(&r["messageStrings"])).or_else(|| {
            std::iter::once(&run["tool"]["driver"])
                .chain(run["tool"]["extensions"].as_array().into_iter().flatten())
                .find_map(|c| lookup(&c["globalMessageStrings"]))
        })
    };
    let (text, templated) = match str_at(msg, &["text"]) {
        Some(t) => (t, false),
        None => match template() {
            Some(t) => (t, true),
            None => (str_at(msg, &["markdown"])?, false),
        },
    };
    let args = msg["arguments"].as_array();
    // untemplated text keeps any literal `{{`
    let text = if templated || args.is_some() {
        let args: Vec<&str> = args
            .into_iter()
            .flatten()
            .map(|a| a.as_str().unwrap_or_default())
            .collect();
        format_message(text, &args)
    } else {
        text.to_string()
    };
    Some(strip_location_links(&text))
}

fn message_string<'a>(strings: &'a Value, id: &str) -> Option<&'a str> {
    let s = &strings[id];
    str_at(s, &["text"]).or_else(|| str_at(s, &["markdown"]))
}

/// `{0}` → the first argument; `{{` and `}}` are literal braces (§3.11.5).
fn format_message(template: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(i) = rest.find(['{', '}']) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if rest.starts_with("{{") || rest.starts_with("}}") {
            out.push_str(&rest[..1]);
            rest = &rest[2..];
            continue;
        }
        if rest.starts_with('{')
            && let Some(close) = rest.find('}')
            && let Ok(n) = rest[1..close].parse::<usize>()
            && let Some(arg) = args.get(n)
        {
            out.push_str(arg);
            rest = &rest[close + 1..];
            continue;
        }
        out.push_str(&rest[..1]);
        rest = &rest[1..];
    }
    out.push_str(rest);
    out
}

/// `[user input](1)` → `user input`. A numeric target means a related location
/// (§3.11.6), which a note can't follow. Other links are left for `md_escape`.
fn strip_location_links(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(c) = text[i..].chars().next() {
        let rest = &text[i..];
        if rest.starts_with("\\[") || rest.starts_with("\\]") {
            out.push_str(&rest[1..2]);
            i += 2;
        } else if let Some((label, len)) = location_link(rest) {
            out.push_str(&label);
            i += len;
        } else {
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// Label ends at the first unescaped `]`. Returns the unescaped label and the
/// link's byte length.
fn location_link(s: &str) -> Option<(String, usize)> {
    let body = s.strip_prefix('[')?;
    let mut label = String::new();
    let mut chars = body.char_indices();
    let close = loop {
        match chars.next()? {
            (j, '\\') if matches!(body[j + 1..].chars().next(), Some('[' | ']')) => {
                label.push(chars.next()?.1);
            }
            (_, '[') => return None,
            (j, ']') => break j,
            (_, c) => label.push(c),
        }
    };
    let target = body[close + 1..].strip_prefix('(')?;
    let digits = target.bytes().take_while(u8::is_ascii_digit).count();
    (digits > 0 && target[digits..].starts_with(')'))
        .then(|| (label, 1 + close + 1 + 1 + digits + 1))
}

fn note_tags<'a>(raw: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in raw.into_iter().filter_map(tag_from_scanner) {
        if out.len() < MAX_TAGS && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// GitLab's schema allows a megabyte here. Note files cap out at 64 KiB.
const MAX_DETAIL_CHARS: usize = 4000;

fn capped(text: &str, max: usize) -> String {
    let text = text.trim();
    match text.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text.to_string(),
    }
}

/// GitLab security reports (SAST, secret detection, dependency scanning), schema 15.
/// Dependency-scanning findings point at a manifest and package with no line and
/// get rejected. Pre-15 reports name the scanner per vulnerability and call the
/// title `message`.
fn parse_gitlab(doc: &Value) -> Parsed {
    let report_tool = str_at(doc, &["scan", "scanner", "name"])
        .or_else(|| str_at(doc, &["scan", "analyzer", "name"]))
        .unwrap_or("GitLab");
    let mut out = Parsed {
        ran: vec![report_tool.to_string()],
        ..Parsed::default()
    };
    for (i, v) in doc["vulnerabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let tool = str_at(v, &["scanner", "name"])
            .unwrap_or(report_tool)
            .to_string();
        if !out.tools.contains(&tool) {
            out.tools.push(tool.clone());
        }
        if !out.ran.contains(&tool) {
            out.ran.push(tool.clone());
        }
        // primary identifier comes first; that's the rule
        let ids: Vec<&Value> = v["identifiers"].as_array().into_iter().flatten().collect();
        let primary = ids.first();
        let rule = primary
            .and_then(|id| str_at(id, &["value"]).or_else(|| str_at(id, &["name"])))
            .unwrap_or("");
        let what = || format!("{tool} vulnerability {} ({rule})", i + 1);

        let loc = &v["location"];
        let Some(file) = str_at(loc, &["file"]) else {
            out.rejected.push(format!("{}: no file location", what()));
            continue;
        };
        let Some(start) = line(loc.get("start_line")) else {
            out.rejected.push(match loc.get("dependency") {
                Some(dep) => format!(
                    "{}: dependency {} {} in {file} has no line to attach to",
                    what(),
                    str_at(dep, &["package", "name"]).unwrap_or("(unnamed)"),
                    str_at(dep, &["version"]).unwrap_or("(no version)")
                ),
                None => format!("{}: {file} has no start line", what()),
            });
            continue;
        };
        let end = line(loc.get("end_line")).unwrap_or(start).max(start);

        let title = str_at(v, &["name"])
            .or_else(|| str_at(v, &["message"]))
            .or_else(|| primary.and_then(|id| str_at(id, &["name"])))
            .unwrap_or("Scanner finding");
        let mut message = title.lines().next().unwrap_or_default().to_string();
        if let Some(d) = str_at(v, &["description"]).filter(|d| !d.trim().is_empty()) {
            message.push_str("\n\n");
            message.push_str(&capped(d, MAX_DETAIL_CHARS));
        }
        if let Some(fix) = str_at(v, &["solution"]).filter(|d| !d.trim().is_empty()) {
            message.push_str("\n\nSolution: ");
            message.push_str(&capped(fix, MAX_DETAIL_CHARS));
        }
        for flag in v["flags"].as_array().into_iter().flatten() {
            if str_at(flag, &["type"]) == Some("flagged-as-likely-false-positive") {
                message.push_str(&format!(
                    "\n\nFlagged as a likely false positive by {}: {}",
                    str_at(flag, &["origin"]).unwrap_or("a scanner"),
                    capped(
                        str_at(flag, &["description"]).unwrap_or_default(),
                        MAX_DETAIL_CHARS
                    )
                ));
            }
        }
        let cwes: Vec<String> = ids
            .iter()
            .filter(|id| str_at(id, &["type"]).is_some_and(|t| t.eq_ignore_ascii_case("cwe")))
            .filter_map(|id| str_at(id, &["value"])?.trim().parse::<u32>().ok())
            .map(|n| format!("cwe-{n}"))
            .collect();
        let tags = note_tags(cwes.iter().map(String::as_str));
        out.findings.push(RawFinding {
            tool: tool.clone(),
            uri: file.to_string(),
            stripped: None,
            start_line: start,
            end_line: end,
            rule: rule.to_string(),
            message,
            level: str_at(v, &["severity"]).map(str::to_string),
            tags,
            flow: Vec::new(),
        });
    }
    out
}

fn parse_brakeman(doc: &Value) -> Parsed {
    let mut out = Parsed {
        tools: vec!["brakeman".into()],
        ran: vec!["brakeman".into()],
        ..Parsed::default()
    };
    for w in doc["warnings"].as_array().into_iter().flatten() {
        let kind = str_at(w, &["warning_type"]).unwrap_or("Warning");
        // Config-level warnings (e.g. an outdated Rails) have no file or line.
        let (Some(uri), Some(line)) = (str_at(w, &["file"]), line(w.get("line"))) else {
            let file = str_at(w, &["file"]).unwrap_or("no file");
            out.rejected.push(format!(
                "brakeman {kind} ({file}): no file and line to attach to"
            ));
            continue;
        };
        let message = match str_at(w, &["message"]) {
            Some(m) => format!("{kind}: {m}"),
            None => kind.to_string(),
        };
        let level = match str_at(w, &["confidence"]) {
            Some("High") => "error",
            Some("Medium") => "warning",
            _ => "note",
        };
        out.findings.push(RawFinding {
            tool: "brakeman".into(),
            uri: uri.to_string(),
            stripped: None,
            start_line: line,
            end_line: line,
            rule: str_at(w, &["check_name"]).unwrap_or("").to_string(),
            message,
            level: Some(level.into()),
            tags: Vec::new(),
            flow: Vec::new(),
        });
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

/// `file:` URIs and plain paths only
fn to_relative(store: &Store, uri: &str) -> Option<String> {
    if uri.starts_with("file:") {
        return store.relative(Path::new(&local_path(uri)?));
    }
    let decoded = percent_decode(uri)?;
    let rel = decoded.strip_prefix("./").unwrap_or(&decoded);
    if Path::new(rel).is_absolute() {
        return store.relative(Path::new(rel));
    }
    safety::is_relative_safe(rel).then(|| rel.to_string())
}

fn read_snippet(store: &Store, rel: &str, start: u32, end: u32) -> Result<Code, String> {
    let path = safety::confine(store.root(), rel).map_err(|e| e.to_string())?;
    let text =
        safety::read_limited(&path, MAX_SOURCE_BYTES, rel).map_err(|e| format!("{rel}: {e:#}"))?;
    anchor::code_at(&text, start, end)
        .ok_or_else(|| format!("{rel}:{start}: line is past the end of the file"))
}

struct Located {
    f: RawFinding,
    rel: String,
    code: Code,
    /// occurrence-0 fingerprint, see [`anchor::fingerprint`]
    base: String,
}

/// Semgrep prefixes rule ids with the config path (`rules.x` vs
/// `Users.me.rules.x`), so only the last segment identifies the rule.
fn rule_key(rule: &str) -> &str {
    rule.rsplit(['.', '/']).next().unwrap_or_default()
}

/// Reported, but the file couldn't be read (broken path, different checkout).
/// The note may still be valid. Never auto-resolve it.
struct Unlocated {
    tool: String,
    rule: String,
    paths: Vec<String>,
    name: String,
}

impl Unlocated {
    /// Deliberately loose (file name alone is enough). Better a note left open
    /// than one closed by mistake.
    fn may_be(&self, note: &Note) -> bool {
        let m = &note.meta;
        m.source.as_deref() == Some(self.tool.as_str())
            && rule_key(m.rule.as_deref().unwrap_or_default()) == self.rule
            && (self.paths.contains(&m.file) || m.file.rsplit('/').next() == Some(&self.name))
    }
}

/// Same tool and rule on a line where the note's code sits now. After an edit
/// the fingerprint won't match, yet the finding is still there.
fn still_reported(
    store: &Store,
    note: &Note,
    reported: &HashMap<(String, String, String), Vec<u32>>,
) -> bool {
    let m = &note.meta;
    let key = (
        m.source.clone().unwrap_or_default(),
        m.file.clone(),
        rule_key(m.rule.as_deref().unwrap_or_default()).to_string(),
    );
    let Some(lines) = reported.get(&key) else {
        return false;
    };
    let Ok(text) = store.read_source(&m.file) else {
        return false;
    };
    let anchor = anchor::locate_in(&m.snippet, m.context(), m.start_line, m.end_line, &text);
    let (start, end) = anchor.range();
    !anchor.is_stale() && lines.iter().any(|l| (start..=end).contains(l))
}

pub fn ingest(
    store: &Store,
    config: &Config,
    parsed: Parsed,
    options: Options,
) -> anyhow::Result<Summary> {
    let resolved_status = match options.resolve_missing {
        true => Some(config.resolved_status().context(
            "--resolve-missing needs `resolved_status` in config.toml: there is no `ok` status \
             to use",
        )?),
        false => None,
    };
    let mut summary = Summary {
        tools: parsed.tools,
        ignored: parsed.ignored,
        rejected: parsed.rejected,
        ..Summary::default()
    };
    let mut unlocated = Vec::new();
    let mut located = Vec::new();
    for f in parsed.findings {
        if !summary.tools.contains(&f.tool) {
            summary.tools.push(f.tool.clone());
        }
        let mut candidates: Vec<String> = Vec::new();
        for rel in [Some(f.uri.as_str()), f.stripped.as_deref()]
            .into_iter()
            .flatten()
            .filter_map(|uri| to_relative(store, uri))
        {
            if !candidates.contains(&rel) {
                candidates.push(rel);
            }
        }
        let name = f.uri.rsplit('/').next().and_then(percent_decode);
        let unlocated_here = |paths: Vec<String>| Unlocated {
            tool: f.tool.clone(),
            rule: rule_key(&f.rule).to_string(),
            paths,
            name: name.clone().unwrap_or_default(),
        };
        if candidates.is_empty() {
            unlocated.push(unlocated_here(Vec::new()));
            summary.rejected.push(format!(
                "{}: path outside the project or unsupported uri",
                f.uri
            ));
            continue;
        }
        let mut first_error = None;
        let mut found = None;
        for rel in &candidates {
            match read_snippet(store, rel, f.start_line, f.end_line) {
                Ok(code) => {
                    found = Some((rel.clone(), code));
                    break;
                }
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        let Some((rel, code)) = found else {
            unlocated.push(unlocated_here(candidates));
            summary.rejected.extend(first_error);
            continue;
        };
        let base = anchor::fingerprint(&rel, rule_key(&f.rule), &code.snippet, 0);
        located.push(Located { f, rel, code, base });
    }

    // Line order keeps occurrence numbers (0, 1, ...) stable across imports when
    // one rule hits identical code twice in a file. Same line reported twice
    // counts once.
    located
        .sort_by(|a, b| (&a.rel, a.f.start_line, &a.base).cmp(&(&b.rel, b.f.start_line, &b.base)));
    let before = located.len();
    located.dedup_by(|b, a| a.rel == b.rel && a.f.start_line == b.f.start_line && a.base == b.base);
    summary.skipped += before - located.len();

    let (existing, _) = store.load_all();
    let mut seen: HashSet<String> = existing
        .into_iter()
        .filter_map(|n| n.meta.fingerprint)
        .collect();
    let mut occurrences: HashMap<String, usize> = HashMap::new();
    let now = Utc::now().trunc_subsecs(0);
    let status = config.import_status().to_string();
    let mut present: HashSet<String> = HashSet::new();
    let mut reported: HashMap<(String, String, String), Vec<u32>> = HashMap::new();

    for Located { f, rel, code, base } in located {
        reported
            .entry((f.tool.clone(), rel.clone(), rule_key(&f.rule).to_string()))
            .or_default()
            .push(f.start_line);
        let n = occurrences.entry(base).or_default();
        let fp = anchor::fingerprint(&rel, rule_key(&f.rule), &code.snippet, *n);
        *n += 1;
        present.insert(fp.clone());
        if !seen.insert(fp.clone()) {
            summary.skipped += 1;
            continue;
        }

        let mut meta = Meta {
            id: store.new_id(&fp),
            file: rel,
            start_line: f.start_line,
            end_line: f.start_line,
            status: status.clone(),
            author: f.tool.clone(),
            created: now,
            source: Some(f.tool.clone()),
            rule: (!f.rule.is_empty()).then(|| f.rule.clone()),
            tags: f.tags.clone(),
            fingerprint: Some(fp),
            snippet: String::new(),
            context_before: None,
            context_after: None,
            extra: Default::default(),
        };
        meta.set(f.start_line, code);
        let note = Note {
            meta,
            body: imported_body(&f),
        };
        match store.save(&note) {
            Ok(_) => summary.imported += 1,
            Err(e) => summary.rejected.push(format!("saving note: {e:#}")),
        }
    }

    if let Some(status) = resolved_status {
        let mut resolved = Vec::new();
        for mut note in store.load_all().0 {
            let m = &note.meta;
            // this report's tools only, never hand-written notes
            let (Some(source), Some(fp)) = (m.source.clone(), &m.fingerprint) else {
                continue;
            };
            if !parsed.ran.contains(&source)
                || present.contains(fp)
                || m.status == status
                || unlocated.iter().any(|u| u.may_be(&note))
                || still_reported(store, &note, &reported)
            {
                continue;
            }
            note.meta.status = status.to_string();
            note.history(&format!("Not reported by {}", md_escape(&source)));
            let m = &note.meta;
            match store.save(&note) {
                Ok(_) => resolved.push(format!(
                    "{} {}:{} {}",
                    m.id,
                    m.file,
                    m.start_line,
                    note.plain_title()
                )),
                Err(e) => summary
                    .rejected
                    .push(format!("saving note {}: {e:#}", m.id)),
            }
        }
        summary.resolved = Some(resolved);
    }
    Ok(summary)
}

fn imported_body(f: &RawFinding) -> String {
    let mut lines = f.message.trim().lines();
    let title = lines.next().unwrap_or("Scanner finding");
    let rest = lines.collect::<Vec<_>>().join("\n");
    let mut body = format!("# {}\n\n", md_escape(title));
    if !rest.trim().is_empty() {
        body.push_str(&md_escape(rest.trim()));
        body.push_str("\n\n");
    }
    if !f.flow.is_empty() {
        body.push_str("Data flow:\n\n");
        for (i, step) in f.flow.iter().take(MAX_FLOW_STEPS).enumerate() {
            // code span, so a report path can't become a link
            body.push_str(&format!("{}. {}", i + 1, inline_code(&step.location)));
            if let Some(m) = &step.message {
                body.push_str(&format!(" — {}", md_escape(m)));
            }
            body.push('\n');
        }
        if let Some(more) = f.flow.len().checked_sub(MAX_FLOW_STEPS).filter(|&n| n > 0) {
            body.push_str(&format!("\n_{more} more steps not shown._\n"));
        }
        body.push('\n');
    }
    body.push_str(&format!("Imported from {}", md_escape(&f.tool)));
    if !f.rule.is_empty() {
        body.push_str(&format!(", rule {}", inline_code(&f.rule)));
    }
    if let Some(level) = &f.level {
        body.push_str(&format!(", level {}", md_escape(level)));
    }
    body.push('.');
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn project() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("app")).unwrap();
        fs::write(
            dir.path().join("app/users.py"),
            "import db\n\ndef show(id):\n    return db.query(f\"select * from users where id={id}\")\n",
        )
        .unwrap();
        let store = Store::new(dir.path());
        (dir, store)
    }

    fn sarif(uri: &str) -> String {
        format!(
            r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"semgrep","rules":[{{"id":"sqli"}}]}}}},
            "results":[{{"ruleId":"sqli","level":"error","message":{{"text":"SQL built with f-string ](http://evil)"}},
            "locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"{uri}"}},"region":{{"startLine":3,"endLine":4}}}}}}]}}]}}]}}"#
        )
    }

    #[test]
    fn recognises_reports_only() {
        for (text, want) in [
            (r#"{"version": "2.1.0", "runs": []}"#, true),
            (r#"{"scan_info": {}, "warnings": [{"x": 1}]}"#, true),
            (r#"{"name": "app", "dependencies": {}}"#, false),
            (r#"{"runs": "nope"}"#, false),
            (r#"{"warnings": null}"#, false),
            (
                r#"{"version": "15.2.5", "scan": {"type": "sast"}, "vulnerabilities": []}"#,
                true,
            ),
            (r#"{"vulnerabilities": []}"#, false),
            // npm audit: vulnerabilities by package name.
            (
                r#"{"auditReportVersion": 2, "vulnerabilities": {}, "scan": {}}"#,
                false,
            ),
            (r#"{"vulnerabilities": [], "scan": []}"#, false),
            (r#"{"runs": [], "warnings": 3}"#, true),
            (r#"{"warnings": [], "runs": "x"}"#, true),
            (r#"[[1], [2], [3], {}]"#, false),
            (r#""runs""#, false),
            ("[1, 2]", false),
            ("not json", false),
        ] {
            assert_eq!(is_report(text), want, "{text}");
            assert_eq!(parse(text).is_ok(), want, "{text}");
        }
    }

    #[test]
    fn imports_and_reimport_is_noop() {
        let (_d, store) = project();
        let s = import_text(&store, &Config::default(), &sarif("app/users.py")).unwrap();
        assert_eq!((s.imported, s.skipped, s.rejected.len()), (1, 0, 0), "{s}");
        let (notes, _) = store.load_all();
        let n = &notes[0];
        assert_eq!((n.meta.start_line, n.meta.end_line), (3, 4));
        assert_eq!(n.meta.status, "open");
        assert!(n.meta.snippet.contains("db.query"));
        assert!(n.body.contains(r"\]\(http://evil\)"), "{}", n.body);

        // Reviewer marks it, then the same report is imported again.
        let mut marked = n.clone();
        marked.meta.status = "issue".into();
        store.save(&marked).unwrap();
        let s = import_text(&store, &Config::default(), &sarif("app/users.py")).unwrap();
        assert_eq!((s.imported, s.skipped), (0, 1));
        let (notes, _) = store.load_all();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].meta.status, "issue");
    }

    #[test]
    fn rejects_escaping_and_foreign_uris() {
        let (_d, store) = project();
        for uri in [
            "../../../etc/passwd",
            "/etc/passwd",
            "http://evil/x.py",
            "file:///etc/passwd",
            "data:,x",
        ] {
            let s = import_text(&store, &Config::default(), &sarif(uri)).unwrap();
            assert_eq!((s.imported, s.rejected.len()), (0, 1), "{uri}");
        }
        assert!(store.load_all().0.is_empty());
    }

    #[test]
    fn file_uri_inside_project_is_accepted() {
        let (_d, store) = project();
        let abs = store.root().join("app/users.py");
        let s = import_text(
            &store,
            &Config::default(),
            &sarif(&format!("file://{}", abs.display())),
        )
        .unwrap();
        assert_eq!(s.imported, 1, "{s:?}");
    }

    #[test]
    fn brakeman() {
        let doc = r#"{"scan_info":{},"warnings":[{"warning_type":"SQL Injection","check_name":"SQL",
            "message":"Possible SQL injection","file":"app/models/user.rb","line":12,"confidence":"High"}]}"#;
        let f = parse(doc).unwrap().findings;
        assert_eq!(f[0].uri, "app/models/user.rb");
        assert_eq!((f[0].start_line, f[0].end_line), (12, 12));
        assert_eq!(f[0].rule, "SQL");
        assert_eq!(f[0].level.as_deref(), Some("error"));
    }

    #[test]
    fn unlocated_results_are_rejected_not_dropped() {
        let (_d, store) = project();
        let doc = r#"{"runs":[{"tool":{"driver":{"name":"t"}},"results":[
            {"ruleId":"a","message":{"text":"no location"}},
            {"ruleId":"b","message":{"text":"no region"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/users.py"}}}]}
        ]}]}"#;
        let s = import_text(&store, &Config::default(), doc).unwrap();
        assert_eq!((s.imported, s.rejected.len()), (0, 2), "{:?}", s.rejected);

        let doc = r#"{"warnings":[{"warning_type":"Unmaintained Dependency","check_name":"EOLRails",
            "message":"Support for Rails 5.0 ended","file":"Gemfile.lock","line":null}]}"#;
        let s = import_text(&store, &Config::default(), doc).unwrap();
        assert_eq!((s.imported, s.rejected.len()), (0, 1), "{:?}", s.rejected);
    }

    #[test]
    fn same_rule_on_identical_lines_is_two_findings() {
        let (dir, store) = project();
        fs::write(dir.path().join("app/e.py"), "eval(x)\nfoo()\neval(x)\n").unwrap();
        let result = |line| {
            format!(
                r#"{{"ruleId":"eval","message":{{"text":"eval"}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"app/e.py"}},"region":{{"startLine":{line}}}}}}}]}}"#
            )
        };
        // last result repeats the first
        let doc = format!(
            r#"{{"runs":[{{"tool":{{"driver":{{"name":"t"}}}},"results":[{},{},{}]}}]}}"#,
            result(3),
            result(1),
            result(3)
        );
        let s = import_text(&store, &Config::default(), &doc).unwrap();
        assert_eq!((s.imported, s.skipped), (2, 1), "{s}");
        let s = import_text(&store, &Config::default(), &doc).unwrap();
        assert_eq!((s.imported, s.skipped), (0, 3), "{s}");
        let mut lines: Vec<u32> = store
            .load_all()
            .0
            .iter()
            .map(|n| n.meta.start_line)
            .collect();
        lines.sort();
        assert_eq!(lines, [1, 3]);
    }

    #[test]
    fn message_formatting() {
        assert_eq!(format_message("{0} to {1}", &["a", "b"]), "a to b");
        assert_eq!(format_message("{{0}} {2} {x}", &["a"]), "{0} {2} {x}");
        assert_eq!(format_message("tail {", &[]), "tail {");
        assert_eq!(format_message("} {0} }", &["a"]), "} a }");
        assert_eq!(
            strip_location_links(r"a [user value](1) \[0\] [x](http://e) [not](a) [y](12)"),
            r"a user value [0] [x](http://e) [not](a) y"
        );
        assert_eq!(strip_location_links("[unclosed](3"), "[unclosed](3");
        // An escaped `]` does not end the label.
        assert_eq!(strip_location_links(r"see [arr\](0)"), "see [arr](0)");
        assert_eq!(strip_location_links(r"[a\]b](1) [c\[d](2)"), "a]b c[d");
        assert_eq!(strip_location_links("é [ü](0) é"), "é ü é");
    }

    #[test]
    fn message_helpers_never_panic() {
        let alphabet = ['{', '}', '[', ']', '(', ')', '\\', '0', 'é', 'a'];
        let n = alphabet.len();
        for mut i in 0..n.pow(5) {
            let mut text = String::new();
            for _ in 0..5 {
                text.push(alphabet[i % n]);
                i /= n;
            }
            format_message(&text, &["x"]);
            strip_location_links(&text);
        }
    }

    #[test]
    fn uri_base_chains_and_loops() {
        let run: Value = serde_json::from_str(
            r#"{"originalUriBaseIds":{
                "A":{"uri":"file:///r/"},"B":{"uri":"sub/","uriBaseId":"A"},
                "X":{"uri":"x/","uriBaseId":"Y"},"Y":{"uri":"y/","uriBaseId":"X"},
                "NONE":{"description":{"text":"set by the user"}}}}"#,
        )
        .unwrap();
        assert_eq!(resolve_uri(&run, "f.py", Some("B")), "file:///r/sub/f.py");
        assert_eq!(resolve_uri(&run, "f.py", Some("NONE")), "f.py");
        assert_eq!(resolve_uri(&run, "f.py", Some("MISSING")), "f.py");
        assert_eq!(resolve_uri(&run, "/abs/f.py", Some("A")), "/abs/f.py");
        // only needs to terminate
        assert!(resolve_uri(&run, "f.py", Some("X")).ends_with("f.py"));
        assert_eq!(report_roots(&run)[0], "/r/sub/");
    }

    #[test]
    fn stripped_root_cannot_escape() {
        let roots = ["/ci/work/proj".to_string()];
        assert_eq!(
            strip_root("file:///ci/work/proj/app/users.py", &roots).as_deref(),
            Some("app/users.py")
        );
        assert_eq!(strip_root("/ci/work/projx/a.py", &roots), None);
        assert_eq!(strip_root("app/users.py", &roots), None);
        let (_d, store) = project();
        let escape = strip_root("/ci/work/proj/../../../etc/passwd", &roots).unwrap();
        assert_eq!(to_relative(&store, &escape), None);
    }

    #[test]
    fn report_from_another_machine() {
        let (_d, store) = project();
        let doc = r#"{"runs":[{"tool":{"driver":{"name":"t"}},
            "invocations":[{"workingDirectory":{"uri":"file:///ci/w%20s/"}}],
            "results":[{"ruleId":"a","message":{"text":"m"},"locations":[{"physicalLocation":
              {"artifactLocation":{"uri":"file:///ci/w%20s/app/users.py"},"region":{"startLine":3}}}]}]}]}"#;
        let s = import_text(&store, &Config::default(), doc).unwrap();
        assert_eq!((s.imported, s.rejected.len()), (1, 0), "{:?}", s.rejected);
        assert_eq!(store.load_all().0[0].meta.file, "app/users.py");
    }

    #[test]
    fn rules_found_wherever_the_report_keeps_them() {
        let run: Value = serde_json::from_str(
            r#"{"tool":{"driver":{"name":"d","rules":[{"id":"d0"},{"id":"d1"}]},
                "extensions":[{"name":"pack","guid":"g1","rules":[{"id":"e0","defaultConfiguration":{"level":"note"}}]}]}}"#,
        )
        .unwrap();
        let id = |result: &str| {
            let result: Value = serde_json::from_str(result).unwrap();
            RuleIndex::new(&run)
                .entry(&run, &result)
                .and_then(|r| str_at(r, &["id"]).map(str::to_string))
        };
        assert_eq!(id(r#"{"ruleIndex":1}"#).as_deref(), Some("d1"));
        assert_eq!(
            id(r#"{"ruleId":"e0","rule":{"index":0,"toolComponent":{"index":0}}}"#).as_deref(),
            Some("e0")
        );
        assert_eq!(
            id(r#"{"rule":{"index":0,"toolComponent":{"name":"pack"}}}"#).as_deref(),
            Some("e0")
        );
        assert_eq!(
            id(r#"{"rule":{"index":0,"toolComponent":{"guid":"g1"}}}"#).as_deref(),
            Some("e0")
        );
        // index into the wrong list; id mismatch, falls back to id lookup
        assert_eq!(
            id(r#"{"ruleId":"e0","ruleIndex":0}"#).as_deref(),
            Some("e0")
        );
        assert_eq!(id(r#"{"ruleId":"d1/sub"}"#).as_deref(), Some("d1"));
        assert_eq!(id(r#"{"ruleId":"d"}"#), None);
        assert_eq!(id(r#"{"ruleId":"nope","ruleIndex":0}"#), None);
    }

    #[test]
    fn live_failures() {
        let live = |r: &str| is_live_failure(&serde_json::from_str(r).unwrap());
        assert!(live(r#"{}"#));
        assert!(live(r#"{"kind":"fail","baselineState":"new"}"#));
        assert!(live(r#"{"kind":"informational"}"#));
        assert!(live(
            r#"{"suppressions":[{"kind":"inSource","status":"rejected"}]}"#
        ));
        assert!(live(
            r#"{"suppressions":[{"kind":"inSource","status":"underReview"}]}"#
        ));
        assert!(live(r#"{"suppressions":[]}"#));
        assert!(!live(r#"{"suppressions":[{"kind":"external"}]}"#));
        assert!(!live(
            r#"{"suppressions":[{"kind":"external","status":"accepted"}]}"#
        ));
        assert!(!live(r#"{"kind":"pass"}"#));
        assert!(!live(r#"{"kind":"notApplicable"}"#));
        assert!(!live(r#"{"baselineState":"absent"}"#));
    }

    #[test]
    fn first_located_location_wins() {
        let (_d, store) = project();
        let doc = r#"{"runs":[{"tool":{"driver":{"name":"t"}},"results":[{"ruleId":"a","message":{"text":"m"},
            "locations":[{"logicalLocations":[{"name":"f"}]},
              {"physicalLocation":{"artifactLocation":{"uri":"app/users.py"}}},
              {"physicalLocation":{"artifactLocation":{"uri":"app/users.py"},"region":{"startLine":4}}}]}]}]}"#;
        let s = import_text(&store, &Config::default(), doc).unwrap();
        assert_eq!(s.imported, 1, "{s}");
        assert_eq!(store.load_all().0[0].meta.start_line, 4);
    }

    #[test]
    fn exact_rule_id_beats_a_rule_it_refines() {
        let run: Value = serde_json::from_str(
            r#"{"tool":{"driver":{"name":"d","rules":[{"id":"js"},{"id":"js/xss"}]},
                "extensions":[{"rules":[{"id":"js/xss/dom"}]}]}}"#,
        )
        .unwrap();
        let rules = RuleIndex::new(&run);
        let id = |rule_id: &str| {
            let result = json!({ "ruleId": rule_id });
            rules
                .entry(&run, &result)
                .and_then(|r| str_at(r, &["id"]))
                .map(str::to_string)
        };
        assert_eq!(id("js/xss").as_deref(), Some("js/xss"));
        assert_eq!(id("js/xss/dom").as_deref(), Some("js/xss/dom"));
        assert_eq!(id("js/xss/other").as_deref(), Some("js/xss"));
        assert_eq!(id("js/sqli").as_deref(), Some("js"));
        assert_eq!(id("jsx"), None);
    }

    #[test]
    fn stripped_path_is_tried_when_the_given_one_is_missing() {
        // The project sits at what the report calls the parent of its root,
        // as in GitHub Actions' `/home/runner/work/<repo>/<repo>` layout.
        let (dir, store) = project();
        let root = store.root().canonicalize().unwrap();
        let root = root.to_str().unwrap();
        fs::create_dir_all(dir.path().join("demo")).unwrap();
        let doc = format!(
            r#"{{"runs":[{{"tool":{{"driver":{{"name":"t"}}}},
            "originalUriBaseIds":{{"SRC":{{"uri":"file://{root}/demo/"}}}},
            "results":[{{"ruleId":"a","message":{{"text":"m"}},"locations":[{{"physicalLocation":
              {{"artifactLocation":{{"uri":"file://{root}/demo/app/users.py"}},"region":{{"startLine":3}}}}}}]}}]}}]}}"#
        );
        let s = import_text(&store, &Config::default(), &doc).unwrap();
        assert_eq!((s.imported, s.rejected.len()), (1, 0), "{:?}", s.rejected);
        assert_eq!(store.load_all().0[0].meta.file, "app/users.py");
    }

    #[test]
    fn shallow_roots_are_not_trusted() {
        let run: Value = serde_json::from_str(
            r#"{"originalUriBaseIds":{"ROOT":{"uri":"file:///"},"HOME":{"uri":"file:///home/"},
                "TOOL":{"uri":"file:///opt/tool/"}},
              "invocations":[{"workingDirectory":{"uri":"file:///"}}]}"#,
        )
        .unwrap();
        assert_eq!(report_roots(&run), ["/opt/tool/"]);
        assert_eq!(strip_root("/etc/passwd", &report_roots(&run)), None);
    }

    #[test]
    fn location_inherits_the_artifacts_base() {
        let run: Value = serde_json::from_str(
            r#"{"originalUriBaseIds":{"SUB":{"uri":"sub/"}},
              "artifacts":[{"location":{"uri":"a.py","uriBaseId":"SUB"}}]}"#,
        )
        .unwrap();
        let uri = |al: Value| artifact_uri(&run, &al);
        assert_eq!(uri(json!({"index":0})).as_deref(), Some("sub/a.py"));
        assert_eq!(
            uri(json!({"uri":"a.py","index":0})).as_deref(),
            Some("sub/a.py")
        );
        // not the artifact's file, its base doesn't apply
        assert_eq!(
            uri(json!({"uri":"b.py","index":0})).as_deref(),
            Some("b.py")
        );
        assert_eq!(uri(json!({"uri":"a.py"})).as_deref(), Some("a.py"));
    }

    #[test]
    fn file_uri_forms() {
        for (uri, want) in [
            ("file:///ci/a.py", Some("/ci/a.py")),
            ("file:/ci/a.py", Some("/ci/a.py")),
            ("file://localhost/ci/a%20b.py", Some("/ci/a b.py")),
            ("file://LOCALHOST/ci/a.py", Some("/ci/a.py")),
            ("file://evil.example/ci/a.py", None),
            ("file://localhost", None),
            ("file:relative.py", None),
            ("/ci/a.py", Some("/ci/a.py")),
            ("ci/a.py", None),
        ] {
            assert_eq!(local_path(uri).as_deref(), want, "{uri}");
        }
    }

    #[test]
    fn deep_base_chains_resolve() {
        let mut bases = serde_json::Map::new();
        bases.insert("B0".into(), json!({"uri": "file:///r/"}));
        for i in 1..20 {
            bases.insert(
                format!("B{i}"),
                json!({"uri": format!("d{i}/"), "uriBaseId": format!("B{}", i - 1)}),
            );
        }
        let run = json!({ "originalUriBaseIds": bases });
        let uri = resolve_uri(&run, "f.py", Some("B19"));
        assert!(uri.starts_with("file:///r/d1/d2/"), "{uri}");
        assert!(uri.ends_with("/d19/f.py"), "{uri}");
    }

    fn gitlab(vulnerabilities: Value) -> String {
        json!({
            "version": "15.2.5",
            "scan": {"type": "sast", "scanner": {"id": "s", "name": "Semgrep"}},
            "vulnerabilities": vulnerabilities,
        })
        .to_string()
    }

    #[test]
    fn gitlab_vulnerabilities() {
        let doc = gitlab(json!([
            {"id": "1", "name": "SQL injection [x](http://evil)", "description": "Long\ntext",
             "severity": "High",
             "identifiers": [
                {"type": "semgrep_id", "name": "SQL rule", "value": "python_sql_rule-x"},
                {"type": "cwe", "name": "CWE-89", "value": "89"},
                {"type": "CWE", "name": "CWE-20", "value": " 20 "},
                {"type": "cwe", "name": "bad", "value": "89](http://evil)"},
                {"type": "owasp", "name": "A03:2021 - Injection", "value": "A03:2021"}],
             "location": {"file": "app/users.py", "start_line": 3, "end_line": 4}},
            {"id": "2", "message": "Older reports: message, scanner per finding",
             "scanner": {"id": "old", "name": "Old Tool"},
             "identifiers": [{"type": "x", "name": "Rule name", "value": "r"}],
             "location": {"file": "app/users.py", "start_line": 4}},
            {"id": "3", "name": "Django", "identifiers": [{"type": "cve", "name": "CVE-1", "value": "CVE-1"}],
             "location": {"file": "requirements.txt",
                          "dependency": {"package": {"name": "Django"}, "version": "3.2.0"}}},
            {"id": "4", "name": "No line", "identifiers": [{"type": "x", "name": "n", "value": "n"}],
             "location": {"file": "app/users.py"}},
            {"id": "5", "name": "No file", "identifiers": [{"type": "x", "name": "n", "value": "n"}],
             "location": {}}
        ]));
        let p = parse(&doc).unwrap();
        assert_eq!(p.tools, ["Semgrep", "Old Tool"]);
        let f = &p.findings;
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].start_line, f[0].end_line), (3, 4));
        assert_eq!(f[0].rule, "python_sql_rule-x");
        assert_eq!(f[0].level.as_deref(), Some("High"));
        assert_eq!(f[0].tags, ["cwe-89", "cwe-20"]);
        assert!(
            f[0].message
                .starts_with("SQL injection [x](http://evil)\n\nLong\ntext")
        );
        assert_eq!((f[1].tool.as_str(), f[1].end_line), ("Old Tool", 4));
        assert!(f[1].message.starts_with("Older reports"));
        assert_eq!(p.rejected.len(), 3, "{:?}", p.rejected);
        assert!(
            p.rejected[0].contains("dependency Django 3.2.0 in requirements.txt has no line"),
            "{:?}",
            p.rejected
        );
        assert!(p.rejected[1].ends_with("app/users.py has no start line"));
        assert!(p.rejected[2].ends_with("no file location"));

        let (_d, store) = project();
        let s = import_text(&store, &Config::default(), &doc).unwrap();
        assert_eq!((s.imported, s.rejected.len()), (2, 3), "{s}");
        let note = store
            .load_all()
            .0
            .into_iter()
            .find(|n| n.meta.start_line == 3)
            .unwrap();
        assert!(
            note.body
                .starts_with(r"# SQL injection \[x\]\(http://evil\)"),
            "{}",
            note.body
        );
        assert!(note.body.contains("level High."), "{}", note.body);
    }

    #[test]
    fn gitlab_paths_are_confined() {
        let (_d, store) = project();
        for file in [
            "../../../etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "app/../../x.py",
        ] {
            let doc = gitlab(json!([{"id": "1", "name": "x",
                "identifiers": [{"type": "x", "name": "n", "value": "n"}],
                "location": {"file": file, "start_line": 1}}]));
            let s = import_text(&store, &Config::default(), &doc).unwrap();
            assert_eq!((s.imported, s.rejected.len()), (0, 1), "{file}");
        }
        assert!(store.load_all().0.is_empty());
    }

    #[test]
    fn long_details_are_capped() {
        let long = "é".repeat(MAX_DETAIL_CHARS + 10);
        let capped = capped(&long, MAX_DETAIL_CHARS);
        assert_eq!(capped.chars().count(), MAX_DETAIL_CHARS + 1);
        assert!(capped.ends_with('…'));
        assert_eq!(super::capped(" short ", 10), "short");
    }

    fn report(tool: &str, results: &[(&str, &str, u32)]) -> String {
        let results: Vec<Value> = results
            .iter()
            .map(|(rule, uri, line)| {
                json!({"ruleId": rule, "message": {"text": format!("{rule} here")},
                       "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                           "region": {"startLine": line}}}]})
            })
            .collect();
        json!({"runs": [{"tool": {"driver": {"name": tool}}, "results": results}]}).to_string()
    }

    #[test]
    fn resolve_missing() {
        let (_d, store) = project();
        let config = Config::default();
        let resolve = Options {
            resolve_missing: true,
        };
        let import = |doc: &str, options| import_text_with(&store, &config, doc, options).unwrap();
        let all = [
            ("sqli", "app/users.py", 4),
            ("def", "app/users.py", 3),
            ("imp", "app/users.py", 1),
        ];
        import(&report("t", &all), Options::default());
        import(
            &report("other", &[("sqli", "app/users.py", 3)]),
            Options::default(),
        );
        let text = fs::read_to_string(store.root().join("app/users.py")).unwrap();
        let by_hand = Note::new_on(
            store.new_id("h"),
            "app/users.py".into(),
            &text,
            4,
            4,
            "note",
            "me".into(),
            "# Mine".into(),
        )
        .unwrap();
        store.save(&by_hand).unwrap();
        let notes = || store.load_all().0;
        let find = |tool: &str, rule: &str| {
            notes()
                .into_iter()
                .find(|n| {
                    n.meta.source.as_deref() == Some(tool) && n.meta.rule.as_deref() == Some(rule)
                })
                .unwrap()
        };
        // already OK, no history line
        let mut ok = find("t", "imp");
        ok.meta.status = "ok".into();
        store.save(&ok).unwrap();

        // no option, nothing resolved
        let s = import(&report("t", &all[..1]), Options::default());
        assert_eq!(s.resolved, None);
        assert!(!s.to_string().contains("resolved"));
        assert!(
            notes()
                .iter()
                .all(|n| n.meta.status != "ok" || n.meta.id == ok.meta.id)
        );

        // `def` is gone. `sqli` has a broken path now but might still exist; keep it.
        let s = import(
            &report(
                "t",
                &[("sqli", "elsewhere/users.py", 4), ("x", "app/users.py", 9)],
            ),
            resolve,
        );
        assert_eq!(s.resolved.as_ref().map(Vec::len), Some(1), "{s}");
        assert!(
            s.to_string().ends_with(", resolved 1 (no longer reported)"),
            "{s}"
        );
        assert_eq!(s.rejected.len(), 2, "{:?}", s.rejected);
        let def = find("t", "def");
        assert_eq!(def.meta.status, "ok");
        assert!(
            def.body.ends_with(&format!(
                "_Not reported by t on {}._",
                Utc::now().format("%Y-%m-%d")
            )),
            "{}",
            def.body
        );
        assert_eq!(find("t", "sqli").meta.status, "open");
        assert_eq!(find("t", "imp"), ok);
        assert_eq!(find("other", "sqli").meta.status, "open");
        let mine = store.load(&by_hand.meta.id).unwrap();
        assert_eq!(mine, by_hand);

        // A clean scan resolves the rest of that tool's findings.
        let s = import(&report("t", &[]), resolve);
        assert_eq!(s.resolved.as_ref().map(Vec::len), Some(1), "{s}");
        assert_eq!(find("t", "sqli").meta.status, "ok");
        assert_eq!(find("other", "sqli").meta.status, "open");
        assert_eq!(store.load(&by_hand.meta.id).unwrap(), by_hand);
        // idempotent
        let s = import(&report("t", &[]), resolve);
        assert_eq!(s.resolved, Some(Vec::new()));
    }

    #[test]
    fn resolve_missing_keeps_a_finding_on_edited_code() {
        let (dir, store) = project();
        let config = Config::default();
        let resolve = Options {
            resolve_missing: true,
        };
        import_text(
            &store,
            &config,
            &report("t", &[("sqli", "app/users.py", 4)]),
        )
        .unwrap();
        let mut triaged = store.load_all().0.remove(0);
        triaged.mark("issue", "Issue", "me");
        store.save(&triaged).unwrap();
        // The flagged line is edited; the scanner still flags it.
        let path = dir.path().join("app/users.py");
        let text = fs::read_to_string(&path).unwrap().replace("{id}", "{uid}");
        fs::write(&path, text).unwrap();
        // Another rule on that line is not this finding.
        let other = report("t", &[("other", "app/users.py", 4)]);
        let s = import_text_with(&store, &config, &other, resolve).unwrap();
        assert_eq!(s.resolved.as_ref().map(Vec::len), Some(1), "{s}");
        store.save(&triaged).unwrap();
        let s = import_text_with(
            &store,
            &config,
            &report("t", &[("sqli", "app/users.py", 4)]),
            resolve,
        )
        .unwrap();
        // Only the `other` finding from the step before is resolved.
        let resolved = s.resolved.unwrap();
        assert!(
            resolved.len() == 1 && resolved[0].ends_with("other here"),
            "{resolved:?}"
        );
        assert_eq!(store.load(&triaged.meta.id).unwrap(), triaged);
    }

    #[test]
    fn resolve_missing_needs_a_status() {
        let (_d, store) = project();
        let config: Config =
            toml::from_str("[[status]]\nid = \"todo\"\nlabel = \"TODO\"\nseverity = \"warning\"\n")
                .unwrap();
        let options = Options {
            resolve_missing: true,
        };
        let err = import_text_with(&store, &config, &report("t", &[]), options).unwrap_err();
        assert!(err.to_string().contains("resolved_status"), "{err}");
    }

    #[test]
    fn data_flow_is_listed_escaped_and_capped() {
        let (_d, store) = project();
        let step = |uri: &str, line: u32, text: &str| {
            json!({"location": {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}},
                                "message": {"text": text}}})
        };
        let mut steps = vec![
            step(
                "[x](http://evil)",
                1,
                "**user** input [here](http://evil) <b>",
            ),
            step("a`b`.py", 2, "multi\nline   text"),
            step("file:///ci/work/proj/app/users.py", 3, "[the value](0)"),
            json!({"location": {"message": {"text": "nowhere"}}}),
        ];
        steps.extend((0..19).map(|i| step("app/users.py", 4, &format!("step {i}"))));
        let doc = json!({"runs": [{"tool": {"driver": {"name": "t"}},
            "originalUriBaseIds": {"SRC": {"uri": "file:///ci/work/proj/"}},
            "results": [{"ruleId": "sqli", "message": {"text": "SQL"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/users.py"}, "region": {"startLine": 4}}}],
                "codeFlows": [{"threadFlows": [{"locations": steps}, {"locations": [step("second.py", 1, "ignored")]}]},
                              {"threadFlows": [{"locations": [step("other.py", 1, "ignored")]}]}]}]}]});
        let s = import_text(&store, &Config::default(), &doc.to_string()).unwrap();
        assert_eq!(s.imported, 1, "{s}");
        let body = &store.load_all().0[0].body;
        assert!(
            body.contains(
                "Data flow:\n\n\
                 1. `[x](http://evil):1` — \\*\\*user\\*\\* input \\[here\\]\\(http://evil\\) \\<b\\>\n\
                 2. ``a`b`.py:2`` — multi line text\n\
                 3. `app/users.py:3` — the value\n\
                 4. `(no location)` — nowhere\n"
            ),
            "{body}"
        );
        assert!(
            body.contains("\n20. `app/users.py:4` — step 15\n\n_3 more steps not shown._\n"),
            "{body}"
        );
        assert!(
            !body.contains("step 16") && !body.contains("ignored"),
            "{body}"
        );
        assert!(body.ends_with("Imported from t, rule `sqli`."), "{body}");
    }

    #[test]
    fn unknown_format_explains_how_to_get_sarif() {
        let err = parse(r#"{"results":[]}"#).unwrap_err().to_string();
        assert!(err.contains("semgrep --sarif"));
    }
}
