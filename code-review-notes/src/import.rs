//! Turning scanner output into review notes (with the default status).
//!
//! Parsers only produce [`RawFinding`]s; all filesystem access (confining the
//! path, reading the snippet) happens once, in [`ingest`].

use anyhow::{Context, bail};
use chrono::{SubsecRound, Utc};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::anchor;
use crate::config::Config;
use crate::markdown::{inline_code, md_escape};
use crate::note::{Meta, Note};
use crate::safety::{self, MAX_IMPORT_BYTES, MAX_SOURCE_BYTES};
use crate::store::Store;

#[derive(Debug, Clone, PartialEq)]
pub struct RawFinding {
    pub tool: String,
    /// As given by the scanner; validated in `ingest`.
    pub uri: String,
    /// `uri` made relative to a root the report names (its source root or
    /// working directory), for reports written on another machine. Tried when
    /// `uri` itself is not in the project; validated the same way.
    pub stripped: Option<String>,
    pub start_line: u32,
    pub end_line: u32,
    pub rule: String,
    pub message: String,
    pub level: Option<String>,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub tools: Vec<String>,
    pub imported: usize,
    pub skipped: usize,
    /// Suppressed, or not a failure (`pass`, `notApplicable`, fixed since the baseline).
    pub ignored: usize,
    pub rejected: Vec<String>,
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
        )
    }
}

const FORMAT_HINT: &str = "expected SARIF or brakeman JSON. Ask your scanner for SARIF: \
    `semgrep --sarif`, `codeql database analyze --format=sarif-latest`, \
    `snyk code test --sarif-file-output=FILE`, `bandit -f sarif`, `gosec -fmt sarif`, `checkov -o sarif`, `brakeman -f json`";

pub fn import_file(store: &Store, config: &Config, path: &Path) -> anyhow::Result<Summary> {
    let text = safety::read_limited(path, MAX_IMPORT_BYTES, "scanner report")
        .with_context(|| format!("reading {}", path.display()))?;
    import_text(store, config, &text)
}

pub fn import_text(store: &Store, config: &Config, text: &str) -> anyhow::Result<Summary> {
    Ok(ingest(store, config, parse(text)?))
}

/// What a parser got out of a report: usable findings, and a reason for each
/// result that could not become a note (no file, no line).
#[derive(Debug, Default)]
pub struct Parsed {
    /// Every tool with results in the report, even if none became a finding.
    pub tools: Vec<String>,
    pub findings: Vec<RawFinding>,
    pub ignored: usize,
    pub rejected: Vec<String>,
}

pub fn parse(text: &str) -> anyhow::Result<Parsed> {
    let doc: Value =
        serde_json::from_str(text).with_context(|| format!("not valid JSON; {FORMAT_HINT}"))?;
    if doc.get("runs").is_some_and(Value::is_array) {
        Ok(parse_sarif(&doc))
    } else if doc.get("warnings").is_some_and(Value::is_array) {
        Ok(parse_brakeman(&doc))
    } else {
        bail!("unrecognised report format; {FORMAT_HINT}")
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

/// Follows SARIF 2.1.0 (§3 refers to its sections) for the parts that place a
/// finding on a line and describe it; everything else in the report is ignored.
fn parse_sarif(doc: &Value) -> Parsed {
    let mut out = Parsed::default();
    for run in doc["runs"].as_array().into_iter().flatten() {
        let tool = str_at(run, &["tool", "driver", "name"])
            .unwrap_or("sarif")
            .to_string();
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

            // The first location that has both a file and a line (§3.27.12).
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
            });
        }
    }
    out
}

/// Not suppressed (§3.27.23, §3.35.3), still present (§3.27.24) and a failure
/// (§3.27.9). `informational` and `review` results are kept for the reviewer.
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

/// `uri` resolved against `base` through `originalUriBaseIds`, whose entries
/// may themselves be relative to another base (§3.14.14). An unknown base
/// leaves `uri` relative, which is what most reports intend: the project root.
fn resolve_uri(run: &Value, uri: &str, base: Option<&str>) -> String {
    let mut uri = uri.to_string();
    let mut base = base.map(str::to_string);
    // Each base once, so a report whose bases refer to each other cannot loop.
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

/// The file an `artifactLocation` names, directly or through `run.artifacts`
/// (§3.4.5), with its base resolved.
fn artifact_uri(run: &Value, al: &Value) -> Option<String> {
    let artifact = al["index"]
        .as_u64()
        .and_then(|i| run["artifacts"].get(usize::try_from(i).ok()?))
        .map(|a| &a["location"]);
    let artifact_uri = artifact.and_then(|a| str_at(a, &["uri"]));
    let uri = str_at(al, &["uri"]).or(artifact_uri)?;
    // The artifact's base applies when the location names the same file
    // without one of its own.
    let base = str_at(al, &["uriBaseId"]).or_else(|| {
        artifact
            .filter(|_| artifact_uri == Some(uri))
            .and_then(|a| str_at(a, &["uriBaseId"]))
    });
    Some(resolve_uri(run, uri, base))
}

/// A local `file:` uri or plain absolute path, decoded.
fn local_path(uri: &str) -> Option<String> {
    if uri.starts_with("file:") {
        return safety::file_uri_path(uri)?.to_str().map(str::to_string);
    }
    percent_decode(uri).filter(|p| p.starts_with('/'))
}

/// The absolute directories the report says it was produced in: its base uris
/// and the invocations' working directories. Roots fewer than two directories
/// deep (`/`, `/home`) would map almost any path onto the project, so they are
/// left out.
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
    // Longest first, so the most specific root wins.
    roots.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    roots.dedup();
    roots
}

/// An absolute `uri` under one of `roots`, relative to it. Whether the result
/// is safe to use is decided in `ingest`, like any other relative path.
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

/// The rules of the tool component a reference names (§3.54): an extension
/// by index or name, else the driver.
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

/// Every rule in a run by id: the driver's, then each extension's, as recent
/// CodeQL keeps one per query pack (§3.52.4). The first rule with an id wins.
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

    /// The rule for `id`, or for the longest rule id it refines: a ruleId may be
    /// `rule/sub` (§3.27.5).
    fn by_id(&self, id: &str) -> Option<&'a Value> {
        let mut id = id;
        loop {
            if let Some(rule) = self.0.get(id) {
                return Some(rule);
            }
            id = &id[..id.rfind('/')?];
        }
    }

    /// The rule metadata for a result (§3.27.6): by index into the component
    /// it names, if that rule agrees with the result's id, else by id.
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

/// The result's message as plain text (§3.11): its own text, or the template
/// it names, with arguments filled in and links to related locations removed.
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
    // Only messages meant to be formatted: a literal `{{` elsewhere stays as is.
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

/// `[user input](1)` → `user input`: in plain-text SARIF messages a link to a
/// number points at one of the result's related locations (§3.11.6), which a
/// note cannot follow. `\[` and `\]` are literal brackets. Links to anything
/// else are left for `md_escape` to defuse.
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

/// `[label](digits)` at the start of `s`: the label with escapes removed, and
/// the link's length. The label ends at the first unescaped `]`.
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

fn parse_brakeman(doc: &Value) -> Parsed {
    let mut out = Parsed {
        tools: vec!["brakeman".into()],
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

/// Scanner uri → worktree-relative path. Only `file:` URIs and plain paths are accepted.
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

/// The code at `start..=end` in the project file `rel`, or why there is none.
fn read_snippet(store: &Store, rel: &str, start: u32, end: u32) -> Result<String, String> {
    let path = safety::confine(store.root(), rel).map_err(|e| e.to_string())?;
    let text =
        safety::read_limited(&path, MAX_SOURCE_BYTES, rel).map_err(|e| format!("{rel}: {e:#}"))?;
    let snippet = anchor::extract(&text, start, end);
    if snippet.is_empty() {
        return Err(format!("{rel}:{start}: line is past the end of the file"));
    }
    Ok(snippet)
}

/// A finding resolved against the project: its confined path and current code.
struct Located {
    f: RawFinding,
    rel: String,
    snippet: String,
    end_line: u32,
    /// Fingerprint of the first occurrence; see [`anchor::fingerprint`].
    base: String,
}

/// Semgrep prefixes rule ids with the config path (`rules.x` vs
/// `Users.me.rules.x`), so only the last segment identifies the rule.
fn rule_key(rule: &str) -> &str {
    rule.rsplit(['.', '/']).next().unwrap_or_default()
}

pub fn ingest(store: &Store, config: &Config, parsed: Parsed) -> Summary {
    let mut summary = Summary {
        tools: parsed.tools,
        ignored: parsed.ignored,
        rejected: parsed.rejected,
        ..Summary::default()
    };
    let mut located = Vec::new();
    for f in parsed.findings {
        if !summary.tools.contains(&f.tool) {
            summary.tools.push(f.tool.clone());
        }
        // The path as given, then relative to a root the report names.
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
        if candidates.is_empty() {
            summary.rejected.push(format!(
                "{}: path outside the project or unsupported uri",
                f.uri
            ));
            continue;
        }
        let mut first_error = None;
        let mut found = None;
        for rel in candidates {
            match read_snippet(store, &rel, f.start_line, f.end_line) {
                Ok(snippet) => {
                    found = Some((rel, snippet));
                    break;
                }
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        let Some((rel, snippet)) = found else {
            summary.rejected.extend(first_error);
            continue;
        };
        let end_line = f.start_line + snippet.lines().count().max(1) as u32 - 1;
        let base = anchor::fingerprint(&rel, rule_key(&f.rule), &snippet, 0);
        located.push(Located {
            f,
            rel,
            snippet,
            end_line,
            base,
        });
    }

    // In line order, so the same rule on identical code twice in a file gets
    // occurrence 0, 1, ... the same way on every import. A scanner reporting
    // the very same line twice is one finding.
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

    for Located {
        f,
        rel,
        snippet,
        end_line,
        base,
    } in located
    {
        let n = occurrences.entry(base).or_default();
        let fp = anchor::fingerprint(&rel, rule_key(&f.rule), &snippet, *n);
        *n += 1;
        if !seen.insert(fp.clone()) {
            summary.skipped += 1;
            continue;
        }

        let note = Note {
            meta: Meta {
                id: store.new_id(&fp),
                file: rel,
                start_line: f.start_line,
                end_line,
                status: status.clone(),
                author: f.tool.clone(),
                created: now,
                source: Some(f.tool.clone()),
                rule: (!f.rule.is_empty()).then(|| f.rule.clone()),
                fingerprint: Some(fp),
                snippet,
            },
            body: imported_body(&f),
        };
        match store.save(&note) {
            Ok(_) => summary.imported += 1,
            Err(e) => summary.rejected.push(format!("saving note: {e:#}")),
        }
    }
    summary
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
        // The last result repeats the first: a scanner listing a line twice.
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
        // Terminates; how far it got does not matter.
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
        // An index into the wrong list is caught by the id, which is then searched for.
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
        // A different file than the artifact: the artifact's base says nothing about it.
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

    #[test]
    fn unknown_format_explains_how_to_get_sarif() {
        let err = parse(r#"{"results":[]}"#).unwrap_err().to_string();
        assert!(err.contains("semgrep --sarif"));
    }
}
