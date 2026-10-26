//! Markdown, JSON, SARIF and GitLab issue exports. Snippets come from the notes
//! themselves; source files are only read (via `confine`) for staleness.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::fmt::Write;

use crate::anchor::{self, Anchor};
use crate::config::{Config, Severity, StatusDef};
use crate::markdown::{fenced, inline_code, md_escape};
use crate::note::Note;
use crate::store::Store;

pub struct Entry {
    pub note: Note,
    pub stale: bool,
    pub changed: bool,
    /// File exists but can't be read (too big, permissions, symlink out of the
    /// project). Shown as stale even though the code may be fine.
    pub unreadable: Option<String>,
}

impl Entry {
    pub fn is_gone(&self) -> bool {
        self.stale && self.unreadable.is_none()
    }

    /// suffix for one-line listings
    pub fn state(&self) -> &'static str {
        if self.stale {
            " (stale)"
        } else if self.changed {
            " (changed)"
        } else {
            ""
        }
    }
}

/// `Ok(None)` for a missing file, `Err` for one that exists but can't be read.
pub fn source(store: &Store, rel: &str) -> Result<Option<String>, String> {
    match store.read_source(rel) {
        Ok(text) => Ok(Some(text)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Groups by file first so each source file is read once.
pub fn check_staleness(store: &Store, mut notes: Vec<Note>) -> Vec<Entry> {
    notes.sort_by(|a, b| a.meta.file.cmp(&b.meta.file));
    let mut current: Option<(String, Result<Option<String>, String>)> = None;
    notes
        .into_iter()
        .map(|note| {
            let m = &note.meta;
            if current.as_ref().is_none_or(|(file, _)| *file != m.file) {
                current = Some((m.file.clone(), source(store, &m.file)));
            }
            let read = current.as_ref().map(|(_, r)| r);
            let text = read.and_then(|r| r.as_ref().ok()?.as_deref());
            let anchor = text
                .map(|t| anchor::locate_in(&m.snippet, m.context(), m.start_line, m.end_line, t));
            Entry {
                stale: anchor.is_none_or(Anchor::is_stale),
                changed: anchor.is_some_and(Anchor::is_changed),
                unreadable: read.and_then(|r| r.as_ref().err().cloned()),
                note,
            }
        })
        .collect()
}

/// The one ordering every export and listing uses
pub fn sort(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        (&a.note.meta.file, a.note.meta.start_line, &a.note.meta.id).cmp(&(
            &b.note.meta.file,
            b.note.meta.start_line,
            &b.note.meta.id,
        ))
    });
}

/// Report sections: configured statuses ordered by severity (issues first),
/// then any status no longer in the config, then Stale.
fn sections<'a>(config: &'a Config, entries: &'a [Entry]) -> Vec<(String, Vec<&'a Entry>)> {
    let mut defs: Vec<&StatusDef> = config.statuses.iter().collect();
    defs.sort_by_key(|d| d.severity);
    let mut ids: Vec<(&str, String)> = defs
        .iter()
        .map(|d| (d.id.as_str(), d.label.clone()))
        .collect();
    for e in entries {
        let id = e.note.meta.status.as_str();
        if !ids.iter().any(|(i, _)| *i == id) {
            ids.push((id, id.to_string()));
        }
    }
    let mut out: Vec<(String, Vec<&Entry>)> = ids
        .into_iter()
        .map(|(id, label)| {
            let items = entries
                .iter()
                .filter(|e| !e.stale && e.note.meta.status == id)
                .collect();
            (label, items)
        })
        .collect();
    out.push(("Stale".into(), entries.iter().filter(|e| e.stale).collect()));
    out
}

pub fn render(
    project: &str,
    config: &Config,
    entries: &mut [Entry],
    generated: DateTime<Utc>,
) -> String {
    sort(entries);
    let sections = sections(config, entries);

    let mut out = String::new();
    let _ = writeln!(out, "# Code review: {}\n", md_escape(project));
    let counts: Vec<String> = sections
        .iter()
        .filter(|(_, items)| !items.is_empty())
        .map(|(label, items)| format!("{} {}", items.len(), md_escape(label)))
        .collect();
    let _ = writeln!(
        out,
        "{} notes · {} · generated {}\n",
        entries.len(),
        if counts.is_empty() {
            "nothing noted".to_string()
        } else {
            counts.join(" · ")
        },
        generated.format("%Y-%m-%d")
    );

    for (heading, items) in &sections {
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(out, "## {}\n", md_escape(heading));
        for e in items {
            write_entry(&mut out, config, e);
        }
    }
    out
}

fn write_entry(out: &mut String, config: &Config, e: &Entry) {
    let m = &e.note.meta;
    let _ = writeln!(out, "### {}\n", e.note.title());
    let mut line = inline_code(&format!("{}:{}-{}", m.file, m.start_line, m.end_line));
    if e.stale {
        let _ = write!(line, " · {}", md_escape(config.label(&m.status)));
    }
    if let Some(src) = &m.source {
        let _ = write!(line, " · {}", md_escape(src));
    }
    if let Some(rule) = &m.rule {
        let _ = write!(line, " · rule {}", inline_code(rule));
    }
    if !m.tags.is_empty() {
        let _ = write!(line, " · tags {}", md_escape(&m.tags.join(", ")));
    }
    let _ = write!(
        line,
        " · {} · {}",
        md_escape(&m.author),
        m.created.format("%Y-%m-%d")
    );
    let _ = writeln!(out, "{line}\n");
    if !m.snippet.trim().is_empty() {
        out.push_str(&fenced(&m.snippet));
        out.push('\n');
    }
    if e.stale {
        out.push_str("_The code this note was made on can no longer be found; the snippet above is the original._\n\n");
    } else if e.changed {
        out.push_str("_The code has been edited since this note was made; the snippet above is the original._\n\n");
    }
    let details = e.note.details();
    if !details.is_empty() {
        // reviewer's own Markdown, demoted to nest under the note heading
        out.push_str(&demote_headings(details));
        out.push('\n');
    }
    out.push_str("---\n\n");
}

/// Unwraps the `toml` crate's private datetime wrapper (from keys added by newer
/// versions) into plain strings.
fn meta_json(note: &Note) -> Value {
    fn datetimes(v: Value) -> Value {
        match v {
            Value::Object(m) => match m.get("$__toml_private_datetime") {
                Some(Value::String(d)) if m.len() == 1 => Value::String(d.clone()),
                _ => Value::Object(m.into_iter().map(|(k, v)| (k, datetimes(v))).collect()),
            },
            Value::Array(a) => Value::Array(a.into_iter().map(datetimes).collect()),
            v => v,
        }
    }
    datetimes(serde_json::to_value(&note.meta).expect("note metadata always serializes"))
}

pub fn render_json(config: &Config, entries: &mut [Entry]) -> String {
    sort(entries);
    let notes: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "meta": meta_json(&e.note),
                "status_label": config.label(&e.note.meta.status),
                "title": e.note.plain_title(),
                "body": e.note.body,
                "stale": e.stale,
                "changed": e.changed,
                "unreadable": e.unreadable,
            })
        })
        .collect();
    let mut out = serde_json::to_string_pretty(&notes).expect("JSON always serializes");
    out.push('\n');
    out
}

/// for hand-written notes and anything else without a scanner rule
pub const NOTE_RULE: &str = "code-review-note";

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
        Severity::Hint => "none",
    }
}

/// SARIF 2.1.0, one result per note. Note text goes in properties rather than a
/// Markdown message.
pub fn render_sarif(config: &Config, entries: &mut [Entry]) -> String {
    sort(entries);
    let rule = |e: &Entry| e.note.meta.rule.clone().unwrap_or_else(|| NOTE_RULE.into());
    let mut rules: Vec<String> = entries.iter().map(rule).collect();
    rules.sort();
    rules.dedup();
    let results: Vec<Value> = entries
        .iter()
        .map(|e| {
            let m = &e.note.meta;
            let mut region = json!({"startLine": m.start_line, "endLine": m.end_line});
            if !m.snippet.is_empty() {
                region["snippet"] = json!({"text": m.snippet});
            }
            json!({
                "ruleId": rule(e),
                "ruleIndex": rules.binary_search(&rule(e)).unwrap_or_default(),
                "level": sarif_level(config.severity(&m.status)),
                "message": {"text": e.note.plain_title()},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": m.file, "uriBaseId": "%SRCROOT%"},
                    "region": region,
                }}],
                "partialFingerprints": {"codeReviewNotes/v1": m.fingerprint.as_deref().unwrap_or(&m.id)},
                "properties": {
                    "noteId": m.id,
                    "status": m.status,
                    "statusLabel": config.label(&m.status),
                    "author": m.author,
                    "created": m.created,
                    "source": m.source,
                    "tags": m.tags,
                    "stale": e.stale,
                    "changed": e.changed,
                    "body": e.note.body,
                },
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "code-review-notes",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules.iter().map(|id| json!({"id": id})).collect::<Vec<_>>(),
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The project root"}}},
            "results": results,
        }],
    });
    let mut out = serde_json::to_string_pretty(&doc).expect("JSON always serializes");
    out.push('\n');
    out
}

/// `(file name, text)` per note; first line of the text is the title. Nothing
/// is posted.
///
/// Note text is repository content. Pasted into an issue, GitLab would run
/// `/assign @x` style quick actions, ping `@mentions` and render links and
/// images. Hence the plain-text title and the body fenced in a code block.
pub fn render_gitlab_issues(config: &Config, entries: &mut [Entry]) -> Vec<(String, String)> {
    sort(entries);
    entries
        .iter()
        .map(|e| {
            let m = &e.note.meta;
            let title: String = e
                .note
                .plain_title()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let mut out = format!("{title}\n\n");
            let mut facts = vec![
                format!("**Status:** {}", md_escape(config.label(&m.status))),
                format!(
                    "**Where:** {}",
                    inline_code(&format!("{}:{}-{}", m.file, m.start_line, m.end_line))
                ),
            ];
            if let Some(src) = &m.source {
                facts.push(format!("**Found by:** {}", md_escape(src)));
            }
            if let Some(rule) = &m.rule {
                facts.push(format!("**Rule:** {}", inline_code(rule)));
            }
            if !m.tags.is_empty() {
                facts.push(format!("**Tags:** {}", md_escape(&m.tags.join(", "))));
            }
            facts.push(format!(
                "**Noted by:** {} on {}",
                md_escape(&m.author),
                m.created.format("%Y-%m-%d")
            ));
            for f in facts {
                let _ = writeln!(out, "- {f}");
            }
            out.push('\n');
            if e.stale {
                out.push_str("The code this note was made on can no longer be found; the snippet below is the original.\n\n");
            } else if e.changed {
                out.push_str("The code has been edited since this note was made; the snippet below is the original.\n\n");
            }
            if !m.snippet.trim().is_empty() {
                out.push_str("### Code\n\n");
                out.push_str(&fenced(&m.snippet));
                out.push('\n');
            }
            out.push_str("### Review note\n\n");
            out.push_str(&fenced(e.note.body.trim()));
            let _ = write!(out, "\n_Exported from code-review-notes, note {}._\n", inline_code(&m.id));
            (format!("{}.md", m.id), out)
        })
        .collect()
}

/// ATX headings down three levels, max `######`. Leaves fenced code and
/// non-heading `#` lines (`#include`) alone.
fn demote_headings(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut fence: Option<(char, usize)> = None;
    for l in md.lines() {
        let t = l.trim_start_matches(' ');
        let indent = &l[..l.len() - t.len()];
        let marker = t.chars().next().filter(|c| matches!(c, '`' | '~'));
        let run = marker.map_or(0, |c| t.chars().take_while(|&x| x == c).count());
        let hashes = t.chars().take_while(|&c| c == '#').count();
        if indent.len() <= 3 && run >= 3 {
            let c = marker.unwrap_or_default();
            match fence {
                None => fence = Some((c, run)),
                Some((fc, n)) if fc == c && run >= n && t[run..].trim().is_empty() => fence = None,
                Some(_) => {}
            }
        } else if fence.is_none()
            && indent.len() <= 3
            && (1..=6).contains(&hashes)
            && t[hashes..]
                .chars()
                .next()
                .is_none_or(|c| c == ' ' || c == '\t')
        {
            out.push_str(indent);
            out.push_str(&"#".repeat((hashes + 3).min(6)));
            out.push_str(&t[hashes..]);
            out.push('\n');
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::Meta;

    fn entry(
        id: &str,
        file: &str,
        line: u32,
        status: &str,
        stale: bool,
        body: &str,
        snippet: &str,
    ) -> Entry {
        Entry {
            note: Note {
                meta: Meta {
                    id: id.into(),
                    file: file.into(),
                    start_line: line,
                    end_line: line + 1,
                    status: status.into(),
                    author: "alice".into(),
                    created: "2026-10-01T10:00:00Z".parse().unwrap(),
                    source: Some("semgrep".into()),
                    rule: Some("python.sqli".into()),
                    tags: Vec::new(),
                    fingerprint: None,
                    snippet: snippet.into(),
                    context_before: None,
                    context_after: None,
                    extra: Default::default(),
                },
                body: body.into(),
            },
            stale,
            changed: false,
            unreadable: None,
        }
    }

    #[test]
    fn demotes_only_real_headings() {
        let md = "## Impact\n```py\n# comment\n```\n#hashtag\n#### Deep\n~~~~\n```\n# still code\n~~~~\n# Back";
        assert_eq!(
            demote_headings(md),
            "##### Impact\n```py\n# comment\n```\n#hashtag\n###### Deep\n~~~~\n```\n# still code\n~~~~\n#### Back\n"
        );
    }

    #[test]
    fn changed_code_is_called_out() {
        let mut e = entry("aaaaaaaa", "a.py", 1, "ok", false, "# Fine", "run(x)\n");
        e.changed = true;
        e.note.meta.tags = vec!["cwe-78".into()];
        let out = render(
            "demo",
            &Config::default(),
            &mut [e],
            "2026-10-09T00:00:00Z".parse().unwrap(),
        );
        assert!(out.contains("## OK"), "{out}");
        assert!(out.contains("edited since this note was made"), "{out}");
        assert!(
            out.contains(" · rule `python.sqli` · tags cwe-78 · alice"),
            "{out}"
        );
    }

    fn hostile() -> Vec<Entry> {
        let mut e = entry(
            "aaaaaaaa",
            "a.py",
            3,
            "issue",
            false,
            "# SQL @all [x](http://evil) `t`\n\n/assign @someone\n![p](http://evil/p.png)\n```\nfence\n```",
            "db.query(f\"{id}\")\n",
        );
        e.changed = true;
        e.note.meta.extra.insert(
            "reviewed_at".into(),
            toml::Value::Datetime("2026-10-01T00:00:00Z".parse().unwrap()),
        );
        e.note.meta.tags = vec!["cwe-89".into(), "sec_rity".into()];
        let mut by_hand = entry("bbbbbbbb", "b.py", 1, "ok", true, "# Fine", "x\n");
        by_hand.note.meta.rule = None;
        by_hand.note.meta.source = None;
        vec![by_hand, e]
    }

    #[test]
    fn json_export() {
        let out = render_json(&Config::default(), &mut hostile());
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        let a = &v[0];
        assert_eq!(a["meta"]["id"], "aaaaaaaa");
        assert_eq!(a["meta"]["created"], "2026-10-01T10:00:00Z");
        assert_eq!(a["meta"]["reviewed_at"], "2026-10-01T00:00:00Z");
        assert_eq!(
            (a["stale"].clone(), a["changed"].clone()),
            (json!(false), json!(true))
        );
        assert_eq!(a["status_label"], "Issue");
        assert!(a["body"].as_str().unwrap().starts_with("# SQL @all"));
        assert_eq!(v[1]["stale"], true);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn sarif_export() {
        let out = render_sarif(&Config::default(), &mut hostile());
        let v: Value = serde_json::from_str(&out).unwrap();
        let run = &v["runs"][0];
        let rules: Vec<&str> = run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(rules, [NOTE_RULE, "python.sqli"]);
        let r = &run["results"];
        assert_eq!(
            (r[0]["ruleId"].as_str(), r[0]["ruleIndex"].as_u64()),
            (Some("python.sqli"), Some(1))
        );
        assert_eq!(r[0]["level"], "error");
        assert_eq!(r[1]["level"], "none");
        assert_eq!(r[1]["ruleId"], NOTE_RULE);
        assert_eq!(
            r[0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"],
            "db.query(f\"{id}\")\n"
        );
        insta::assert_snapshot!(out);
    }

    #[test]
    fn gitlab_issues_quote_the_note() {
        let issues = render_gitlab_issues(&Config::default(), &mut hostile());
        assert_eq!(issues.len(), 2);
        let (name, text) = &issues[0];
        assert_eq!(name, "aaaaaaaa.md");
        assert!(
            text.starts_with("SQL @all [x](http://evil) `t`\n\n"),
            "{text}"
        );
        // fence must be longer than any fence in the body
        let body = text.split("### Review note\n\n").nth(1).unwrap();
        assert!(body.starts_with("````\n# SQL"), "{body}");
        assert!(
            body.contains("/assign @someone\n![p](http://evil/p.png)\n```\nfence\n```\n````\n"),
            "{body}"
        );
        assert!(text.contains("edited since this note was made"), "{text}");
        insta::assert_snapshot!(text);
    }

    #[test]
    fn report_snapshot() {
        let mut entries = vec![
            entry(
                "bbbbbbbb",
                "b.py",
                9,
                "open",
                false,
                "# Check this\n\nNot sure yet.",
                "eval(x)\n",
            ),
            entry(
                "aaaaaaaa",
                "a.py",
                3,
                "issue",
                false,
                "# SQL injection \\]\\(http://evil\\)\n\nReachable from **/users**.",
                "db.query(f\"{id}\")\n",
            ),
            entry(
                "cccccccc",
                "a.py",
                1,
                "ok",
                false,
                "# Constant input",
                "run(\"ls\")\n",
            ),
            entry(
                "dddddddd",
                "c.md",
                1,
                "issue",
                true,
                "# Fence test",
                "````\ncode\n````\n",
            ),
        ];
        entries.push(entry(
            "eeeeeeee",
            "d.py",
            1,
            "removed_status",
            false,
            "# Status no longer configured",
            "x\n",
        ));
        let out = render(
            "demo",
            &Config::default(),
            &mut entries,
            "2026-10-09T00:00:00Z".parse().unwrap(),
        );
        insta::assert_snapshot!(out);
    }
}
