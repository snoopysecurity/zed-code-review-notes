//! Markdown report of all review notes.
//!
//! Snippets come from the note files, never from re-reading the paths they
//! name; source files are only consulted (through `confine`) to tell whether a
//! note has gone stale.

use chrono::{DateTime, Utc};
use std::fmt::Write;

use crate::anchor;
use crate::config::{Config, StatusDef};
use crate::markdown::{fenced, inline_code, md_escape};
use crate::note::Note;
use crate::store::Store;

pub struct Entry {
    pub note: Note,
    pub stale: bool,
}

/// Pair each note with whether its code can still be found. Notes are
/// grouped by file so each file is read once.
pub fn check_staleness(store: &Store, mut notes: Vec<Note>) -> Vec<Entry> {
    notes.sort_by(|a, b| a.meta.file.cmp(&b.meta.file));
    let mut current: Option<(String, Option<String>)> = None;
    notes
        .into_iter()
        .map(|note| {
            let m = &note.meta;
            if current.as_ref().is_none_or(|(file, _)| *file != m.file) {
                current = Some((m.file.clone(), store.read_source(&m.file).ok()));
            }
            let text = current.as_ref().and_then(|(_, t)| t.as_deref());
            let stale = text
                .is_none_or(|t| anchor::locate(&m.snippet, m.start_line, m.end_line, t).is_stale());
            Entry { note, stale }
        })
        .collect()
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
    entries.sort_by(|a, b| {
        (&a.note.meta.file, a.note.meta.start_line, &a.note.meta.id).cmp(&(
            &b.note.meta.file,
            b.note.meta.start_line,
            &b.note.meta.id,
        ))
    });
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
    }
    let details = e.note.details();
    if !details.is_empty() {
        // Notes are the reviewer's own Markdown; demote headings so they nest.
        out.push_str(&demote_headings(details));
        out.push('\n');
    }
    out.push_str("---\n\n");
}

/// Push ATX headings down three levels (capped at `######`), leaving fenced
/// code blocks and `#`-lines that are not headings (`#include`) untouched.
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
                    fingerprint: None,
                    snippet: snippet.into(),
                },
                body: body.into(),
            },
            stale,
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
