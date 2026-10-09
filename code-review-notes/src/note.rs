//! A review note: TOML front matter between `+++` lines, then a Markdown body.

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::is_valid_status_id;
use crate::safety;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub id: String,
    /// Worktree-relative POSIX path.
    pub file: String,
    /// 1-based, inclusive.
    pub start_line: u32,
    pub end_line: u32,
    /// One of the ids in `config.toml`, e.g. `open`.
    pub status: String,
    pub author: String,
    pub created: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub snippet: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Note {
    pub meta: Meta,
    pub body: String,
}

const FENCE: &str = "+++";

impl Note {
    pub fn parse(text: &str) -> anyhow::Result<Note> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let text = text.replace("\r\n", "\n");
        let Some(rest) = text.strip_prefix("+++\n") else {
            bail!("note does not start with a +++ front-matter block");
        };
        // A `+++` line can also appear inside the snippet string (a diff, say),
        // so the closing fence is the first `+++` line after which the front
        // matter parses. Cutting inside the snippet leaves an unclosed string.
        let mut first_err = None;
        for (end, _) in rest.match_indices("\n+++") {
            let after = &rest[end + 4..];
            if !(after.is_empty() || after.starts_with('\n')) {
                continue;
            }
            match toml::from_str::<Meta>(&rest[..end + 1]) {
                Ok(meta) => {
                    validate(&meta)?;
                    return Ok(Note {
                        meta,
                        body: after.trim_start_matches('\n').trim_end().to_string(),
                    });
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e).context("invalid front matter"),
            None => bail!("front matter is not closed with +++"),
        }
    }

    pub fn render(&self) -> String {
        let front = toml::to_string(&self.meta).expect("note metadata always serializes");
        let mut out = format!("{FENCE}\n{front}{FENCE}\n\n");
        let body = self.body.trim_end();
        if !body.is_empty() {
            out.push_str(body);
            out.push('\n');
        }
        out
    }

    /// The first non-empty body line, without a leading Markdown heading marker.
    pub fn title(&self) -> &str {
        self.body
            .lines()
            .map(|l| l.trim().trim_start_matches('#').trim())
            .find(|l| !l.is_empty())
            .unwrap_or("(untitled note)")
    }

    /// The title as plain text, for places that don't render Markdown
    /// (diagnostics, symbols, the CLI): backslash escapes are removed.
    pub fn plain_title(&self) -> String {
        crate::markdown::unescape(self.title())
    }

    /// The body with the title line removed.
    pub fn details(&self) -> &str {
        match self.body.trim_start().split_once('\n') {
            Some((_, rest)) => rest.trim(),
            None => "",
        }
    }
}

/// Reject note files whose fields would make us touch the wrong place on disk.
fn validate(meta: &Meta) -> anyhow::Result<()> {
    if !is_valid_id(&meta.id) {
        bail!(
            "note id {:?} must be 8-32 lowercase hex characters",
            meta.id
        );
    }
    if !safety::is_relative_safe(&meta.file) {
        return Err(safety::SafetyError::PathEscape {
            candidate: meta.file.clone(),
        }
        .into());
    }
    if !is_valid_status_id(&meta.status) {
        bail!("invalid status {:?}", meta.status);
    }
    if meta.start_line == 0 || meta.end_line < meta.start_line {
        bail!("invalid line range {}-{}", meta.start_line, meta.end_line);
    }
    Ok(())
}

pub fn is_valid_id(id: &str) -> bool {
    (8..=32).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Note {
        Note {
            meta: Meta {
                id: "7f3a9c21".into(),
                file: "app/controllers/users_controller.rb".into(),
                start_line: 41,
                end_line: 43,
                status: "issue".into(),
                author: "alice".into(),
                created: "2026-10-09T10:00:00Z".parse().unwrap(),
                source: Some("semgrep".into()),
                rule: Some("ruby.sql".into()),
                fingerprint: Some("abc".into()),
                snippet: "def show\n  User.find_by_sql(\"\"\"x\"\"\")\nend\n".into(),
            },
            body: "# SQL injection\n\nReachable from GET /users/:id.".into(),
        }
    }

    #[test]
    fn round_trips() {
        let note = sample();
        let text = note.render();
        let parsed = Note::parse(&text).unwrap();
        assert_eq!(parsed, note);
        assert_eq!(parsed.render(), text);
    }

    #[test]
    fn plus_fence_inside_snippet_round_trips() {
        let mut note = sample();
        note.meta.snippet = "--- a/x\n+++ b/x\n+++\n@@ -1 +1 @@\n".into();
        note.body = "# Diff\n\n+++\nnot a fence".into();
        let parsed = Note::parse(&note.render()).unwrap();
        assert_eq!(parsed, note);
    }

    #[test]
    fn plain_title_unescapes() {
        let mut note = sample();
        note.body = r"# Use of eval\(\) on \`x\_y\` \\ C:\path".into();
        assert_eq!(note.plain_title(), r"Use of eval() on `x_y` \ C:\path");
    }

    #[test]
    fn title_and_details() {
        let note = sample();
        assert_eq!(note.title(), "SQL injection");
        assert_eq!(note.details(), "Reachable from GET /users/:id.");
    }

    #[test]
    fn rejects_escaping_file_and_bad_id() {
        let mut note = sample();
        note.meta.file = "../../../../.ssh/id_rsa".into();
        assert!(Note::parse(&note.render()).is_err());
        let mut note = sample();
        note.meta.id = "../x".into();
        assert!(Note::parse(&note.render()).is_err());
        let mut note = sample();
        note.meta.status = "](http://evil)".into();
        assert!(Note::parse(&note.render()).is_err());
    }

    #[test]
    fn rejects_missing_front_matter() {
        assert!(Note::parse("# just markdown").is_err());
        assert!(Note::parse("+++\nid = \"x\"\n").is_err());
    }
}
