//! A review note: TOML front matter between `+++` lines, Markdown body after.

use anyhow::{Context, bail};
use chrono::{DateTime, SubsecRound, Utc};
use serde::{Deserialize, Serialize};

use crate::anchor;
use crate::config::is_valid_status_id;
use crate::markdown::md_escape;
use crate::safety;

/// Unknown fields land in [`Meta::extra`] and get written back untouched. Notes
/// travel through git and a teammate on a newer version may add fields we've
/// never heard of.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Meta {
    pub id: String,
    /// worktree-relative, POSIX
    pub file: String,
    /// 1-based, inclusive
    pub start_line: u32,
    pub end_line: u32,
    /// a status id from `config.toml`, e.g. `open`
    pub status: String,
    pub author: String,
    pub created: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Plain labels like `cwe-89`, see [`is_valid_tag`]. Older versions keep
    /// them in `extra`, which keeps notes readable there.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub snippet: String,
    /// Nearest non-blank line around the code (see [`anchor::Context`]).
    /// Absent in notes written before we recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_after: Option<String>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Meta {
    /// Point the note at lines `start..=end` of `text`. The end gets cut at the
    /// snippet line limit; errors if `start` is past EOF.
    pub fn set_code(&mut self, text: &str, start: u32, end: u32) -> anyhow::Result<()> {
        let code = anchor::code_at(text, start, end)
            .with_context(|| format!("line {start} is past the end of the file"))?;
        self.set(start, code);
        Ok(())
    }

    pub fn set(&mut self, start: u32, code: anchor::Code) {
        self.start_line = start;
        self.end_line = code.end_line;
        self.snippet = code.snippet;
        self.context_before = code.context_before;
        self.context_after = code.context_after;
    }

    pub fn context(&self) -> anchor::Context<'_> {
        anchor::Context {
            before: self.context_before.as_deref(),
            after: self.context_after.as_deref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Note {
    pub meta: Meta,
    pub body: String,
}

const FENCE: &str = "+++";

/// Initial title for notes added in the editor (selected so you can type over it)
pub const PLACEHOLDER_TITLE: &str = "New review note";

impl Note {
    /// `rel` is the project-relative path `text` was read from
    #[allow(clippy::too_many_arguments)]
    pub fn new_on(
        id: String,
        rel: String,
        text: &str,
        start: u32,
        end: u32,
        status: &str,
        author: String,
        body: String,
    ) -> anyhow::Result<Note> {
        anyhow::ensure!(start >= 1, "lines are numbered from 1");
        anyhow::ensure!(start <= end, "start line {start} is after end line {end}");
        let mut meta = Meta {
            id,
            file: rel,
            start_line: start,
            end_line: end,
            status: status.to_string(),
            author,
            created: Utc::now().trunc_subsecs(0),
            source: None,
            rule: None,
            tags: Vec::new(),
            fingerprint: None,
            snippet: String::new(),
            context_before: None,
            context_after: None,
            extra: Default::default(),
        };
        meta.set_code(text, start, end)?;
        Ok(Note { meta, body })
    }

    /// Also logs who changed it in the body's history
    pub fn mark(&mut self, status: &str, label: &str, author: &str) {
        self.meta.status = status.to_string();
        self.history(&format!(
            "{} marked this {}",
            md_escape(author),
            md_escape(label)
        ));
    }

    /// Appends `_<what> on <date>._` to the body
    pub fn history(&mut self, what: &str) {
        self.body.push_str(&format!(
            "\n\n_{what} on {}._",
            Utc::now().format("%Y-%m-%d")
        ));
    }

    /// Line plus start/end columns (UTF-16) of the title in [`Note::render`]'s
    /// output, used to select it in the editor
    pub fn title_position(&self) -> Option<(u32, u32, u32)> {
        let title = self.title();
        self.render().lines().enumerate().find_map(|(i, l)| {
            let at = l
                .find(title)
                .filter(|_| l.trim_start_matches('#').trim() == title)?;
            let start = l[..at].encode_utf16().count() as u32;
            Some((i as u32, start, start + title.encode_utf16().count() as u32))
        })
    }

    pub fn parse(text: &str) -> anyhow::Result<Note> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let text = text.replace("\r\n", "\n");
        let Some(rest) = text.strip_prefix("+++\n") else {
            bail!("note does not start with a +++ front-matter block");
        };
        // `+++` can also show up inside the snippet string (a diff, say). Take the
        // first `+++` line after which the front matter actually parses; cutting
        // inside the snippet leaves an unclosed string and fails.
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

    /// First non-empty body line, minus any leading `#` marker
    pub fn title(&self) -> &str {
        self.body
            .lines()
            .map(|l| l.trim().trim_start_matches('#').trim())
            .find(|l| !l.is_empty())
            .unwrap_or("(untitled note)")
    }

    /// Title without backslash escapes, for diagnostics, symbols and the CLI
    /// (none of which render Markdown)
    pub fn plain_title(&self) -> String {
        crate::markdown::unescape(self.title())
    }

    pub fn details(&self) -> &str {
        match self.body.trim_start().split_once('\n') {
            Some((_, rest)) => rest.trim(),
            None => "",
        }
    }
}

/// Rejects notes whose fields would point us at the wrong place on disk
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
    if let Some(t) = meta.tags.iter().find(|t| !is_valid_tag(t)) {
        bail!("tag {t:?} must be up to 32 lowercase letters, digits, '-', '_' or '.'");
    }
    if meta.tags.len() > MAX_TAGS {
        bail!("a note can have at most {MAX_TAGS} tags");
    }
    Ok(())
}

pub const MAX_TAGS: usize = 16;

/// Tags show up in hovers, `cmd-t` and reports. Keep them plain: no spaces,
/// no Markdown.
pub fn is_valid_tag(tag: &str) -> bool {
    (1..=32).contains(&tag.len())
        && tag.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && tag
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

/// Scanner tag -> note tag, if possible. CWE ids in their many spellings
/// (`CWE-89: Improper...`, `external/cwe/cwe-089`) become `cwe-89`; anything
/// else must already be plain apart from case.
pub fn tag_from_scanner(raw: &str) -> Option<String> {
    let t = raw.trim().to_ascii_lowercase();
    let head = t.split(':').next().unwrap_or_default();
    let last = head.rsplit('/').next().unwrap_or_default().trim();
    if let Some(n) = last.strip_prefix("cwe")
        && let Ok(n) = n.trim_start_matches(['-', '_', ' ']).parse::<u32>()
    {
        return Some(format!("cwe-{n}"));
    }
    is_valid_tag(&t).then_some(t)
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
                tags: Vec::new(),
                fingerprint: Some("abc".into()),
                snippet: "def show\n  User.find_by_sql(\"\"\"x\"\"\")\nend\n".into(),
                context_before: None,
                context_after: None,
                extra: Default::default(),
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
    fn keeps_fields_from_newer_versions() {
        let text = sample().render().replacen(
            "+++\n\n",
            "labels = [\"cwe-89\"]\nseverity = 7\n\n[review]\nround = 2\n+++\n\n",
            1,
        );
        let note = Note::parse(&text).unwrap();
        assert_eq!(note.meta.extra["labels"].as_array().unwrap().len(), 1);
        assert_eq!(note.meta.extra["review"]["round"].as_integer(), Some(2));
        let mut changed = note.clone();
        changed.meta.status = "ok".into();
        let again = Note::parse(&changed.render()).unwrap();
        assert_eq!(again.meta.extra, note.meta.extra);
        assert_eq!(again.meta.status, "ok");
        // native TOML datetime should stay a datetime
        let text =
            sample()
                .render()
                .replacen("+++\n\n", "reviewed_at = 2026-10-01T00:00:00Z\n+++\n\n", 1);
        assert!(
            Note::parse(&text)
                .unwrap()
                .render()
                .contains("\nreviewed_at = 2026-10-01T00:00:00Z\n")
        );
    }

    /// From the version before tags, plus a key from a newer one
    const OLD_NOTE: &str = r#"+++
id = "95288894"
file = "app/users.py"
start_line = 9
end_line = 9
status = "open"
author = "CodeQL"
created = "2026-10-14T15:59:00Z"
source = "CodeQL"
rule = "py/sql-injection"
fingerprint = "8eeb31a9bde35bceaec32dabb32db5a5"
snippet = """
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
context_before = "cursor = db.cursor()"
context_after = "return cursor.fetchone()"
reviewed_by = "bob"
+++

# This SQL query depends on a user-provided value.

Imported from CodeQL, rule `py/sql-injection`, level error.
"#;

    #[test]
    fn note_without_tags_round_trips_byte_for_byte() {
        let note = Note::parse(OLD_NOTE).unwrap();
        assert!(note.meta.tags.is_empty());
        assert_eq!(note.render(), OLD_NOTE);
        let mut tagged = note.clone();
        tagged.meta.tags = vec!["cwe-89".into(), "security".into()];
        let text = tagged.render();
        assert!(
            text.contains("rule = \"py/sql-injection\"\ntags = [\"cwe-89\", \"security\"]\n"),
            "{text}"
        );
        assert_eq!(Note::parse(&text).unwrap(), tagged);
    }

    #[test]
    fn tags_are_plain() {
        for bad in [
            "",
            "SQL",
            "a b",
            "[x](http://e)",
            "-x",
            "é",
            &"a".repeat(33),
        ] {
            let mut note = sample();
            note.meta.tags = vec![bad.to_string()];
            assert!(Note::parse(&note.render()).is_err(), "{bad:?}");
        }
        let mut note = sample();
        note.meta.tags = (0..=MAX_TAGS).map(|i| format!("t{i}")).collect();
        assert!(Note::parse(&note.render()).is_err());
        for (raw, want) in [
            (
                "CWE-89: Improper Neutralization of Special Elements",
                Some("cwe-89"),
            ),
            ("external/cwe/cwe-089", Some("cwe-89")),
            ("cwe_22", Some("cwe-22")),
            ("Security", Some("security")),
            ("OWASP-A01:2017 - Injection", None),
            ("python 3", None),
            ("[x](http://evil)", None),
        ] {
            assert_eq!(tag_from_scanner(raw).as_deref(), want, "{raw}");
        }
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
