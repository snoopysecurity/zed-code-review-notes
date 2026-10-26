//! `.code-review-notes/config.toml`. For now it only holds the note statuses.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::safety::{self, MAX_CONFIG_BYTES};

pub const FILE: &str = "config.toml";

/// How a status is drawn in the editor. Most severe first; reports use the same order.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StatusDef {
    pub id: String,
    pub label: String,
    pub severity: Severity,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    /// for notes added in the editor (default: first status)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_note_status: Option<String>,
    /// for imported findings (default: first status)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_status: Option<String>,
    /// what `import --resolve-missing` sets on findings a newer report dropped.
    /// Defaults to `ok` if there is one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_status: Option<String>,
    #[serde(rename = "status")]
    pub statuses: Vec<StatusDef>,
}

fn status(id: &str, label: &str, severity: Severity) -> StatusDef {
    StatusDef {
        id: id.into(),
        label: label.into(),
        severity,
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            new_note_status: Some("note".into()),
            import_status: Some("open".into()),
            resolved_status: Some("ok".into()),
            statuses: vec![
                status("open", "Open", Severity::Warning),
                status("issue", "Issue", Severity::Error),
                status("question", "Question", Severity::Info),
                status("note", "Note", Severity::Info),
                status("ok", "OK", Severity::Hint),
            ],
        }
    }
}

/// Ids end up in note files and reports, keep them plain
pub fn is_valid_status_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Config keys we don't recognise
fn unknown_keys(text: &str) -> Vec<String> {
    let Ok(table) = toml::from_str::<toml::Table>(text) else {
        return Vec::new();
    };
    let mut out: Vec<String> = table
        .keys()
        .filter(|k| {
            ![
                "new_note_status",
                "import_status",
                "resolved_status",
                "status",
            ]
            .contains(&k.as_str())
        })
        .map(|k| format!("`{k}`"))
        .collect();
    for (i, status) in table
        .get("status")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        for k in status.as_table().into_iter().flat_map(|t| t.keys()) {
            if !["id", "label", "severity"].contains(&k.as_str()) {
                out.push(format!("`{k}` in [[status]] {}", i + 1));
            }
        }
    }
    out
}

impl Config {
    /// Missing file means defaults. An invalid one also falls back to defaults,
    /// with a warning.
    pub fn load(dir: &Path) -> (Config, Option<String>) {
        let path = dir.join(FILE);
        match std::fs::symlink_metadata(&path) {
            Err(_) => return (Config::default(), None),
            Ok(m) if !m.is_file() => {
                return (
                    Config::default(),
                    Some(format!(
                        "{FILE} is not a regular file; using the default statuses"
                    )),
                );
            }
            Ok(_) => {}
        }
        let text = safety::read_limited(&path, MAX_CONFIG_BYTES, FILE);
        let parsed = text
            .as_deref()
            .map_err(|e| anyhow::anyhow!("{e:#}"))
            .and_then(|t| Ok(toml::from_str::<Config>(t)?))
            .and_then(|c| c.validate().map(|_| c));
        match parsed {
            // Unknown keys are allowed (configs from newer versions keep working) but
            // we name them so typos get noticed
            Ok(c) => {
                let unknown = text.as_deref().map(unknown_keys).unwrap_or_default();
                let warning = (!unknown.is_empty()).then(|| {
                    format!(
                        "{FILE}: ignoring unknown {} {} (a typo, or from a newer version?)",
                        if unknown.len() == 1 { "key" } else { "keys" },
                        unknown.join(", ")
                    )
                });
                (c, warning)
            }
            Err(e) => (
                Config::default(),
                Some(format!("{FILE}: {e:#}; using the default statuses")),
            ),
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.statuses.is_empty(),
            "at least one [[status]] is required"
        );
        for (i, s) in self.statuses.iter().enumerate() {
            anyhow::ensure!(
                is_valid_status_id(&s.id),
                "status id {:?} must be lowercase letters, digits, '_' or '-'",
                s.id
            );
            anyhow::ensure!(
                !s.label.trim().is_empty(),
                "status {:?} needs a label",
                s.id
            );
            anyhow::ensure!(
                !self.statuses[..i].iter().any(|o| o.id == s.id),
                "status {:?} is defined twice",
                s.id
            );
        }
        for (key, value) in [
            ("new_note_status", &self.new_note_status),
            ("import_status", &self.import_status),
            ("resolved_status", &self.resolved_status),
        ] {
            if let Some(id) = value {
                anyhow::ensure!(
                    self.get(id).is_some(),
                    "{key} = {id:?} is not one of the [[status]] ids"
                );
            }
        }
        Ok(())
    }

    fn first(&self) -> &str {
        &self.statuses[0].id
    }

    pub fn new_note_status(&self) -> &str {
        self.new_note_status
            .as_deref()
            .unwrap_or_else(|| self.first())
    }

    pub fn import_status(&self) -> &str {
        self.import_status
            .as_deref()
            .unwrap_or_else(|| self.first())
    }

    /// `None` if unset and there's no `ok` status to fall back on
    pub fn resolved_status(&self) -> Option<&str> {
        match &self.resolved_status {
            Some(id) => Some(id),
            None => self.get("ok").map(|s| s.id.as_str()),
        }
    }

    pub fn get(&self, id: &str) -> Option<&StatusDef> {
        self.statuses.iter().find(|s| s.id == id)
    }

    /// Falls back to the raw id for statuses that were removed from the config
    pub fn label<'a>(&'a self, id: &'a str) -> &'a str {
        self.get(id).map_or(id, |s| s.label.as_str())
    }

    pub fn severity(&self, id: &str) -> Severity {
        self.get(id).map_or(Severity::Warning, |s| s.severity)
    }

    /// Commented defaults for `code-review-notes init`
    pub fn template() -> String {
        let mut out = String::from(
            "# new_note_status: status for notes you add in the editor.\n\
             # import_status:   status for imported scanner findings.\n\
             # resolved_status: status for imported findings a later report no\n\
             #                  longer has, with `import --resolve-missing`.\n\
             # The first two can be left out to use the first [[status]]; the\n\
             # last to use `ok`.\n\
             #\n\
             # Each [[status]] has an id (stored in note files), a label (shown in\n\
             # Zed and reports) and a severity, which sets how it is drawn in Zed:\n\
             # error | warning | info | hint. Reports list statuses by severity.\n\n",
        );
        out.push_str(&toml::to_string(&Config::default()).expect("default config serializes"));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn defaults_without_file() {
        let dir = tempfile::tempdir().unwrap();
        let (c, warn) = Config::load(dir.path());
        assert!(warn.is_none());
        assert_eq!(c.new_note_status(), "note");
        assert_eq!(c.import_status(), "open");
        assert_eq!(c.label("issue"), "Issue");
        assert_eq!(c.label("gone"), "gone");
    }

    #[test]
    fn template_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), Config::template()).unwrap();
        let (c, warn) = Config::load(dir.path());
        assert!(warn.is_none(), "{warn:?}");
        assert_eq!(c, Config::default());
    }

    #[test]
    fn custom_statuses() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(FILE),
            "[[status]]\nid = \"todo\"\nlabel = \"TODO\"\nseverity = \"warning\"\n\
             [[status]]\nid = \"vulnerable\"\nlabel = \"Vulnerable\"\nseverity = \"error\"\n",
        )
        .unwrap();
        let (c, warn) = Config::load(dir.path());
        assert!(warn.is_none());
        // neither key set, both use the first status
        assert_eq!(c.new_note_status(), "todo");
        assert_eq!(c.import_status(), "todo");
        assert_eq!(c.severity("vulnerable"), Severity::Error);
        assert_eq!(c.resolved_status(), None);
        assert_eq!(Config::default().resolved_status(), Some("ok"));
    }

    #[test]
    fn ignores_keys_from_newer_versions() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(FILE),
            "future_key = true\n[[status]]\nid = \"a\"\nlabel = \"A\"\nseverity = \"hint\"\ncolor = \"red\"\n",
        )
        .unwrap();
        let (c, warn) = Config::load(dir.path());
        assert_eq!(c.label("a"), "A");
        let warn = warn.unwrap();
        assert!(
            warn.contains("`future_key`") && warn.contains("`color` in [[status]] 1"),
            "{warn}"
        );
    }

    #[test]
    fn invalid_config_falls_back_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "status = []",
            "[[status]]\nid = \"Bad Id\"\nlabel = \"x\"\nseverity = \"hint\"\n",
            "[[status]]\nid = \"a\"\nlabel = \"x\"\nseverity = \"loud\"\n",
            "[[status]]\nid = \"a\"\nlabel = \"x\"\nseverity = \"hint\"\n[[status]]\nid = \"a\"\nlabel = \"y\"\nseverity = \"hint\"\n",
            "import_status = \"nope\"\n[[status]]\nid = \"a\"\nlabel = \"x\"\nseverity = \"hint\"\n",
            "resolved_status = \"ok\"\n[[status]]\nid = \"a\"\nlabel = \"x\"\nseverity = \"hint\"\n",
        ] {
            fs::write(dir.path().join(FILE), bad).unwrap();
            let (c, warn) = Config::load(dir.path());
            assert!(warn.is_some(), "{bad}");
            assert_eq!(c, Config::default());
        }
    }
}
