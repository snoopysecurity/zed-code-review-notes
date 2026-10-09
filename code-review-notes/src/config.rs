//! Per-project settings in `.code-review-notes/config.toml`. Today that is
//! just the list of statuses a note can have.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::safety::{self, MAX_CONFIG_BYTES};

pub const FILE: &str = "config.toml";

/// How a status is drawn in the editor. Ordered most severe first, which is
/// the order reports list statuses in.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatusDef {
    pub id: String,
    pub label: String,
    pub severity: Severity,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Status for notes you add in the editor; defaults to the first status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_note_status: Option<String>,
    /// Status for imported scanner findings; defaults to the first status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_status: Option<String>,
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

/// Status ids are written into note files and shown in reports, so keep them plain.
pub fn is_valid_status_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

impl Config {
    /// Load `config.toml` from the notes directory. A missing file means the
    /// defaults; an invalid one also falls back to the defaults, with a warning.
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
        let parsed = safety::read_limited(&path, MAX_CONFIG_BYTES, FILE)
            .and_then(|t| Ok(toml::from_str::<Config>(&t)?))
            .and_then(|c| c.validate().map(|_| c));
        match parsed {
            Ok(c) => (c, None),
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

    pub fn get(&self, id: &str) -> Option<&StatusDef> {
        self.statuses.iter().find(|s| s.id == id)
    }

    /// The display label, or the raw id for a status no longer in the config.
    pub fn label<'a>(&'a self, id: &'a str) -> &'a str {
        self.get(id).map_or(id, |s| s.label.as_str())
    }

    pub fn severity(&self, id: &str) -> Severity {
        self.get(id).map_or(Severity::Warning, |s| s.severity)
    }

    /// The defaults as a commented file, for `code-review-notes init`.
    pub fn template() -> String {
        let mut out = String::from(
            "# new_note_status: status for notes you add in the editor.\n\
             # import_status:   status for imported scanner findings.\n\
             # Either can be left out to use the first [[status]].\n\
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
        // Without the two keys, both start at the first status.
        assert_eq!(c.new_note_status(), "todo");
        assert_eq!(c.import_status(), "todo");
        assert_eq!(c.severity("vulnerable"), Severity::Error);
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
        ] {
            fs::write(dir.path().join(FILE), bad).unwrap();
            let (c, warn) = Config::load(dir.path());
            assert!(warn.is_some(), "{bad}");
            assert_eq!(c, Config::default());
        }
    }
}
