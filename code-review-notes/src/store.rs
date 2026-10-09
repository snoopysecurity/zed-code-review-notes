//! `.code-review-notes/` on disk: one `<id>.md` file per note.

use anyhow::Context;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::note::{Note, is_valid_id};
use crate::safety::{self, MAX_NOTE_BYTES, MAX_SOURCE_BYTES};

pub const DIR: &str = ".code-review-notes";

pub struct Store {
    root: PathBuf,
    dir: PathBuf,
}

/// Walk up from `start` to the nearest directory holding `.code-review-notes/` or `.git/`.
pub fn discover(start: &Path) -> PathBuf {
    let start = fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    start
        .ancestors()
        .find(|d| d.join(DIR).is_dir() || d.join(".git").exists())
        .unwrap_or(&start)
        .to_path_buf()
}

/// Read and check one note file, refusing symlinks planted in the store.
fn read_note(path: &Path) -> anyhow::Result<Note> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if fs::symlink_metadata(path).is_ok_and(|m| !m.is_file()) {
        anyhow::bail!("not a regular file");
    }
    let note = Note::parse(&safety::read_limited(path, MAX_NOTE_BYTES, &name)?)?;
    anyhow::ensure!(
        path.file_stem().is_some_and(|s| *s == *note.meta.id),
        "id {:?} does not match the file name",
        note.meta.id
    );
    Ok(note)
}

impl Store {
    pub fn new(root: &Path) -> Store {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        Store {
            dir: root.join(DIR),
            root,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The store directory, unless it is a symlink: a hostile repository could
    /// point `.code-review-notes` outside the project to have us read or write
    /// there. Fine if it does not exist yet.
    fn checked_dir(&self) -> anyhow::Result<&Path> {
        match fs::symlink_metadata(&self.dir) {
            Ok(m) if m.file_type().is_symlink() => Err(safety::SafetyError::PathEscape {
                candidate: format!("{DIR} (a symlink)"),
            }
            .into()),
            _ => Ok(&self.dir),
        }
    }

    /// The project's statuses, plus a warning if `config.toml` was invalid.
    pub fn config(&self) -> (Config, Option<String>) {
        match self.checked_dir() {
            Ok(dir) => Config::load(dir),
            Err(e) => (
                Config::default(),
                Some(format!("{e:#}; using the default statuses")),
            ),
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.join(crate::config::FILE)
    }

    /// Write the default `config.toml` if there is none. Returns whether it wrote one.
    pub fn init(&self) -> anyhow::Result<bool> {
        let path = self.config_path();
        if path.exists() {
            return Ok(false);
        }
        self.write_atomic(&path, Config::template().as_bytes())?;
        Ok(true)
    }

    pub fn note_path(&self, id: &str) -> PathBuf {
        debug_assert!(is_valid_id(id));
        self.dir.join(format!("{id}.md"))
    }

    /// Load every note. Unreadable or invalid files are reported and skipped, so
    /// one bad file never hides the rest.
    pub fn load_all(&self) -> (Vec<Note>, Vec<String>) {
        let mut notes = Vec::new();
        let mut errors = Vec::new();
        let dir = match self.checked_dir() {
            Ok(dir) => dir,
            Err(e) => {
                errors.push(format!("{e:#}"));
                return (notes, errors);
            }
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return (notes, errors);
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "md"))
            .collect();
        paths.sort();
        for path in paths {
            match read_note(&path) {
                Ok(note) => notes.push(note),
                Err(e) => {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    errors.push(format!("{name}: {e:#}"));
                }
            }
        }
        (notes, errors)
    }

    /// Load one note from disk.
    pub fn load(&self, id: &str) -> anyhow::Result<Note> {
        self.checked_dir()?;
        read_note(&self.note_path(id))
    }

    /// A project file's text, for locating notes in it.
    pub fn read_source(&self, rel: &str) -> anyhow::Result<String> {
        let path = safety::confine(self.root(), rel)?;
        safety::read_limited(&path, MAX_SOURCE_BYTES, rel)
    }

    pub fn save(&self, note: &Note) -> anyhow::Result<PathBuf> {
        let path = self.note_path(&note.meta.id);
        self.write_atomic(&path, note.render().as_bytes())?;
        Ok(path)
    }

    pub fn delete(&self, id: &str) -> anyhow::Result<()> {
        self.checked_dir()?;
        fs::remove_file(self.note_path(id)).with_context(|| format!("deleting note {id}"))
    }

    /// Write to a temp file in the store, fsync, then rename over the target, so
    /// a crash leaves either the old note or the new one, never half of one.
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        self.checked_dir()?;
        fs::create_dir_all(&self.dir).context("creating .code-review-notes/")?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".tmp-")
            .tempfile_in(&self.dir)?;
        tmp.write_all(bytes)?;
        // Temp files are created private (0600); notes are ordinary project files.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        tmp.as_file().sync_all()?;
        tmp.persist(path)?;
        fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// A fresh id that no existing note uses.
    pub fn new_id(&self, seed: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let hash =
            blake3::hash(format!("{seed}\0{nanos}\0{}", std::process::id()).as_bytes()).to_hex();
        (8..=32)
            .step_by(4)
            .map(|n| hash[..n].to_string())
            .find(|id| !self.note_path(id).exists())
            .unwrap_or_else(|| hash[..32].to_string())
    }

    /// `REVIEW_NOTES_AUTHOR`, then git `user.name`, then the OS user.
    pub fn author(&self) -> String {
        if let Ok(a) = std::env::var("REVIEW_NOTES_AUTHOR")
            && !a.trim().is_empty()
        {
            return a.trim().to_string();
        }
        let git = std::process::Command::new("git")
            .args(["config", "user.name"])
            .current_dir(&self.root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty());
        git.or_else(|| std::env::var("USER").ok())
            .or_else(|| std::env::var("USERNAME").ok())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Worktree-relative POSIX path for an absolute path inside the root.
    pub fn relative(&self, abs: &Path) -> Option<String> {
        let abs = fs::canonicalize(abs).unwrap_or_else(|_| abs.to_path_buf());
        let rel = abs.strip_prefix(&self.root).ok()?;
        let s = rel
            .components()
            .map(|c| c.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()?
            .join("/");
        safety::is_relative_safe(&s).then_some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::Meta;

    fn note(id: &str) -> Note {
        Note {
            meta: Meta {
                id: id.into(),
                file: "a.rb".into(),
                start_line: 1,
                end_line: 1,
                status: "open".into(),
                author: "t".into(),
                created: "2026-10-09T10:00:00Z".parse().unwrap(),
                source: None,
                rule: None,
                fingerprint: None,
                snippet: "x".into(),
            },
            body: "hi".into(),
        }
    }

    #[test]
    fn save_load_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let ids: Vec<String> = (0..20).map(|i| store.new_id(&i.to_string())).collect();
        for id in &ids {
            store.save(&note(id)).unwrap();
        }
        for id in &ids[..5] {
            store.delete(id).unwrap();
        }
        let (notes, errors) = store.load_all();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(notes.len(), 15);
        // No temp files left behind.
        let leftovers = fs::read_dir(store.dir())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.note_path(&ids[10]))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644);
        }
    }

    #[test]
    fn bad_files_are_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        store.save(&note("aaaaaaaa")).unwrap();
        fs::write(store.dir().join("broken.md"), "nope").unwrap();
        fs::write(store.dir().join("bbbbbbbb.md"), note("cccccccc").render()).unwrap();
        let (notes, errors) = store.load_all();
        assert_eq!(notes.len(), 1);
        assert_eq!(errors.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_store_is_refused() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("aaaaaaaa.md"),
            note("aaaaaaaa").render(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(DIR)).unwrap();
        let store = Store::new(dir.path());
        assert!(store.init().is_err());
        assert!(store.save(&note("bbbbbbbb")).is_err());
        assert!(store.delete("aaaaaaaa").is_err());
        let (notes, errors) = store.load_all();
        assert!(notes.is_empty() && errors.len() == 1, "{errors:?}");
        assert!(store.config().1.is_some());
        let mut left: Vec<_> = fs::read_dir(outside.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["aaaaaaaa.md"]);
    }

    #[test]
    fn init_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        assert!(store.init().unwrap());
        fs::write(store.dir().join("config.toml"), "# edited").unwrap();
        assert!(!store.init().unwrap());
        assert_eq!(
            fs::read_to_string(store.dir().join("config.toml")).unwrap(),
            "# edited"
        );
    }
}
