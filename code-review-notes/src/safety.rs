//! Path confinement and size limits.
//!
//! Note files and scanner reports come from the repository under review, which
//! may be hostile. Every path taken from them goes through [`confine`] before it
//! touches the filesystem, and every read goes through [`read_limited`].

use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_NOTE_BYTES: u64 = 64 * 1024;
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub const MAX_SNIPPET_LINES: usize = 200;

#[derive(Debug, PartialEq, Eq)]
pub enum SafetyError {
    PathEscape { candidate: String },
    TooLarge { what: String, limit: u64 },
}

impl fmt::Display for SafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SafetyError::PathEscape { candidate } => {
                write!(f, "path escapes the project: {candidate:?}")
            }
            SafetyError::TooLarge { what, limit } => {
                write!(f, "{what} is larger than the {limit}-byte limit")
            }
        }
    }
}

impl std::error::Error for SafetyError {}

/// Lexical checks only: no filesystem access. Accepts a worktree-relative POSIX path.
pub fn is_relative_safe(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.contains('\0') || candidate.contains('\\') {
        return false;
    }
    if has_scheme_or_drive(candidate) {
        return false;
    }
    let path = Path::new(candidate);
    path.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// `http:`, `data:`, `C:` and friends: anything that looks like `<letters>:` up front.
pub(crate) fn has_scheme_or_drive(s: &str) -> bool {
    let Some(colon) = s.find(':') else {
        return false;
    };
    let head = &s[..colon];
    !head.is_empty()
        && head.starts_with(|c: char| c.is_ascii_alphabetic())
        && head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The local path a `file:` uri names, decoded: `file:///abs`, `file:/abs` or
/// `file://localhost/abs` (RFC 8089). Other hosts are not local files.
pub(crate) fn file_uri_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file:")?;
    let path = match rest.strip_prefix("//") {
        Some(authority_and_path) => {
            let slash = authority_and_path.find('/')?;
            let host = &authority_and_path[..slash];
            if !(host.is_empty() || host.eq_ignore_ascii_case("localhost")) {
                return None;
            }
            &authority_and_path[slash..]
        }
        None => rest,
    };
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    decoded
        .starts_with('/')
        .then(|| PathBuf::from(decoded.as_ref()))
}

/// Resolve a worktree-relative path to an absolute one, refusing anything that
/// leaves `root` — lexically (`..`, absolute, scheme) or through a symlink.
pub fn confine(root: &Path, candidate: &str) -> Result<PathBuf, SafetyError> {
    let escape = || SafetyError::PathEscape {
        candidate: candidate.to_string(),
    };
    if !is_relative_safe(candidate) {
        return Err(escape());
    }
    let root = fs::canonicalize(root).map_err(|_| escape())?;
    let joined = root.join(candidate);

    // The leaf may not exist yet, so canonicalize the deepest ancestor that does.
    let mut existing = joined.as_path();
    let mut rest = Vec::new();
    while !existing.exists() {
        rest.push(existing.file_name().ok_or_else(escape)?.to_owned());
        existing = existing.parent().ok_or_else(escape)?;
    }
    let mut resolved = fs::canonicalize(existing).map_err(|_| escape())?;
    if !resolved.starts_with(&root) {
        return Err(escape());
    }
    for part in rest.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

/// Read a file as UTF-8 (lossily), refusing anything over `limit` before reading it.
pub fn read_limited(path: &Path, limit: u64, what: &str) -> anyhow::Result<String> {
    let len = fs::metadata(path)?.len();
    if len > limit {
        return Err(SafetyError::TooLarge {
            what: what.to_string(),
            limit,
        }
        .into());
    }
    let bytes = fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_lexical_escapes() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "/etc/passwd",
            "../outside",
            "a/../../outside",
            "../../../../.ssh/id_rsa",
            "C:\\Windows",
            "C:/Windows",
            "\\\\server\\share",
            "http://evil/x",
            "data:text/plain,hi",
            "",
        ] {
            assert!(
                matches!(
                    confine(dir.path(), bad),
                    Err(SafetyError::PathEscape { .. })
                ),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_relative_paths_including_missing_leaf() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("app")).unwrap();
        fs::write(dir.path().join("app/x.rb"), "x").unwrap();
        assert!(confine(dir.path(), "app/x.rb").is_ok());
        assert!(confine(dir.path(), "app/new/y.rb").is_ok());
        assert!(confine(dir.path(), "./app/x.rb").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_out_of_root() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "key").unwrap();
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        assert!(matches!(
            confine(root.path(), "link/secret"),
            Err(SafetyError::PathEscape { .. })
        ));
    }

    #[test]
    fn read_limited_enforces_size() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big");
        fs::write(&p, vec![b'a'; 2048]).unwrap();
        assert!(read_limited(&p, 1024, "big").is_err());
        assert!(read_limited(&p, 4096, "big").is_ok());
    }
}
