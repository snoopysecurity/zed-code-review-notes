use std::fs;
use std::path::{Path, PathBuf};

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name)
}

/// git repo with a copy of `fixtures/demo-app`
pub fn demo_app() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for rel in [
        "app/users.py",
        "app/controllers/users_controller.rb",
        "config/settings.py",
    ] {
        let to = dir.path().join(rel);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(fixture("demo-app").join(rel), to).unwrap();
    }
    fs::create_dir(dir.path().join(".git")).unwrap();
    dir
}
