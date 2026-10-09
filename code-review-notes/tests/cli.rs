//! The `code-review-notes` command line, run as a real process.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::{demo_app, fixture};

fn run(dir: &Path, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_code-review-notes"))
        .args(args)
        .current_dir(dir)
        .env("REVIEW_NOTES_AUTHOR", "tester")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

#[test]
fn init_import_list_export() {
    let dir = demo_app();
    let root = dir.path();
    // Run from a subdirectory: the project root is found by walking up.
    let sub = root.join("app");

    assert!(stdout(&run(&sub, &["init"])).starts_with("wrote "));
    assert!(root.join(".code-review-notes/config.toml").is_file());
    assert!(stdout(&run(&sub, &["init"])).contains("already exists"));

    let semgrep = fixture("semgrep.sarif");
    let out = stdout(&run(&sub, &["import", semgrep.to_str().unwrap()]));
    assert!(out.contains("imported 2, skipped 0"), "{out}");

    let list = stdout(&run(&sub, &["list"]));
    assert_eq!(list.lines().count(), 2, "{list}");
    assert!(list.contains("app/users.py:9-9"), "{list}");

    run(&sub, &["export", "-o", "review.md"]);
    let report = std::fs::read_to_string(sub.join("review.md")).unwrap();
    assert!(report.starts_with("# Code review: "), "{report}");
    assert!(report.contains("2 notes · 2 Open"), "{report}");
}

#[test]
fn no_subcommand_runs_the_language_server() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_code-review-notes"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}"#;
    write!(
        child.stdin.take().unwrap(),
        "Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let out = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    assert!(out.contains(r#""capabilities""#), "{out}");
}
