//! CLI tests, running the real binary.

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
    // from a subdir, root should be found by walking up
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

    let py = root.join("app/users.py");
    let text = std::fs::read_to_string(&py).unwrap();
    let gone = text
        .lines()
        .filter(|l| !l.contains("check_output"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&py, gone).unwrap();

    let stale = stdout(&run(&sub, &["list", "--stale"]));
    assert_eq!(stale.lines().count(), 1, "{stale}");
    assert!(stale.contains("Open (stale)"), "{stale}");
    let open = stdout(&run(&sub, &["list", "--status", "open"]));
    assert_eq!(open.lines().count(), 2, "{open}");
    assert!(stdout(&run(&sub, &["list", "--status", "issue"])).is_empty());

    let stats = stdout(&run(&sub, &["stats"]));
    assert!(stats.starts_with("2 notes\n"), "{stats}");
    assert!(stats.contains("      2  Open\n"), "{stats}");
    assert!(stats.contains("      1  stale"), "{stats}");
    assert!(stats.contains("      2  Semgrep OSS"), "{stats}");

    let dry = stdout(&run(&sub, &["prune"]));
    assert!(
        dry.contains("would delete") && dry.contains("run with --yes"),
        "{dry}"
    );
    assert_eq!(stdout(&run(&sub, &["list"])).lines().count(), 2);
    let done = stdout(&run(&sub, &["prune", "--yes"]));
    assert!(done.contains("deleted 1 stale notes"), "{done}");
    let left = stdout(&run(&sub, &["list"]));
    assert_eq!(left.lines().count(), 1, "{left}");
    assert!(left.contains("app/users.py:9-9"), "{left}");
}

#[test]
fn mcp_subcommand_speaks_mcp() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = demo_app();
    let mut child = Command::new(env!("CARGO_BIN_EXE_code-review-notes"))
        .arg("mcp")
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}}}}}}"#
    )
    .unwrap();
    let out = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.contains(r#""serverInfo""#) && out.ends_with("}\n"),
        "{out}"
    );
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

#[test]
fn prune_keeps_notes_whose_file_cannot_be_read() {
    let dir = demo_app();
    let root = dir.path();
    let semgrep = fixture("semgrep.sarif");
    run(root, &["import", semgrep.to_str().unwrap()]);
    // path exists but isn't readable text. Notes look stale, yet the code
    // could still be there
    let py = root.join("app/users.py");
    std::fs::remove_file(&py).unwrap();
    std::fs::create_dir(&py).unwrap();
    let out = run(root, &["prune", "--yes"]);
    assert!(stdout(&out).contains("no stale notes"), "{}", stdout(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches("kept ").count(), 2, "{err}");
    assert_eq!(stdout(&run(root, &["list"])).lines().count(), 2);
    std::fs::remove_dir(&py).unwrap();
    assert!(stdout(&run(root, &["prune", "--yes"])).contains("deleted 2 stale notes"));
}

#[test]
fn import_resolve_missing() {
    let dir = demo_app();
    let root = dir.path();
    let semgrep = fixture("semgrep.sarif");
    run(root, &["import", semgrep.to_str().unwrap()]);
    // same scanner, nothing found this time
    let clean = root.join("clean.sarif");
    std::fs::write(
        &clean,
        r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[]}]}"#,
    )
    .unwrap();
    let out = run(root, &["import", clean.to_str().unwrap()]);
    assert!(!stdout(&out).contains("resolved"), "{}", stdout(&out));
    assert!(stdout(&run(root, &["list", "--status", "ok"])).is_empty());

    let out = run(
        root,
        &["import", "--resolve-missing", clean.to_str().unwrap()],
    );
    assert!(
        stdout(&out).contains("resolved 2 (no longer reported)"),
        "{}",
        stdout(&out)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches("resolved: ").count(), 2, "{err}");
    let ok = stdout(&run(root, &["list", "--status", "ok"]));
    assert_eq!(ok.lines().count(), 2, "{ok}");
}

#[test]
fn export_formats() {
    let dir = demo_app();
    let root = dir.path();
    let semgrep = fixture("semgrep.sarif");
    run(root, &["import", semgrep.to_str().unwrap()]);
    let brakeman = fixture("brakeman.json");
    run(root, &["import", brakeman.to_str().unwrap()]);
    let files = |out: &str| -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(out).unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .map(|n| n["meta"]["file"].as_str().unwrap().to_string())
            .collect()
    };
    let all = stdout(&run(root, &["export", "--format", "json"]));
    assert_eq!(files(&all).len(), 4, "{all}");

    let notes = root.join(".code-review-notes");
    let first = std::fs::read_dir(&notes)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "md"))
        .unwrap();
    let text = std::fs::read_to_string(&first).unwrap();
    std::fs::write(
        &first,
        text.replace("status = \"open\"", "status = \"issue\""),
    )
    .unwrap();
    let issues = stdout(&run(
        root,
        &["export", "--format", "json", "--status", "issue"],
    ));
    assert_eq!(files(&issues).len(), 1, "{issues}");
    let both = run(
        root,
        &[
            "export", "--format", "sarif", "--status", "issue", "--status", "open",
        ],
    );
    let sarif: serde_json::Value = serde_json::from_str(&stdout(&both)).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 4);

    run(
        root,
        &[
            "export",
            "--format",
            "gitlab-issues",
            "--status",
            "issue",
            "-o",
            "issues",
        ],
    );
    let written: Vec<_> = std::fs::read_dir(root.join("issues")).unwrap().collect();
    assert_eq!(written.len(), 1);
    let md = run(root, &["export", "--status", "issue"]);
    assert!(stdout(&md).contains("1 notes · 1 Issue"), "{}", stdout(&md));
}

#[test]
fn list_by_tag() {
    let dir = demo_app();
    let root = dir.path();
    let gl = fixture("gl-sast-report.json");
    run(root, &["import", gl.to_str().unwrap()]);
    let sql = stdout(&run(root, &["list", "--tag", "CWE-89"]));
    assert_eq!(sql.lines().count(), 1, "{sql}");
    assert!(sql.trim_end().ends_with("  #cwe-89"), "{sql}");
    let two = stdout(&run(root, &["list", "--tag", "cwe-89", "--tag", "cwe-078"]));
    assert_eq!(two.lines().count(), 2, "{two}");
    assert!(stdout(&run(root, &["list", "--tag", "cwe-1"])).is_empty());
    let bad = Command::new(env!("CARGO_BIN_EXE_code-review-notes"))
        .args(["list", "--tag", "SQL injection"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("is not a tag"));
}
