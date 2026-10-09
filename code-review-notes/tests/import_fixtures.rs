//! Importing the real scanner output in `fixtures/`.

mod common;

use code_review_notes::config::Config;
use code_review_notes::import::{Summary, import_file};
use code_review_notes::store::Store;
use common::{demo_app, fixture};

#[test]
fn real_scanner_output() {
    let dir = demo_app();
    let store = Store::new(dir.path());
    let config = Config::default();
    let s = import_file(&store, &config, &fixture("semgrep.sarif")).unwrap();
    assert_eq!(
        (s.imported, s.rejected.len()),
        (2, 0),
        "{s} {:?}",
        s.rejected
    );
    let s = import_file(&store, &config, &fixture("brakeman.json")).unwrap();
    assert_eq!(
        (s.imported, s.rejected.len()),
        (2, 0),
        "{s} {:?}",
        s.rejected
    );
    let mut at: Vec<(String, u32)> = store
        .load_all()
        .0
        .into_iter()
        .map(|n| (n.meta.file, n.meta.start_line))
        .collect();
    at.sort();
    assert_eq!(
        at,
        [
            ("app/controllers/users_controller.rb".into(), 3),
            ("app/controllers/users_controller.rb".into(), 7),
            ("app/users.py".into(), 9),
            ("app/users.py".into(), 14),
        ]
    );
    for report in ["semgrep.sarif", "brakeman.json"] {
        let s = import_file(&store, &config, &fixture(report)).unwrap();
        assert_eq!((s.imported, s.skipped), (0, 2), "{report}: {s}");
    }
}

#[test]
fn adversarial_fixture() {
    let dir = demo_app();
    let store = Store::new(dir.path());
    let s = import_file(&store, &Config::default(), &fixture("adversarial.sarif")).unwrap();
    assert_eq!((s.imported, s.rejected.len()), (1, 3), "{:?}", s.rejected);
    let notes = store.load_all().0;
    assert_eq!(notes[0].meta.file, "app/users.py");
    assert!(
        notes[0].body.contains(r"\]\(http://evil\)"),
        "{}",
        notes[0].body
    );
}

/// Imports `report` into a fresh demo app; returns the summary and the notes
/// as `(file, line, title)`, sorted.
fn import_into_demo(report: &str) -> (Summary, Vec<(String, u32, String)>) {
    let dir = demo_app();
    let store = Store::new(dir.path());
    let config = Config::default();
    let s = import_file(&store, &config, &fixture(report)).unwrap();
    let again = import_file(&store, &config, &fixture(report)).unwrap();
    assert_eq!(
        (again.imported, again.skipped),
        (0, s.imported),
        "{report} re-imported: {again}"
    );
    let mut notes: Vec<_> = store
        .load_all()
        .0
        .into_iter()
        .map(|n| {
            let title = n.body.lines().next().unwrap_or_default().to_string();
            (n.meta.file, n.meta.start_line, title)
        })
        .collect();
    notes.sort();
    (s, notes)
}

#[test]
fn codeql_rules_in_extensions_and_artifact_index() {
    let (s, notes) = import_into_demo("codeql.sarif");
    assert_eq!(
        (s.imported, s.rejected.len()),
        (4, 0),
        "{s} {:?}",
        s.rejected
    );
    assert_eq!(s.tools, ["CodeQL"]);
    let at: Vec<_> = notes.iter().map(|(f, l, _)| (f.as_str(), *l)).collect();
    assert_eq!(
        at,
        [
            ("app/controllers/users_controller.rb", 3),
            ("app/controllers/users_controller.rb", 7),
            ("app/users.py", 9),
            ("app/users.py", 14),
        ]
    );
    // Links to related locations become plain text.
    assert_eq!(
        notes[2].2,
        "# This SQL query depends on a user-provided value."
    );
}

#[test]
fn codeql_level_comes_from_the_extension_rule() {
    let dir = demo_app();
    let store = Store::new(dir.path());
    import_file(&store, &Config::default(), &fixture("codeql.sarif")).unwrap();
    let notes = store.load_all().0;
    assert!(
        notes.iter().all(|n| n.body.contains("level error")),
        "{:?}",
        notes.iter().map(|n| &n.body).collect::<Vec<_>>()
    );
}

#[test]
fn snyk_code_skips_ignored_issues() {
    let (s, notes) = import_into_demo("snyk-code.sarif");
    assert_eq!(
        (s.imported, s.ignored, s.rejected.len()),
        (2, 1, 0),
        "{s} {:?}",
        s.rejected
    );
    let at: Vec<_> = notes.iter().map(|(f, l, _)| (f.as_str(), *l)).collect();
    assert_eq!(at, [("app/users.py", 9), ("app/users.py", 14)]);
    assert!(
        notes[0]
            .2
            .starts_with("# Unsanitized input from a function argument flows into execute")
    );
}

#[test]
fn sarif_spec_edge_cases() {
    let (s, notes) = import_into_demo("sarif-spec-edges.sarif");
    assert_eq!(
        (s.imported, s.ignored, s.rejected.len()),
        (3, 3, 2),
        "{s} {:?}",
        s.rejected
    );
    assert_eq!(s.tools, ["spec-edges", "wd-tool"]);
    assert_eq!(
        notes,
        [
            (
                "app/controllers/users_controller.rb".into(),
                3,
                r"# Query interpolates {{params}}: \[id\] reaches the query, see \[docs\]\(https://example.com\)".into()
            ),
            (
                "app/users.py".into(),
                9,
                r"# Tainted user\_id reaches execute; literal {braces}".into()
            ),
            ("app/users.py".into(), 14, "# Global template for host".into()),
        ]
    );
    assert!(
        s.rejected.iter().any(|r| r.contains("etc/passwd")),
        "{:?}",
        s.rejected
    );
}
