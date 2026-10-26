//! Imports the real scanner output in `fixtures/`.

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

/// Returns the import summary and the notes as sorted `(file, line, title)`
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
    // related-location links become plain text
    assert_eq!(
        notes[2].2,
        "# This SQL query depends on a user-provided value."
    );
}

#[test]
fn codeql_data_flow() {
    let dir = demo_app();
    let store = Store::new(dir.path());
    import_file(&store, &Config::default(), &fixture("codeql.sarif")).unwrap();
    let notes = store.load_all().0;
    let sql = notes
        .iter()
        .find(|n| n.meta.rule.as_deref() == Some("py/sql-injection"))
        .unwrap();
    assert!(
        sql.body.contains(
            "Data flow:\n\n1. `app/users.py:7` — ControlFlowNode for user\\_id\n\
             2. `app/users.py:9` — ControlFlowNode for Fstring\n"
        ),
        "{}",
        sql.body
    );
    // `external/cwe/cwe-089` counts as a CWE id
    assert_eq!(sql.meta.tags, ["security", "cwe-89"]);
    assert_eq!(
        notes
            .iter()
            .filter(|n| n.body.contains("Data flow"))
            .count(),
        1
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

#[test]
fn gitlab_sast_report() {
    let (s, notes) = import_into_demo("gl-sast-report.json");
    assert_eq!(
        (s.imported, s.rejected.len()),
        (3, 0),
        "{s} {:?}",
        s.rejected
    );
    assert_eq!(s.tools, ["Semgrep"]);
    let at: Vec<_> = notes.iter().map(|(f, l, _)| (f.as_str(), *l)).collect();
    assert_eq!(
        at,
        [
            ("app/controllers/users_controller.rb", 7),
            ("app/users.py", 9),
            ("app/users.py", 14),
        ]
    );
    assert_eq!(
        notes[1].2,
        r"# Improper neutralization of special elements used in an SQL Command \('SQL Injection'\)"
    );
    let text = std::fs::read_to_string(fixture("gl-sast-report.json")).unwrap();
    let parsed = code_review_notes::import::parse(&text).unwrap();
    assert_eq!(
        parsed.findings[0].rule,
        "python_sql_rule-hardcoded-sql-expression"
    );
    assert_eq!(parsed.findings[0].tags, ["cwe-89"]);
    assert!(
        parsed.findings[1]
            .message
            .contains("likely false positive by vet")
    );
}

#[test]
fn gitlab_secret_detection_report() {
    let (s, notes) = import_into_demo("gl-secret-detection-report.json");
    assert_eq!(
        (s.imported, s.rejected.len()),
        (1, 0),
        "{s} {:?}",
        s.rejected
    );
    assert_eq!(s.tools, ["Gitleaks"]);
    assert_eq!(
        notes,
        [("config/settings.py".into(), 4, "# AWS access token".into())]
    );
}

#[test]
fn gitlab_dependency_findings_are_rejected_with_a_reason() {
    let (s, notes) = import_into_demo("gl-dependency-scanning-report.json");
    assert_eq!((s.imported, notes.len()), (0, 0), "{s}");
    assert_eq!(
        s.rejected,
        [
            "gemnasium-python vulnerability 1 (6c2b1a3f-0a6e-4d36-9a0f-1b0a3c6e1d2f): \
          dependency Django 3.2.0 in requirements.txt has no line to attach to"
        ]
    );
}

#[test]
fn tags_come_from_the_rule_and_identifiers() {
    let dir = demo_app();
    let store = Store::new(dir.path());
    let config = Config::default();
    import_file(&store, &config, &fixture("snyk-code.sarif")).unwrap();
    import_file(&store, &config, &fixture("gl-sast-report.json")).unwrap();
    let tags = |rule: &str| {
        store
            .load_all()
            .0
            .into_iter()
            .find(|n| n.meta.rule.as_deref() == Some(rule))
            .unwrap()
            .meta
            .tags
    };
    assert_eq!(tags("python/Sqli"), ["python", "sqli", "security"]);
    assert!(tags("python/CommandInjection").is_empty());
    assert_eq!(tags("python_sql_rule-hardcoded-sql-expression"), ["cwe-89"]);
    assert_eq!(tags("ruby_redirect_rule-CheckRedirect"), ["cwe-601"]);
}
