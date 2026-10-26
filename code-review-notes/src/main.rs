use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use code_review_notes::note::tag_from_scanner;
use code_review_notes::{export, import, lsp, mcp, store};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "code-review-notes",
    version,
    about = "Code review notes for Zed, with SAST import"
)]
struct Cli {
    /// Project root (default: nearest directory above the cwd with .code-review-notes/ or .git/)
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    /// With no subcommand, runs the language server. Zed starts the binary
    /// with no arguments when `lsp.code-review-notes.binary.path` is set.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the language server on stdio (started by the Zed extension)
    Lsp,
    /// Write .code-review-notes/config.toml with the default statuses, ready to edit
    Init,
    /// Import SARIF (CodeQL, Snyk, semgrep, bandit, gosec, checkov, ...), a GitLab security report or brakeman JSON as Open notes
    Import {
        report: PathBuf,
        /// Mark findings from the report's tools that it no longer has as resolved
        /// (`resolved_status` in config.toml, default OK). Use a report of a full scan.
        #[arg(long)]
        resolve_missing: bool,
    },
    /// Export the notes: a Markdown report, JSON, SARIF, or GitLab issue bodies
    Export {
        #[arg(long, value_enum, default_value_t = Format::Markdown)]
        format: Format,
        /// Only notes with this status id (repeatable)
        #[arg(long)]
        status: Vec<String>,
        /// Output file (default: stdout); a directory for gitlab-issues
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List notes, one per line
    List {
        /// Only notes with this status id (repeatable)
        #[arg(long)]
        status: Vec<String>,
        /// Only notes whose code is gone
        #[arg(long)]
        stale: bool,
        /// Only notes whose code has been edited since
        #[arg(long)]
        changed: bool,
        /// Only notes with this tag, such as cwe-89 (repeatable)
        #[arg(long)]
        tag: Vec<String>,
    },
    /// Count notes by status, by scanner, and stale or changed
    Stats,
    /// Delete notes whose code is gone; lists them unless given --yes
    Prune {
        /// Delete them
        #[arg(long)]
        yes: bool,
    },
    /// Run an MCP server on stdio so Zed's agent can read and change notes
    Mcp,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// A report grouped by status
    Markdown,
    /// One object per note
    Json,
    /// SARIF 2.1.0, one result per note
    Sarif,
    /// One Markdown file per note, `<id>.md`, with the title on the first line
    GitlabIssues,
}

/// All notes with their gone/changed state. Unreadable ones go to stderr
fn load_entries(store: &store::Store) -> Vec<export::Entry> {
    let (notes, errors) = store.load_all();
    for e in errors {
        eprintln!("skipped note {e}");
    }
    export::check_staleness(store, notes)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cmd = match cli.cmd {
        None | Some(Cmd::Lsp) => return lsp::run(),
        // works out its own root (--root, client roots, or cwd)
        Some(Cmd::Mcp) => return mcp::run(cli.root),
        Some(cmd) => cmd,
    };
    let cwd = std::env::current_dir()?;
    let root = cli.root.unwrap_or_else(|| store::discover(&cwd));
    let store = store::Store::new(&root);
    let config = || {
        let (config, warning) = store.config();
        if let Some(w) = warning {
            eprintln!("warning: {w}");
        }
        config
    };

    match cmd {
        Cmd::Lsp | Cmd::Mcp => unreachable!(),
        Cmd::Init => {
            let path = store.config_path();
            if store.init()? {
                println!("wrote {}", path.display());
            } else {
                println!("{} already exists", path.display());
            }
        }
        Cmd::Import {
            report,
            resolve_missing,
        } => {
            let options = import::Options { resolve_missing };
            let summary = import::import_file_with(&store, &config(), &report, options)?;
            for r in &summary.rejected {
                eprintln!("rejected: {r}");
            }
            for r in summary.resolved.iter().flatten() {
                eprintln!("resolved: {r}");
            }
            println!("{summary}");
        }
        Cmd::Export {
            format,
            status,
            output,
        } => {
            let config = config();
            for s in status.iter().filter(|s| config.get(s).is_none()) {
                eprintln!("warning: {s:?} is not a status in config.toml");
            }
            let mut entries = load_entries(&store);
            entries.retain(|e| status.is_empty() || status.contains(&e.note.meta.status));
            let report = match format {
                Format::Markdown => {
                    let name = store
                        .root()
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    export::render(&name, &config, &mut entries, chrono::Utc::now())
                }
                Format::Json => export::render_json(&config, &mut entries),
                Format::Sarif => export::render_sarif(&config, &mut entries),
                Format::GitlabIssues => {
                    let dir = output.context("gitlab-issues needs a directory: -o DIR")?;
                    std::fs::create_dir_all(&dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                    let issues = export::render_gitlab_issues(&config, &mut entries);
                    for (name, text) in &issues {
                        let path = dir.join(name);
                        std::fs::write(&path, text)
                            .with_context(|| format!("writing {}", path.display()))?;
                    }
                    eprintln!("wrote {} issues to {}", issues.len(), dir.display());
                    return Ok(());
                }
            };
            match output {
                Some(path) => {
                    std::fs::write(&path, report)
                        .with_context(|| format!("writing {}", path.display()))?;
                    eprintln!("wrote {} notes to {}", entries.len(), path.display());
                }
                None => print!("{report}"),
            }
        }
        Cmd::List {
            status,
            stale,
            changed,
            tag,
        } => {
            let config = config();
            let tag = tag
                .iter()
                .map(|t| tag_from_scanner(t).with_context(|| format!("{t:?} is not a tag")))
                .collect::<anyhow::Result<Vec<String>>>()?;
            for e in load_entries(&store) {
                let m = &e.note.meta;
                if (!status.is_empty() && !status.contains(&m.status))
                    || (stale && !e.stale)
                    || (changed && !e.changed)
                    || (!tag.is_empty() && !m.tags.iter().any(|t| tag.contains(t)))
                {
                    continue;
                }
                let tags: String = m.tags.iter().map(|t| format!("  #{t}")).collect();
                println!(
                    "{}  {:<16}  {}:{}-{}  {}{tags}",
                    m.id,
                    format!("{}{}", config.label(&m.status), e.state()),
                    m.file,
                    m.start_line,
                    m.end_line,
                    e.note.plain_title()
                );
            }
        }
        Cmd::Stats => {
            let config = config();
            let entries = load_entries(&store);
            println!("{} notes", entries.len());
            let mut defs: Vec<_> = config.statuses.iter().collect();
            defs.sort_by_key(|d| d.severity);
            let mut ids: Vec<(&str, &str)> = defs
                .iter()
                .map(|d| (d.id.as_str(), d.label.as_str()))
                .collect();
            for e in &entries {
                let id = e.note.meta.status.as_str();
                if !ids.iter().any(|(i, _)| *i == id) {
                    ids.push((id, id));
                }
            }
            for (id, label) in ids {
                let n = entries.iter().filter(|e| e.note.meta.status == id).count();
                if n > 0 {
                    println!("  {n:>5}  {label}");
                }
            }
            let stale = entries.iter().filter(|e| e.stale).count();
            let changed = entries.iter().filter(|e| e.changed).count();
            println!(
                "  {stale:>5}  stale (code gone)\n  {changed:>5}  changed (code edited since)"
            );
            let mut sources: std::collections::BTreeMap<&str, usize> = Default::default();
            for e in &entries {
                *sources
                    .entry(e.note.meta.source.as_deref().unwrap_or("written by hand"))
                    .or_default() += 1;
            }
            println!("by source:");
            for (source, n) in sources {
                println!("  {n:>5}  {source}");
            }
        }
        Cmd::Prune { yes } => {
            let config = config();
            let (stale, unreadable): (Vec<_>, Vec<_>) = load_entries(&store)
                .into_iter()
                .filter(|e| e.stale)
                .partition(|e| e.is_gone());
            // can't read the file, so the code might still be there; keep them
            for e in &unreadable {
                eprintln!(
                    "kept {}: {} can't be read ({})",
                    e.note.meta.id,
                    e.note.meta.file,
                    e.unreadable.as_deref().unwrap_or_default()
                );
            }
            for e in &stale {
                let m = &e.note.meta;
                if yes {
                    store.delete(&m.id)?;
                }
                println!(
                    "{}  {}  {:<16}  {}:{}-{}  {}",
                    if yes { "deleted" } else { "would delete" },
                    m.id,
                    config.label(&m.status),
                    m.file,
                    m.start_line,
                    m.end_line,
                    e.note.plain_title()
                );
            }
            match (stale.len(), yes) {
                (0, _) => println!("no stale notes"),
                (n, false) => println!("{n} stale notes; run with --yes to delete them"),
                (n, true) => println!("deleted {n} stale notes"),
            }
        }
    }
    Ok(())
}
