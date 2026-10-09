use anyhow::Context;
use clap::{Parser, Subcommand};
use code_review_notes::{export, import, lsp, store};
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
    /// With no subcommand, runs the language server: Zed starts the binary
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
    /// Import SARIF (CodeQL, Snyk, semgrep, bandit, gosec, checkov, ...) or brakeman JSON as Open notes
    Import { report: PathBuf },
    /// Write a Markdown report of all notes
    Export {
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List notes, one per line
    List,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cmd = match cli.cmd {
        None | Some(Cmd::Lsp) => return lsp::run(),
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
        Cmd::Lsp => unreachable!(),
        Cmd::Init => {
            let path = store.config_path();
            if store.init()? {
                println!("wrote {}", path.display());
            } else {
                println!("{} already exists", path.display());
            }
        }
        Cmd::Import { report } => {
            let summary = import::import_file(&store, &config(), &report)?;
            for r in &summary.rejected {
                eprintln!("rejected: {r}");
            }
            println!("{summary}");
        }
        Cmd::Export { output } => {
            let (notes, errors) = store.load_all();
            for e in errors {
                eprintln!("skipped note {e}");
            }
            let name = store
                .root()
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut entries = export::check_staleness(&store, notes);
            let report = export::render(&name, &config(), &mut entries, chrono::Utc::now());
            match output {
                Some(path) => {
                    std::fs::write(&path, report)
                        .with_context(|| format!("writing {}", path.display()))?;
                    eprintln!("wrote {} notes to {}", entries.len(), path.display());
                }
                None => print!("{report}"),
            }
        }
        Cmd::List => {
            let config = config();
            let (notes, errors) = store.load_all();
            for e in errors {
                eprintln!("skipped note {e}");
            }
            for e in export::check_staleness(&store, notes) {
                let m = &e.note.meta;
                let label = config.label(&m.status);
                let status = if e.stale {
                    format!("{label} (stale)")
                } else {
                    label.to_string()
                };
                println!(
                    "{}  {:<16}  {}:{}-{}  {}",
                    m.id,
                    status,
                    m.file,
                    m.start_line,
                    m.end_line,
                    e.note.plain_title()
                );
            }
        }
    }
    Ok(())
}
