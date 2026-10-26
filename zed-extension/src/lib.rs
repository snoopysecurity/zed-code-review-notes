//! Thin launcher for the `code-review-notes` binary (LSP + MCP context server).
//!
//! If `lsp.code-review-notes.binary.path` is set, Zed runs it directly with
//! whatever `arguments` are configured, possibly none, and never calls us.
//! That's why the binary defaults to `lsp` with no subcommand.

use zed_extension_api::{
    self as zed, ContextServerId, LanguageServerId, Project, Result,
    settings::{ContextServerSettings, LspSettings},
};

const SERVER: &str = "code-review-notes";

/// Binary path saved in the extension's work dir for the context server.
/// Zed may start the context server before the LSP has looked for it.
const BINARY_FILE: &str = "binary-path";

#[derive(Default)]
struct CodeReviewNotes {
    /// Context server has no worktree to search PATH with, so reuse the LSP's.
    binary: Option<String>,
}

impl CodeReviewNotes {
    fn remember(&mut self, binary: &str) {
        if self.binary.as_deref() != Some(binary) {
            // best effort; context server falls back to Zed's PATH
            let _ = std::fs::write(BINARY_FILE, binary);
            self.binary = Some(binary.to_string());
        }
    }

    fn remembered(&self) -> Option<String> {
        self.binary.clone().or_else(|| {
            std::fs::read_to_string(BINARY_FILE)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
    }
}

fn exe_name() -> String {
    match zed::current_platform().0 {
        zed::Os::Windows => format!("{SERVER}.exe"),
        _ => SERVER.to_string(),
    }
}

/// `$CARGO_HOME/bin`, else `~/.cargo/bin` (`USERPROFILE` on Windows).
fn cargo_bin(env: &[(String, String)]) -> Option<String> {
    let var = |name: &str| {
        env.iter()
            .find(|(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| v.trim_end_matches(['/', '\\']).to_string())
    };
    let home = match zed::current_platform().0 {
        zed::Os::Windows => var("USERPROFILE").or_else(|| var("HOME")),
        _ => var("HOME"),
    };
    let dir = var("CARGO_HOME").or_else(|| Some(format!("{}/.cargo", home?)))?;
    Some(format!("{dir}/bin/{}", exe_name()))
}

impl zed::Extension for CodeReviewNotes {
    fn new() -> Self {
        CodeReviewNotes::default()
    }

    fn language_server_command(
        &mut self,
        _id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let args = match LspSettings::for_worktree(SERVER, worktree) {
            Ok(settings) => settings.binary.and_then(|b| b.arguments),
            Err(err) => {
                // Use the default, but don't swallow a typo in the settings silently.
                eprintln!("code-review-notes: ignoring lsp settings ({err})");
                None
            }
        }
        .unwrap_or_else(|| vec!["lsp".into()]);
        let env = worktree.shell_env();

        // Login shell PATH, then cargo's bin dir. Extensions can't stat host
        // files, so a missing binary only surfaces as Zed's "Failed to run".
        let command = worktree
            .which(SERVER)
            .or_else(|| cargo_bin(&env))
            .ok_or_else(|| {
                "code-review-notes not found: run `cargo install --path code-review-notes`, \
                 or set lsp.code-review-notes.binary.path in Zed settings"
                    .to_string()
            })?;
        self.remember(&command);

        Ok(zed::Command { command, args, env })
    }

    fn context_server_command(
        &mut self,
        _id: &ContextServerId,
        project: &Project,
    ) -> Result<zed::Command> {
        let settings = ContextServerSettings::for_project(SERVER, project)
            .ok()
            .and_then(|s| s.command);
        let (path, args, env) = match settings {
            Some(c) => (c.path, c.arguments, c.env),
            None => (None, None, None),
        };
        // Configured path, else whatever the LSP last ran (this session or a
        // previous one), else the bare name and hope it's on Zed's PATH.
        let command = path.or_else(|| self.remembered()).unwrap_or_else(exe_name);
        Ok(zed::Command {
            command,
            args: args.unwrap_or_else(|| vec!["mcp".into()]),
            env: env.map(|e| e.into_iter().collect()).unwrap_or_default(),
        })
    }
}

zed::register_extension!(CodeReviewNotes);
