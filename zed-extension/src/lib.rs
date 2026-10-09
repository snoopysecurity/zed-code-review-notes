//! Launches the `code-review-notes` language server. All the logic lives in that binary.
//!
//! When `lsp.code-review-notes.binary.path` is set, Zed starts that binary
//! itself (with the setting's `arguments`, or none) and never asks us, so the
//! binary runs the language server when given no subcommand.

use zed_extension_api::{self as zed, LanguageServerId, Result, settings::LspSettings};

const SERVER: &str = "code-review-notes";

struct CodeReviewNotes;

impl zed::Extension for CodeReviewNotes {
    fn new() -> Self {
        CodeReviewNotes
    }

    fn language_server_command(
        &mut self,
        _id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let args = LspSettings::for_worktree(SERVER, worktree)
            .ok()
            .and_then(|s| s.binary)
            .and_then(|b| b.arguments)
            .unwrap_or_else(|| vec!["lsp".into()]);
        let env = worktree.shell_env();

        // `code-review-notes` on the login shell's PATH, else where `cargo
        // install` puts it. Extensions can't check that a host file exists, so
        // a missing binary shows up as Zed's "Failed to run code-review-notes".
        let command = worktree
            .which(SERVER)
            .or_else(|| {
                env.iter()
                    .find(|(k, _)| k == "HOME")
                    .map(|(_, home)| format!("{home}/.cargo/bin/{SERVER}"))
            })
            .ok_or_else(|| {
                "code-review-notes not found: run `cargo install --path code-review-notes`, \
                 or set lsp.code-review-notes.binary.path in Zed settings"
                    .to_string()
            })?;

        Ok(zed::Command { command, args, env })
    }
}

zed::register_extension!(CodeReviewNotes);
