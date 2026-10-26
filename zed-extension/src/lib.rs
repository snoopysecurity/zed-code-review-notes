//! Thin launcher for the `code-review-notes` binary (LSP + MCP context server).
//!
//! If `lsp.code-review-notes.binary.path` is set, Zed runs it directly with
//! whatever `arguments` are configured, possibly none, and never calls us.
//! That's why the binary defaults to `lsp` with no subcommand.

use zed_extension_api::{
    self as zed, ContextServerId, LanguageServerId, Project, Result,
    settings::{CommandSettings, ContextServerSettings, LspSettings},
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

fn exe_name(os: zed::Os) -> String {
    match os {
        zed::Os::Windows => format!("{SERVER}.exe"),
        _ => SERVER.to_string(),
    }
}

/// `$CARGO_HOME/bin`, else `~/.cargo/bin` (`USERPROFILE` on Windows).
fn cargo_bin(env: &[(String, String)], os: zed::Os) -> Option<String> {
    let var = |name: &str| {
        env.iter()
            .find(|(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| v.trim_end_matches(['/', '\\']).to_string())
    };
    let home = match os {
        zed::Os::Windows => var("USERPROFILE").or_else(|| var("HOME")),
        _ => var("HOME"),
    };
    let dir = var("CARGO_HOME").or_else(|| Some(format!("{}/.cargo", home?)))?;
    Some(format!("{dir}/bin/{}", exe_name(os)))
}

fn context_command(
    settings: Option<CommandSettings>,
    remembered: Option<String>,
    fallback: String,
) -> zed::Command {
    let (path, args, env) = match settings {
        Some(c) => (c.path, c.arguments, c.env),
        None => (None, None, None),
    };
    zed::Command {
        command: path.or(remembered).unwrap_or(fallback),
        args: args.unwrap_or_else(|| vec!["mcp".into()]),
        env: env.map(|e| e.into_iter().collect()).unwrap_or_default(),
    }
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
            .or_else(|| cargo_bin(&env, zed::current_platform().0))
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
        // Configured path, else whatever the LSP last ran (this session or a
        // previous one), else the bare name and hope it's on Zed's PATH.
        Ok(context_command(
            settings,
            self.remembered(),
            exe_name(zed::current_platform().0),
        ))
    }
}

zed::register_extension!(CodeReviewNotes);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn context_server_starts_before_language_server() {
        let command = context_command(None, None, SERVER.into());
        assert_eq!(command.command, SERVER);
        assert_eq!(command.args, ["mcp"]);
        assert!(command.env.is_empty());
    }

    #[test]
    fn context_server_uses_remembered_path_and_allows_override() {
        let command = context_command(
            None,
            Some("/cargo/bin/code-review-notes".into()),
            SERVER.into(),
        );
        assert_eq!(command.command, "/cargo/bin/code-review-notes");

        let settings = CommandSettings {
            path: Some("/custom/reviewer".into()),
            arguments: Some(vec!["serve".into()]),
            env: Some(HashMap::from([("REVIEW_MODE".into(), "test".into())])),
        };
        let command = context_command(
            settings.into(),
            Some("/cargo/bin/code-review-notes".into()),
            SERVER.into(),
        );
        assert_eq!(command.command, "/custom/reviewer");
        assert_eq!(command.args, ["serve"]);
        assert_eq!(command.env, [("REVIEW_MODE".into(), "test".into())]);
    }

    #[test]
    fn cargo_fallback_uses_home_or_cargo_home() {
        let env = vec![("HOME".into(), "/users/reviewer".into())];
        assert_eq!(
            cargo_bin(&env, zed::Os::Linux).as_deref(),
            Some("/users/reviewer/.cargo/bin/code-review-notes")
        );
        assert_eq!(
            cargo_bin(&env, zed::Os::Windows).as_deref(),
            Some("/users/reviewer/.cargo/bin/code-review-notes.exe")
        );

        let env = vec![("CARGO_HOME".into(), "/toolchain/".into())];
        assert_eq!(
            cargo_bin(&env, zed::Os::Linux).as_deref(),
            Some("/toolchain/bin/code-review-notes")
        );
    }
}
