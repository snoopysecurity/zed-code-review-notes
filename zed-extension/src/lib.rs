//! Thin launcher for the `code-review-notes` language server.
//!
//! If `lsp.code-review-notes.binary.path` is set, Zed runs it directly with
//! whatever `arguments` are configured, possibly none, and never calls us.
//! That's why the binary defaults to `lsp` with no subcommand.

use zed_extension_api::{self as zed, LanguageServerId, Result, settings::LspSettings};

const SERVER: &str = "code-review-notes";

#[derive(Default)]
struct CodeReviewNotes;

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

impl zed::Extension for CodeReviewNotes {
    fn new() -> Self {
        Self
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
        Ok(zed::Command { command, args, env })
    }
}

zed::register_extension!(CodeReviewNotes);

#[cfg(test)]
mod tests {
    use super::*;
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
