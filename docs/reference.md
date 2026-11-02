# Reference

## Statuses

| Status | Meaning | Zed severity | In `cmd-shift-m`? |
| --- | --- | --- | --- |
| Open | Needs review; default for imports | warning | yes |
| Issue | Confirmed problem | error | yes |
| Question | Ask the author | info | no |
| Note | General comment; default for new notes | info | no |
| OK | Checked | hint | no |

`code-review-notes init` creates `.code-review-notes/config.toml`. Changes apply in Zed immediately. For example:

```toml
new_note_status = "todo"
import_status = "todo"
resolved_status = "not_vulnerable"

[[status]]
id = "todo"
label = "TODO"
severity = "warning"

[[status]]
id = "vulnerable"
label = "Vulnerable"
severity = "error"

[[status]]
id = "not_vulnerable"
label = "Not Vulnerable"
severity = "hint"
```

Without `new_note_status` or `import_status`, the first configured status is used. `resolved_status` defaults to `ok`. Only warning and error statuses appear in `cmd-shift-m`. Existing notes retain a status ID if you remove it from the config.

## Scanner reports

Supported inputs include SARIF from CodeQL, Semgrep, Snyk, Bandit, Gosec, and others; Brakeman JSON; and GitLab SAST and secret-detection JSON. Open the report in Zed or pass it to `code-review-notes import` from the project root.

SARIF creates one note per result, at the first location with a file and start line. The first `codeFlows` path contributes up to 20 plain-text steps. Rule metadata supplies severity, tags, and a fallback title. Suppressed results, `pass` / `notApplicable` kinds, and `baselineState: absent` are skipped. Results without a file or line are rejected.

Paths can be project-relative, relative to a SARIF `uriBaseId` or artifact index, or absolute inside the project. CI reports work if the report records a root in `originalUriBaseIds` or `invocations[].workingDirectory` at least two folders deep. If an import rejects a path, run the scanner from the project root or correct the report's paths. A missing file or out-of-range line usually means the report came from another checkout or older code.

GitLab reports use `location.file` and `start_line` / `end_line`; CWE identifiers become tags. Dependency-scanning findings have no line and cannot be attached to a note. Secret-detection notes retain the secret's line in the note and exports; revoke exposed secrets. The supported GitLab security schema is version 15, with some older reports also working.

Imports match findings by file, rule, and code rather than line number. Re-importing preserves existing statuses. `code-review-notes import --resolve-missing REPORT` changes notes from that scanner that are absent from the new report to `resolved_status` (OK by default), with a history entry. Use it only with a full scan.

Tags are lowercase labels of up to 32 letters, digits, `-`, `_`, or `.`, with a maximum of 16 per note. SARIF rule tags and GitLab CWE IDs are normalized into tags; for example, `external/cwe/cwe-089` becomes `cwe-89`. Search with `code-review-notes list --tag cwe-89` or `cmd-t`.

## Exports

`code-review-notes export -o review.md` writes Markdown grouped by status. `--format json`, `--format sarif`, and `--format gitlab-issues` are also available; `--status issue` filters by status. SARIF maps status severity to `error`, `warning`, `note`, or `none` and uses `code-review-note` as the rule for hand-written notes. GitLab issues export writes one `<id>.md` per note into the output directory. Nothing is sent to GitLab. Exports use stored snippets, not the current file on disk.

To export from Zed, add a task to `.zed/tasks.json` and run **task: spawn**:

```json
[{ "label": "Code Review Notes: export report", "command": "code-review-notes export -o code-review.md" }]
```

## Note files

Notes are Markdown with TOML front matter in `.code-review-notes/`:

```markdown
+++
id = "3ce66a51"
file = "app/users.py"
start_line = 9
end_line = 9
status = "open"
author = "Semgrep OSS"
created = "2026-10-09T15:48:12Z"
source = "Semgrep OSS"
rule = "rules.python-fstring-sql"
tags = ["cwe-89", "security"]
fingerprint = "…"
snippet = """
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
context_before = "cursor = db.cursor()"
context_after = "return cursor.fetchone()"
+++

# SQL query built with an f-string; use parameters instead

Reachable from GET /users/:id without authentication.
```

Edit the body and leave the front matter alone. Unknown keys are preserved. Status changes append a history line. Author names come from `REVIEW_NOTES_AUTHOR`, then git `user.name` (read at server start), then your login.

Notes store their code snippet and nearby lines to follow edits, re-indentation, moves, and branch switches. If at least 80% of a changed snippet survives with its surrounding context, the note follows it and is marked *changed* until you accept it or set a status. If the code disappears, the note stays at its old location marked *stale*.

Hovers show author, date, and scanner rule. Inlay hints show the status and title; enable them with `"inlay_hints": { "enabled": true }` or **editor: toggle inlay hints**. `F8` / `shift-F8` moves between notes. Note files that fail to parse appear in Zed's diagnostics panel.

## Zed agent

The optional `code-review-notes mcp` command provides `list_notes`, `get_note`, `add_note`, and `set_status`. The Zed extension does not start it automatically. Agent changes are recorded under your name with *(agent)*.

After installing the CLI, open **Settings → AI → MCP Servers** in Zed and add a local server. Set its command to `code-review-notes` and its arguments to `mcp`, `--root`, and the absolute path to your project. You can also add this entry to your Zed settings file:

```json
{
  "context_servers": {
    "code-review-notes": {
      "command": "code-review-notes",
      "args": ["mcp", "--root", "/path/to/project"]
    }
  }
}
```

Replace `/path/to/project` with the project you want the agent to use. This server connects to Zed's agent; the editor's review note actions work without it.

## Language support

The extension serves Zed's built-in languages, common extension languages, SARIF, and Plain Text. For another language, add its exact status-bar name to `languages` in `zed-extension/extension.toml` and reinstall the dev extension. Extensions cannot add keybindings; use **zed: open keymap file** to set your own:

```json
[{ "context": "Editor", "bindings": { "cmd-alt-n": "editor::ToggleCodeActions" } }]
```

## Build troubleshooting

- If extension compilation cannot find `rustc`, add `. "$HOME/.cargo/env"` to `~/.profile`, then log out and in, or launch Zed from a shell with Cargo on `PATH`.
- If `wasm32-wasip2` is missing, run `rustup target add wasm32-wasip2`.
- If Zed cannot reach `index.crates.io`, retry when the network is available; it needs to download the Rust dependency once.
- If Zed cannot run `code-review-notes`, install the binary or configure `lsp.code-review-notes.binary.path` in Zed settings.

Use **zed: open log** for Zed's log, or **dev: open language server logs** for the extension's server log.

## Security details

Paths from notes and reports must stay inside the project. Paths that escape the project, non-`file:` URIs, escaping symlinks, and a symlinked `.code-review-notes` directory are rejected. Scanner messages are Markdown-escaped, file reads are size-limited, and note files are written atomically.

Anyone with commit access can plant notes pre-marked OK, claim to be a scanner or another author, or include links. Hovers show links as plain text and flag notes from other authors or committers. Check `git log -- .code-review-notes` before a review of an untrusted repository; the Markdown export retains links. The Zed agent reads note text as data, but it can still be misled, so review its changes.
