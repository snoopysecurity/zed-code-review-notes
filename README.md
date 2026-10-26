# Code Review Notes for Zed

Code Review Notes is a Zed extension for adding review notes to code and importing findings from SAST tools. Notes are Markdown files in `.code-review-notes/` at the project root.

## Install

Install Rust with [rustup](https://rustup.rs), then run these commands from the repository root:

```sh
cargo install --path code-review-notes
```

In Zed, run **zed: install dev extension** and select `zed-extension/`. Trust the project if Zed shows *Restricted Mode*. You should then see **Add review note** in the code actions menu.

After changing the Rust code, run `cargo install --path code-review-notes` again and restart the language server. After changing `zed-extension/`, reinstall the dev extension.

## Quick start

1. Select some lines, open the code actions (right-click → **Show Code Actions**, or `cmd-.`) and pick **Add review note**. Type over the placeholder title, write the note, save.
2. On a noted line, use the code actions to **Mark Issue**, **Mark Question**, **Mark OK** and so on.
3. Open a `.sarif` file (or a brakeman or GitLab `.json` report) and run **Import into Code Review Notes**. Each finding becomes an Open note.
4. `cmd-shift-m` shows what's still Open or an Issue. `cmd-t` finds any note, e.g. `redirect` or `issue sql`.
5. `code-review-notes export -o review.md` writes a report.

## In the editor

Everything is in the code actions menu.

| Action | Where |
| --- | --- |
| **Add review note** | any line or selection |
| **Mark Open / Issue / Question / Note / OK** | on a noted line, or inside a note file |
| **Accept edited code** | on a note marked *changed*, once you've checked the new code |
| **Open review note** / **Delete review note** | on a noted line |
| **Import into Code Review Notes** | in an open `.sarif` file, or a `.json` file with SARIF, a GitLab report or brakeman output |

The hover shows author, date and the scanner rule for imports. It flags notes you didn't write, and names whoever last committed a note if it wasn't you. Links are shown as `text (url)`, not clickable. Underlines update about 150 ms after you stop typing.

Inlay hints show `◆ [Status] title` on each note's first line. Turn them on with `"inlay_hints": { "enabled": true }` or **editor: toggle inlay hints**.

`cmd-t` fuzzy-matches every note as `[Status] title #tag` (not by file name). `cmd-shift-m` lists Open and Issue notes across all files except gitignored ones. Zed's panel only shows errors and warnings, and those are the two statuses mapped to them by default. `F8` / `shift-F8` jump between notes in the file. Note files that fail to parse show a message and appear in the diagnostics panel with the reason.

Notes work in Zed's built-in languages, common extension languages (Ruby and ERB, PHP, Java, Vue, Svelte and others) and Plain Text. For anything else, add the exact language name to `zed-extension/extension.toml`. Extensions can't add keybindings, but you can (**zed: open keymap file**):

```json
[{ "context": "Editor", "bindings": { "cmd-alt-n": "editor::ToggleCodeActions" } }]
```

### How notes follow the code

Each note stores the snippet it was made on and finds it again after edits, re-indenting, moves or a branch switch. The new position is written to the note when you save the file. If the code was edited in place and at least 80% of it survives (weighted towards the longer lines), the note stays and is marked *changed* until you **Accept edited code** or set a status.

Similarity alone would let a note jump to a look-alike, such as `if (authorized)` next to the `if (!authorized)` it was made on. So each note also records its nearest line above and below, and edited code only matches if those neighbours are still around it. If the code is gone, the note stays at its old position marked *stale*.

## Statuses

| Status | Meaning | Shown as | In `cmd-shift-m`? |
| --- | --- | --- | --- |
| **Open** | needs looking at; imports start here | warning (yellow) | yes |
| **Issue** | a real problem | error (red) | yes |
| **Question** | something to ask the author | info (blue) | no |
| **Note** | a remark; notes you add start here | info (blue) | no |
| **OK** | checked, nothing wrong | hint (faint) | no |

`code-review-notes init` writes `.code-review-notes/config.toml`. Edits apply in Zed immediately. For a security review:

```toml
new_note_status = "todo"   # status for notes you add
import_status = "todo"     # status for imported findings
resolved_status = "not_vulnerable"   # for findings a later scan no longer reports

[[status]]
id = "todo"
label = "TODO"
severity = "warning"       # error | warning | info | hint

[[status]]
id = "vulnerable"
label = "Vulnerable"
severity = "error"

[[status]]
id = "not_vulnerable"
label = "Not Vulnerable"
severity = "hint"
```

Missing `new_note_status` or `import_status` means the first status. `resolved_status` defaults to `ok`. Only `warning` and `error` show in `cmd-shift-m`. A note whose status is removed from the config keeps the raw id.

## Importing scanner output

```sh
semgrep --config auto --sarif -o semgrep.sarif .
codeql database analyze db --format=sarif-latest --output=codeql.sarif
snyk code test --sarif-file-output=snyk-code.sarif
snyk test --sarif-file-output=snyk-oss.sarif   # dependency findings land on the manifest file
bandit -r . -f sarif -o bandit.sarif           # needs bandit[sarif]
gosec -fmt sarif -out gosec.sarif ./...
checkov -d . -o sarif
brakeman -f json -o brakeman.json
```

Then use **Import into Code Review Notes** in Zed, or `code-review-notes import semgrep.sarif` from the project root. Each finding becomes an Open note (or `import_status`) titled with the scanner message. Findings are matched on file, rule and code, not line number. Re-importing adds nothing and leaves statuses alone, even after code moves. The semgrep and brakeman files in `fixtures/` are real output; the CodeQL, Snyk Code and GitLab ones are hand-written (GitLab schema 15.2.5).

### Marking fixed findings

`code-review-notes import --resolve-missing semgrep.sarif` gives `resolved_status` (OK by default) to notes previously imported from the same tool that the report no longer has, with a history line like *Not reported by Semgrep OSS on 2026-10-14.* Other notes are untouched. Use a full scan with your usual rules, or anything the scan skipped gets marked resolved. CLI only.

### SARIF details

One note per result, on the first location with a file and start line. For `codeFlows` (CodeQL and Snyk Code injection findings), the note lists up to 20 steps of the first path as plain text. Rule metadata supplies level, [tags](#tags) and a fallback title. CodeQL-style `[text](1)` links become plain text.

Paths can be project-relative (run the scanner from the root), relative to a `uriBaseId`, an `artifacts` index, or absolute inside the project. CI reports work if their paths start with a recorded root (`originalUriBaseIds` or `invocations[].workingDirectory`) at least two folders deep.

Suppressed results, `pass`/`notApplicable` kinds and `baselineState: absent` are skipped. Results with no file or line are rejected.

### GitLab security reports

`gl-sast-report.json`, `gl-secret-detection-report.json` and `gl-dependency-scanning-report.json` from CI job artifacts, per the [security report schemas](https://gitlab.com/gitlab-org/security-products/security-report-schemas) (version 15; older mostly work). Notes land on `location.file` lines `start_line` to `end_line`. CWE identifiers become tags. Dependency-scanning findings are rejected because they have no line. Secret-detection notes keep the secret's line in their snippet, so the secret ends up in the note file and in every export. Revoke it.

### If findings are rejected

| Summary says | Fix |
|---|---|
| `path outside the project or unsupported uri` | Run the scanner from the project root with relative output, or rewrite the paths. |
| `No such file or directory` / `line is past the end of the file` | Report is from another checkout or older code. Re-run the scanner. |
| `no file location` / `has no start line` | Not about a line of code. |
| `dependency … has no line to attach to` | A GitLab dependency-scanning finding. |

## Report and list

```sh
code-review-notes list                     # one line per note, stale and changed ones marked
code-review-notes list --status issue      # only Issues (repeatable); also --stale, --changed
code-review-notes list --tag cwe-89        # only notes with this tag (repeatable)
code-review-notes stats                    # counts by status, stale and changed, and by scanner
code-review-notes prune                    # lists notes whose code is gone; --yes deletes them
code-review-notes export -o review.md      # Markdown report grouped by status
code-review-notes export --format json     # also sarif, gitlab-issues; --status issue (repeatable)
```

`sarif` maps status severity to `error`, `warning`, `note` or `none`, and uses `code-review-note` as the rule for hand-written notes. `gitlab-issues` writes one `<id>.md` per note into the `-o` directory (title on the first line). Nothing is sent to GitLab, and note text is fenced so it can't trigger quick actions or mentions. Every export uses the stored snippet, never the file on disk.

To export from Zed, add a task to `.zed/tasks.json` and run **task: spawn**:

```json
[{ "label": "Code Review Notes: export report", "command": "code-review-notes export -o code-review.md" }]
```

## Zed's agent

The extension adds a context server with `list_notes`, `get_note` (includes the current code if it changed), `add_note` and `set_status`. Enable *code-review-notes* in the agent panel settings, then ask something like *"go through the Open notes in app/ and mark the false positives OK, saying why"*. The agent's changes are recorded under your name with *(agent)*.

It uses the same binary as the language server, falling back to `code-review-notes` on Zed's `PATH` on first run. If it can't start or says *the project folder is not known*, configure it:

```json
{ "context_servers": { "code-review-notes": { "command": { "path": "code-review-notes", "arguments": ["mcp", "--root", "/path/to/project"] } } } }
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| *compiling Rust extension* fails with `running rustc: No such file or directory` | Zed was launched without Cargo on `PATH`. Add `. "$HOME/.cargo/env"` to `~/.profile`, log out and in, or launch Zed from a terminal after running `source "$HOME/.cargo/env"`. |
| Same error with `can't find crate for core` / `wasm32-wasip2` | `rustup target add wasm32-wasip2` |
| *compiling Rust extension* cannot resolve `index.crates.io` | Check your network connection and retry; Zed must download the extension's Rust dependency once. |
| No **Add review note** | Trust the project, then check **dev: open language server logs** → *Code Review Notes*. |
| *Failed to run code-review-notes* | Install the binary, or set `{ "lsp": { "code-review-notes": { "binary": { "path": "/Users/you/.cargo/bin/code-review-notes" } } } }` |
| No notes in some file type | Add the language from Zed's status bar to `languages` in `zed-extension/extension.toml` and rebuild. |

Zed's log: `~/Library/Logs/Zed/Zed.log` on macOS, or **zed: open log**.

## Note files

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

Leave the front matter alone and edit the body. Unknown keys are preserved. Status changes append a line like *alice marked this Issue on 2026-10-09.* Authors come from `REVIEW_NOTES_AUTHOR`, then git `user.name` (read once at server start), then your login.

### Tags

Lowercase labels like `cwe-89`, up to 32 characters of letters, digits, `-`, `_` or `.`, max 16 per note. Imports fill them from SARIF rule tags and GitLab CWE ids, normalised so `external/cwe/cwe-089` becomes `cwe-89`. Filter with `list --tag cwe-89` or search in `cmd-t`.

## Safety

Assume the repository under review is hostile.

- Paths from notes and reports must stay inside the project. Absolute paths, `..`, non-`file:` URIs and escaping symlinks are rejected. A `.code-review-notes` symlink is refused.
- Exports never re-read the paths notes name. That's how the VS Code Security Notes export could leak files like SSH keys.
- Scanner messages are Markdown-escaped, file reads are size-limited, and note files are written atomically.
- Anyone with commit access can plant notes that are pre-marked OK, claim to be from a scanner or from you, or carry links. Hovers render links as plain text and flag notes by other authors or committers. Still check `git log -- .code-review-notes`, and clear the folder before reviewing an untrusted repo. The Markdown report keeps links.
- The agent reads those notes too. It's told note text is data, not instructions, but it can still be misled. Check what it changes.

## License

MIT, see [LICENSE](LICENSE).
