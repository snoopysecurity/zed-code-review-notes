# Code Review Notes for Zed

Keep notes on code while you review it in Zed 📝, and import findings from your SAST tools 🛠️.

Notes are Markdown files in `.code-review-notes/` at the root of the project you're reviewing, one file per note. They live in git next to the code, so a review can be shared, diffed and picked up again later.

## Features

- **Notes on any lines of code.** Select some code and add a note. Write it in Markdown; the first line is the title.
- **Statuses:** Open, Issue, Question, Note and OK by default, each drawn in its own colour. You can define your own per project, such as TODO / Vulnerable / Not Vulnerable for a security review.
- **Import SAST findings** from any scanner that writes SARIF 2.1.0 (CodeQL, Snyk, semgrep, bandit, gosec, checkov, …) and from brakeman. Re-importing never duplicates a finding or resets a status you've set.
- **See it in the code:** noted lines are underlined, and hovering shows the note.
- **Find any note:** `cmd-t` searches every note in the project by title or status. The diagnostics panel (`cmd-shift-m`) is a to-do list of Open findings and Issues across all files.
- **Notes follow the code** when lines are added, removed or re-indented. If the code is deleted, the note is kept and marked *stale* rather than pointing at the wrong lines.
- **Works in most file types,** including plain-text files Zed doesn't recognise, such as `.rb` without the Ruby extension.
- **Markdown report** of the whole review, grouped by status.
- **Safe on untrusted repositories:** paths are confined to the project and scanner text is escaped (see [Safety](#safety)).

## Quick start

Once it's installed (see [Install](#install)), open the project you're reviewing in Zed:

1. **Add a note:** select some lines, right-click → **Show Code Actions** (or press `cmd-.`) → **Add review note**. A note file opens. Replace the title line, write your note, and save. The lines are now underlined; hover over them to read the note.
2. **Set a status:** on a noted line, open the code actions again and choose **Mark Issue**, **Mark Question**, **Mark OK** and so on.
3. **Import scanner findings:** open a `.sarif` file (or brakeman `.json`) in Zed → code actions → **Import into Code Review Notes**. Each finding becomes an **Open** note on its line.
4. **Work through them:** `cmd-shift-m` lists everything still Open or marked Issue. `cmd-t` finds any note by title, for example `redirect` or `issue sql`.
5. **Write the report:** run `code-review-notes export -o review.md` in Zed's terminal.

## In the editor

All actions are in the **code actions** menu: right-click → **Show Code Actions**, or `cmd-.`.

| Action | Where |
| --- | --- |
| **Add review note** | any line or selection |
| **Mark Open / Issue / Question / Note / OK** | on a noted line, or inside a note file |
| **Open review note** | on a noted line: opens its Markdown file |
| **Delete review note** | on a noted line |
| **Import into Code Review Notes** | in an open `.sarif` or `.json` scanner report |

- **Underlines and hover:** each note underlines the lines it covers, coloured by status. Hover to read it, including author, date and the scanner rule for imported findings.
- **`cmd-t` (project symbol search):** lists every note in the project as `[Status] title`, matched fuzzily. Picking one jumps to the code. It matches titles and statuses, not file names.
- **`cmd-shift-m` (diagnostics panel):** lists notes across all files, opened or not, with click-to-jump. Zed's panel only shows errors and warnings, so with the default statuses it lists **Open** and **Issue** notes, which makes it a natural to-do list. Use `cmd-t` to see Notes, Questions and OK items too. Notes on gitignored files aren't listed.
- **`F8` / `shift-F8`:** jump to the next or previous note in the current file.
- **Editing a note file** updates the hover and underline as you type.
- **Notes follow the code.** Each note keeps the snippet it was made on and finds it again after edits, re-indenting or a branch switch. The new position is written to the note when you save the file. If the code is gone, the note is shown as *stale* at its old position.
- **File types:** notes work in Zed's built-in languages, in common languages from extensions (Ruby and ERB, PHP, Java, Vue, Svelte and more), and in *Plain Text*, which is what Zed uses for files it doesn't recognise. Zed has no "all languages" option, so a language from an extension that isn't in the list in `zed-extension/extension.toml` gets no notes; add its exact name there.

Zed doesn't let extensions add keybindings or right-click menu items. For a dedicated key, add one to your keymap (**zed: open keymap file**):

```json
[{ "context": "Editor", "bindings": { "cmd-alt-n": "editor::ToggleCodeActions" } }]
```

## Statuses

The defaults:

| Status | Meaning | Shown as | In `cmd-shift-m`? |
| --- | --- | --- | --- |
| **Open** | needs looking at; **imported findings start here** | warning (yellow) | yes |
| **Issue** | a real problem | error (red) | yes |
| **Question** | something to ask the author | info (blue) | no, use `cmd-t` |
| **Note** | a remark or context; **notes you add start here** | info (blue) | no, use `cmd-t` |
| **OK** | checked, nothing wrong | hint (faint) | no, use `cmd-t` |

Untriaged scanner findings stand out in yellow, and your own notes stay quiet until you mark them as an Issue.

To change them for a project, run `code-review-notes init`. It writes `.code-review-notes/config.toml`, ready to edit, and changes apply in Zed straight away. For example, a security review might use:

```toml
new_note_status = "todo"   # status for notes you add
import_status = "todo"     # status for imported findings

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

- Leave out `new_note_status` or `import_status` to use the first status.
- Use `severity = "warning"` or `"error"` for any status you want listed in `cmd-shift-m`.
- Reports list statuses by severity, issues first.
- A note whose status is later removed from the config keeps it, and shows under that raw id.

## Importing scanner output

Supported formats are **SARIF 2.1.0**, which almost every scanner can write, and **brakeman JSON**:

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

The semgrep and brakeman reports in `fixtures/` are real output. The CodeQL and Snyk Code fixtures are hand-written to match those tools' output. Other SARIF scanners should work too, as long as their report follows the rules below.

Then open the report in Zed and use **Import into Code Review Notes**, or run it from a terminal in the project:

```sh
code-review-notes import semgrep.sarif
```

- Each finding becomes an **Open** note, or whatever `import_status` says. Its title is the scanner's message, and the body records the tool, rule and level.
- Importing the same results again adds nothing and never changes a status you've set. This holds even after the code has moved, because findings are matched by file, rule and code, not by line number.
- Findings whose paths point outside the project, or that use non-file URIs, are rejected and listed in the summary.

### What gets imported

- **One note per result**, on the first of its locations that names a file and a start line. Data-flow steps (`codeFlows`) and related locations aren't imported.
- **Paths** must lead to a file in the project. These all work:
  - relative paths, which are taken as relative to the project root, so run the scanner from there;
  - paths relative to a `uriBaseId` the report defines;
  - files given only as an index into the report's `artifacts`;
  - absolute paths inside the project.
- **Reports from CI or another machine** work too, if the absolute paths begin with a source root or working directory the report records (`originalUriBaseIds` or `invocations[].workingDirectory`). That root is replaced by the project root. Roots less than two folders deep, such as `/` or `/home`, are ignored, because they would map almost any path onto the project.
- **Rules** are looked up in the scanner's own rule list or in its extensions, which is where CodeQL keeps them. The rule supplies the level, and the title when the result has no message.
- **Messages** have their `{0}` arguments and message templates (`message.id`) filled in. CodeQL-style links to related locations, such as `[user-provided value](1)`, become plain text.
- **Ignored, and counted as such in the summary:**
  - suppressed results, such as issues ignored in Snyk or suppressed in the source;
  - results whose `kind` is `pass` or `notApplicable`;
  - results whose `baselineState` is `absent`, meaning they've been fixed since the baseline.
- **Rejected, and listed in the summary:** results with no file or no line, such as project-wide or dependency-level findings.

### If findings are rejected

| Summary says | Why, and what to do |
|---|---|
| `path outside the project or unsupported uri` | The path is absolute and isn't inside this project, and the report doesn't record the root it was made in. Run the scanner from the project root with relative output, or rewrite the paths. |
| `No such file or directory` / `line is past the end of the file` | The report is for a different checkout or an older version of the code. Re-run the scanner. |
| `no file location` / `has no start line` | The result isn't about a line of code, so there's nothing to attach a note to. |

## Report and list

```sh
code-review-notes list                     # one line per note, stale ones marked
code-review-notes export -o review.md      # Markdown report grouped by status
```

To run the export from Zed, add a task to `.zed/tasks.json`, then run **task: spawn**:

```json
[{ "label": "Code Review Notes: export report", "command": "code-review-notes export -o code-review.md" }]
```

## Install

You need Rust installed via [rustup](https://rustup.rs); Zed uses it to build dev extensions. The repository's `rust-toolchain.toml` installs the `wasm32-wasip2` target that Zed needs.

1. Install the language server binary:

   ```sh
   cargo install --path code-review-notes
   ```

   This installs `~/.cargo/bin/code-review-notes`. The extension looks for it on your login shell's `PATH`, then in `~/.cargo/bin`. If the `lsp.code-review-notes.binary.path` setting is set, Zed uses that instead.

2. In Zed, run **zed: install dev extension** from the command palette and choose the `zed-extension/` folder.

3. Open a project and **trust it** (the *Restricted Mode* indicator in the title bar). Zed doesn't start language servers in untrusted projects.

4. If **Add review note** appears in the code actions, it's working.

After changing the Rust code, run `cargo install --path code-review-notes` again, then **editor: restart language server** in Zed. After changing `zed-extension/`, rebuild it from **zed: extensions**.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| *Failed to install dev extension: compiling Rust extension*, and the log says `running rustc: No such file or directory` | Zed can't find Rust. Make sure your login shell loads it, for example `. "$HOME/.cargo/env"` in `~/.zprofile`. Then quit Zed with `cmd-q` and reopen it. |
| The same error with `can't find crate for core` / `wasm32-wasip2` | `rustup target add wasm32-wasip2` |
| No **Add review note** in the code actions | Trust the project (Restricted Mode). Then check **dev: open language server logs** → *Code Review Notes*. |
| *Failed to run code-review-notes* in the status bar, with `No such file or directory` | Run `cargo install --path code-review-notes`, or set the path in Zed's settings: `{ "lsp": { "code-review-notes": { "binary": { "path": "/Users/you/.cargo/bin/code-review-notes" } } } }` |
| No notes in some file type | Check the file's language in Zed's status bar. If it isn't in `languages` in `zed-extension/extension.toml`, add it and rebuild the extension. |
| A note doesn't show in `cmd-shift-m` | The panel only lists errors and warnings. Use `cmd-t`, or give that status a warning severity. |

Zed's own log is at `~/Library/Logs/Zed/Zed.log` on macOS, or via **zed: open log**.

## Note files

```markdown
+++
id = "3ce66a51"
file = "app/users.py"
start_line = 9
end_line = 9
status = "open"                    # imported findings start as Open
author = "Semgrep OSS"
created = "2026-10-09T15:48:12Z"
source = "Semgrep OSS"
rule = "rules.python-fstring-sql"
fingerprint = "…"
snippet = """
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
+++

# SQL query built with an f-string; use parameters instead

Reachable from GET /users/:id without authentication.
```

The front matter is managed for you. Edit the body freely. Status changes add a line such as *alice marked this Issue on 2026-10-09.* to the body, as a small history.

## Safety

The tool reads files from the repository under review, which may be hostile.

- Every path from a note file or a scanner report must stay inside the project. Absolute paths, `..`, non-`file:` URIs and symlinks pointing outside the project are rejected.
- The export uses the snippets stored in the notes and never re-reads the paths they name. That was how the VS Code Security Notes extension's export could leak local files, such as SSH keys, into a report.
- Scanner messages are Markdown-escaped, and file reads are size-limited.
- Note files are written atomically: a temp file is written, then renamed into place. A `.code-review-notes` that is a symlink is refused.
- Note files are Markdown and are shown as written. Anyone who can commit to the repository can add or change notes, so a hostile repository can ship notes of its own: ones already marked OK, ones that claim to come from a scanner, or ones with links. Zed opens links in a hover without asking. Check `git log -- .code-review-notes` before trusting notes you didn't write, and clear out the folder before reviewing a repository you don't trust.

## Development

```sh
cargo test                                   # unit tests, fixture imports, CLI tests, export snapshot
cargo clippy --all-targets -- -D warnings
cargo build && python3 scripts/lsp_e2e.py    # drives the language server like Zed does
(cd zed-extension && cargo build --target wasm32-wasip2)
```

CI (`.github/workflows/ci.yml`) runs all of these on Linux and macOS.

| Path | What |
| --- | --- |
| `code-review-notes/src/` | the library (`lib.rs`: store, anchoring, import, export, language server) and the command line on top (`main.rs`: `lsp`, `import`, `export`, `list`, `init`) |
| `code-review-notes/tests/` | integration tests: importing the fixtures, and the command line run as a process |
| `zed-extension/` | the Zed extension (WASM): launches the binary |
| `fixtures/` | a small demo app; real semgrep and brakeman output for it; hand-written CodeQL and Snyk Code reports for it; `sarif-spec-edges.sarif`, which uses less common SARIF features; and `adversarial.sarif`, whose paths try to escape the project |
| `scripts/lsp_e2e.py` | end-to-end test that talks LSP to the binary |

## License

MIT, see [LICENSE](LICENSE).
