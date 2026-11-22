# Changelog

## Unreleased

## [0.2.0] - 2026-11-22

- Make the Zed extension an opt-in language server under the ID `code-review-notes-lsp`.
- Remove its SARIF file type and grammar. To import `.sarif` reports in Zed, enable the server for Plain Text and associate `.sarif` files with Plain Text in Zed settings, or select Plain Text for each report.
- Keep the existing `code-review-notes` CLI and language server settings key. The CLI still imports SARIF, Brakeman, and GitLab reports directly.

## [0.1.0] - 2026-11-02

Initial release of Code Review Notes for Zed.

### Added

- Keep review notes alongside source code in `.code-review-notes/`.
- Track note locations through edits, moves, and branch switches.
- Show note status, author, date, scanner rule, and links in Zed.
- Import findings from SARIF, Brakeman, and GitLab security reports.
- Export notes as Markdown, JSON, SARIF, or GitLab issues.
- Add optional MCP tools for agents to list, read, create, and update notes.
- Support configurable statuses, tags, history, and stale-note detection.

