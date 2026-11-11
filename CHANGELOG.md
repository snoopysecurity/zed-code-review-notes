# Changelog

## Unreleased

- Make the Zed extension an opt-in language server under the ID `code-review-notes-lsp`.
- Remove its SARIF file type and grammar; import `.sarif` reports in Zed after selecting Plain Text.

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

