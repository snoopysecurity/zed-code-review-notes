//! Code review notes for Zed: notes stored as Markdown files in
//! `.code-review-notes/`, SAST import, a Markdown report, and the language
//! server the Zed extension starts. `main.rs` is the command line on top.

pub mod anchor;
pub mod config;
pub mod export;
pub mod import;
pub mod lsp;
pub mod markdown;
pub mod note;
pub mod safety;
pub mod store;
