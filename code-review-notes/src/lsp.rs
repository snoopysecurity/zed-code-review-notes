//! The language server Zed talks to.
//!
//! Notes are shown as diagnostics on the lines they cover, with the note text
//! on hover. Code actions add a note, change its status, open it, delete it,
//! or import an open scanner report. Every change is written to
//! `.code-review-notes/`; statuses come from its `config.toml`.

use anyhow::Context;
use chrono::{SubsecRound, Utc};
use lsp_server::{Connection, ErrorCode, Message, Notification, Request, RequestId, Response};
use lsp_types::{
    ApplyWorkspaceEditParams, CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams,
    Command, Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidChangeWatchedFilesParams, DidChangeWatchedFilesRegistrationOptions,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    ExecuteCommandOptions, ExecuteCommandParams, FileSystemWatcher, GlobPattern, Hover,
    HoverContents, HoverParams, HoverProviderCapability, InitializeParams, Location, MarkupContent,
    MarkupKind, MessageType, NumberOrString, OneOf, Position, PublishDiagnosticsParams, Range,
    Registration, RegistrationParams, ServerCapabilities, ShowDocumentParams, ShowMessageParams,
    SymbolInformation, SymbolKind, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextDocumentSyncOptions, TextDocumentSyncSaveOptions, TextEdit, Uri, WorkspaceEdit,
    WorkspaceSymbolParams, WorkspaceSymbolResponse,
};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::SystemTime;

use crate::anchor::{self, Anchor};
use crate::config::{self, Config, Severity};
use crate::import;
use crate::markdown::{inline_code, md_escape};
use crate::note::{Meta, Note};
use crate::safety::{self, MAX_SOURCE_BYTES};
use crate::store::{self, Store};

const CMD_ADD: &str = "codeReviewNotes.addNote";
const CMD_STATUS: &str = "codeReviewNotes.setStatus";
const CMD_OPEN: &str = "codeReviewNotes.openNote";
const CMD_DELETE: &str = "codeReviewNotes.deleteNote";
const CMD_IMPORT: &str = "codeReviewNotes.import";
const NAME: &str = "Code Review Notes";

pub fn run() -> anyhow::Result<()> {
    let (conn, io) = Connection::stdio();
    let caps = ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(
            TextDocumentSyncOptions {
                open_close: Some(true),
                change: Some(TextDocumentSyncKind::FULL),
                save: Some(TextDocumentSyncSaveOptions::Supported(true)),
                ..Default::default()
            },
        )),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        workspace_symbol_provider: Some(OneOf::Left(true)),
        code_action_provider: Some(true.into()),
        execute_command_provider: Some(ExecuteCommandOptions {
            commands: [CMD_ADD, CMD_STATUS, CMD_OPEN, CMD_DELETE, CMD_IMPORT]
                .map(String::from)
                .to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let init = conn.initialize(serde_json::to_value(caps)?)?;
    let params: InitializeParams = serde_json::from_value(init)?;
    let mut server = Server::new(conn, workspace_root(&params));
    server.start();
    server.main_loop()?;
    drop(server);
    io.join()?;
    Ok(())
}

#[allow(deprecated)]
fn workspace_root(params: &InitializeParams) -> Option<PathBuf> {
    let uri = params
        .workspace_folders
        .as_ref()
        .and_then(|f| f.first())
        .map(|f| &f.uri)
        .or(params.root_uri.as_ref())?;
    uri_to_path(uri)
}

/// Characters to escape in the path part of a `file://` URI.
const PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'|');

fn uri_to_path(uri: &Uri) -> Option<PathBuf> {
    safety::file_uri_path(uri.as_str())
}

fn path_to_uri(path: &Path) -> Option<Uri> {
    let s = path.to_str()?;
    format!("file://{}", utf8_percent_encode(s, PATH))
        .parse()
        .ok()
}

struct Doc {
    uri: Uri,
    /// Worktree-relative path, if the file is inside the project.
    rel: Option<String>,
    text: Rc<str>,
}

/// One project file's notes, located against its current text.
struct FileNotes<'a> {
    uri: Uri,
    text: Rc<str>,
    notes: Vec<(&'a Note, Anchor)>,
}

/// An unopened file's text (`None` if unreadable), with the size and mtime
/// it was read at.
struct DiskText {
    stamp: (u64, Option<SystemTime>),
    text: Option<Rc<str>>,
}

struct Server {
    conn: Connection,
    store: Option<Store>,
    /// The project root as Zed gave it. The store's root is canonical, but Zed
    /// matches paths to its worktrees textually, so URIs we send use this one.
    client_root: Option<PathBuf>,
    config: Config,
    /// Last config warning shown, so an invalid config is reported once.
    config_warning: Option<String>,
    notes: Vec<Note>,
    docs: HashMap<String, Doc>,
    /// Texts of noted files that aren't open, so publishing and `cmd-t` don't
    /// re-read them; a file is read again when its size or mtime changes.
    disk: RefCell<HashMap<String, DiskText>>,
    /// URIs that currently have diagnostics from us, so they can be cleared.
    published: HashSet<String>,
    next_request: u64,
}

fn arg(args: &[Value], i: usize) -> anyhow::Result<&Value> {
    args.get(i).with_context(|| format!("missing argument {i}"))
}

/// A 1-based line number argument.
fn arg_line(args: &[Value], i: usize) -> anyhow::Result<u32> {
    arg(args, i)?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&n| n >= 1)
        .with_context(|| format!("argument {i} must be a line number from 1"))
}

fn arg_str(args: &[Value], i: usize) -> anyhow::Result<&str> {
    arg(args, i)?
        .as_str()
        .with_context(|| format!("argument {i} must be a string"))
}

impl Server {
    fn new(conn: Connection, root: Option<PathBuf>) -> Server {
        Server {
            conn,
            store: root.as_deref().map(Store::new),
            client_root: root,
            config: Config::default(),
            config_warning: None,
            notes: Vec::new(),
            docs: HashMap::new(),
            disk: RefCell::default(),
            published: HashSet::new(),
            next_request: 0,
        }
    }

    fn start(&mut self) {
        self.reload();
        // Pick up edits to note files made outside the editor, or by git.
        self.send_request(
            "client/registerCapability",
            RegistrationParams {
                registrations: vec![Registration {
                    id: "code-review-notes-watch".into(),
                    method: "workspace/didChangeWatchedFiles".into(),
                    register_options: serde_json::to_value(
                        DidChangeWatchedFilesRegistrationOptions {
                            watchers: vec![FileSystemWatcher {
                                glob_pattern: GlobPattern::String(format!("**/{}/*", store::DIR)),
                                kind: None,
                            }],
                        },
                    )
                    .ok(),
                }],
            },
        );
    }

    fn main_loop(&mut self) -> anyhow::Result<()> {
        while let Ok(msg) = self.conn.receiver.recv() {
            match msg {
                Message::Request(req) => {
                    if self.conn.handle_shutdown(&req)? {
                        return Ok(());
                    }
                    let id = req.id.clone();
                    let resp = match self.handle_request(req) {
                        Ok(Some(v)) => Response::new_ok(id, v),
                        Ok(None) => Response::new_err(
                            id,
                            ErrorCode::MethodNotFound as i32,
                            "unsupported".into(),
                        ),
                        Err(e) => {
                            self.show_message(MessageType::ERROR, format!("{NAME}: {e:#}"));
                            Response::new_err(id, ErrorCode::RequestFailed as i32, format!("{e:#}"))
                        }
                    };
                    self.conn.sender.send(Message::Response(resp))?;
                }
                Message::Notification(n) => {
                    if let Err(e) = self.handle_notification(n) {
                        eprintln!("code-review-notes: {e:#}");
                    }
                }
                Message::Response(_) => {}
            }
        }
        Ok(())
    }

    fn handle_request(&mut self, req: Request) -> anyhow::Result<Option<Value>> {
        Ok(Some(match req.method.as_str() {
            "textDocument/hover" => {
                let p: HoverParams = serde_json::from_value(req.params)?;
                serde_json::to_value(self.hover(&p))?
            }
            "textDocument/codeAction" => {
                let p: CodeActionParams = serde_json::from_value(req.params)?;
                serde_json::to_value(self.code_actions(&p))?
            }
            "workspace/symbol" => {
                let p: WorkspaceSymbolParams = serde_json::from_value(req.params)?;
                serde_json::to_value(WorkspaceSymbolResponse::Flat(self.symbols(&p.query)))?
            }
            "workspace/executeCommand" => {
                let p: ExecuteCommandParams = serde_json::from_value(req.params)?;
                self.execute(&p.command, &p.arguments)?;
                Value::Null
            }
            _ => return Ok(None),
        }))
    }

    fn handle_notification(&mut self, n: Notification) -> anyhow::Result<()> {
        match n.method.as_str() {
            "textDocument/didOpen" => {
                let p: DidOpenTextDocumentParams = serde_json::from_value(n.params)?;
                let rel = self.rel(&p.text_document.uri);
                let key = p.text_document.uri.as_str().to_string();
                self.docs.insert(
                    key.clone(),
                    Doc {
                        uri: p.text_document.uri,
                        rel,
                        text: p.text_document.text.into(),
                    },
                );
                self.doc_changed(&key);
            }
            "textDocument/didChange" => {
                let p: DidChangeTextDocumentParams = serde_json::from_value(n.params)?;
                let key = p.text_document.uri.as_str().to_string();
                if let (Some(doc), Some(change)) = (
                    self.docs.get_mut(&key),
                    p.content_changes.into_iter().last(),
                ) {
                    doc.text = change.text.into();
                }
                self.doc_changed(&key);
            }
            "textDocument/didSave" => {
                let p: DidSaveTextDocumentParams = serde_json::from_value(n.params)?;
                self.doc_saved(p.text_document.uri.as_str());
            }
            "textDocument/didClose" => {
                let p: DidCloseTextDocumentParams = serde_json::from_value(n.params)?;
                let rel = self
                    .docs
                    .remove(p.text_document.uri.as_str())
                    .and_then(|d| d.rel);
                // Unsaved edits are gone: fall back to what is on disk.
                match rel.as_deref().and_then(Self::note_file_id) {
                    Some(id) => self.revert_note(id),
                    None => {
                        if let Some(rel) = rel {
                            self.publish_file(&rel);
                        }
                    }
                }
            }
            "workspace/didChangeWatchedFiles" => {
                let _: DidChangeWatchedFilesParams = serde_json::from_value(n.params)?;
                self.reload();
            }
            _ => {}
        }
        Ok(())
    }

    // ---- state ------------------------------------------------------------

    fn rel(&self, uri: &Uri) -> Option<String> {
        self.store.as_ref()?.relative(&uri_to_path(uri)?)
    }

    /// The note id if `rel` is a note file, e.g. `.code-review-notes/7f3a9c21.md`.
    fn note_file_id(rel: &str) -> Option<&str> {
        rel.strip_prefix(store::DIR)?
            .strip_prefix('/')?
            .strip_suffix(".md")
    }

    /// Re-read every note from disk, then overlay note files open with unsaved
    /// edits. Only notes still on disk are overlaid, so deleting a note whose
    /// file is open in the editor does not bring it back.
    fn reload(&mut self) {
        let Some(store) = &self.store else { return };
        let (config, warning) = store.config();
        self.config = config;
        if let Some(w) = &warning
            && warning != self.config_warning
        {
            self.show_message(MessageType::WARNING, format!("{NAME}: {w}"));
        }
        self.config_warning = warning;
        let (mut notes, errors) = store.load_all();
        for e in errors {
            eprintln!("code-review-notes: skipped note {e}");
        }
        for doc in self.docs.values() {
            if let Some(id) = doc.rel.as_deref().and_then(Self::note_file_id)
                && let Ok(live) = Note::parse(&doc.text)
                && live.meta.id == id
                && let Some(slot) = notes.iter_mut().find(|n| n.meta.id == id)
            {
                *slot = live;
            }
        }
        self.notes = notes;
        self.publish_all();
    }

    /// A note file's buffer changed: use its text in place of the saved note,
    /// if it parses as that note, and republish just the files involved.
    /// A buffer mid-edit that doesn't parse leaves the last good version.
    fn note_buffer_changed(&mut self, key: &str) {
        let Some(doc) = self.docs.get(key) else {
            return;
        };
        let Some(id) = doc.rel.as_deref().and_then(Self::note_file_id) else {
            return;
        };
        let Ok(live) = Note::parse(&doc.text) else {
            return;
        };
        // Only notes still on disk are shown, so deleting a note whose file is
        // open in the editor does not bring it back.
        let Some(slot) = self.notes.iter_mut().find(|n| n.meta.id == id) else {
            return;
        };
        if live.meta.id != id || *slot == live {
            return;
        }
        let old = std::mem::replace(slot, live).meta.file;
        let new = slot.meta.file.clone();
        self.publish_file(&old);
        if new != old {
            self.publish_file(&new);
        }
    }

    /// Show the saved version of a note again, e.g. after its file is closed
    /// without saving.
    fn revert_note(&mut self, id: &str) {
        let Some(store) = &self.store else { return };
        let saved = store.load(id).ok();
        let i = self.notes.iter().position(|n| n.meta.id == id);
        let mut files = Vec::new();
        match (i, saved) {
            (Some(i), Some(note)) => {
                files.push(note.meta.file.clone());
                files.push(std::mem::replace(&mut self.notes[i], note).meta.file);
            }
            (Some(i), None) => files.push(self.notes.remove(i).meta.file),
            (None, Some(note)) => {
                files.push(note.meta.file.clone());
                self.notes.push(note);
            }
            (None, None) => {}
        }
        files.dedup();
        for f in files {
            self.publish_file(&f);
        }
    }

    fn doc_changed(&mut self, key: &str) {
        let is_note = self
            .docs
            .get(key)
            .and_then(|d| d.rel.as_deref())
            .and_then(Self::note_file_id)
            .is_some();
        if is_note {
            self.note_buffer_changed(key);
        } else {
            self.publish(key);
        }
    }

    /// On save, write moved anchors back so the note files follow the code.
    fn doc_saved(&mut self, key: &str) {
        let Some(doc) = self.docs.get(key) else {
            return;
        };
        let Some(rel) = doc.rel.clone() else { return };
        if Self::note_file_id(&rel).is_some() || rel == format!("{}/{}", store::DIR, config::FILE) {
            self.reload();
            return;
        }
        let moved: Vec<Note> = self
            .notes
            .iter()
            .filter(|n| n.meta.file == rel)
            .filter_map(|n| match locate(n, &doc.text) {
                Anchor::Moved { start, end } => {
                    let mut n = n.clone();
                    n.meta.start_line = start;
                    n.meta.end_line = end;
                    n.meta.snippet = anchor::extract(&doc.text, start, end);
                    Some(n)
                }
                _ => None,
            })
            .collect();
        let mut changed = false;
        for note in moved {
            match self.write_note(note) {
                Ok(()) => changed = true,
                Err(e) => eprintln!("code-review-notes: {e:#}"),
            }
        }
        if changed {
            self.publish(key);
        }
    }

    /// Persist a changed note and keep it in memory. If the note's file is
    /// open with unsaved edits, change the editor's buffer instead and leave
    /// saving to the user: writing to disk behind a dirty buffer makes Zed
    /// flag a conflict, and one side's edits get lost.
    fn write_note(&mut self, note: Note) -> anyhow::Result<()> {
        let store = self.store.as_ref().context("no project folder is open")?;
        let id = note.meta.id.clone();
        let path = store.note_path(&id);
        let open = self
            .docs
            .values()
            .find(|d| d.rel.as_deref().and_then(Self::note_file_id) == Some(id.as_str()));
        match open {
            Some(doc) if !matches_disk(&path, &doc.text) => {
                // `reload` already merged the buffer into the note, unless the
                // buffer doesn't parse (mid-edit) or names another note.
                anyhow::ensure!(
                    Note::parse(&doc.text).is_ok_and(|live| live.meta.id == id),
                    "note {id} has unsaved edits that can't be read; save or fix it first"
                );
                let edit = TextEdit {
                    range: whole_document(&doc.text),
                    new_text: note.render(),
                };
                let params = ApplyWorkspaceEditParams {
                    label: Some(format!("{NAME}: update note {id}")),
                    edit: WorkspaceEdit {
                        changes: Some(HashMap::from([(doc.uri.clone(), vec![edit])])),
                        ..Default::default()
                    },
                };
                self.send_request("workspace/applyEdit", params);
            }
            _ => {
                store
                    .save(&note)
                    .with_context(|| format!("saving note {id}"))?;
            }
        }
        if let Some(slot) = self.notes.iter_mut().find(|n| n.meta.id == id) {
            *slot = note;
        }
        Ok(())
    }

    fn notes_in<'a>(&'a self, doc: &'a Doc) -> impl Iterator<Item = (&'a Note, Anchor)> + 'a {
        let rel = doc.rel.as_deref();
        self.notes
            .iter()
            .filter(move |n| Some(n.meta.file.as_str()) == rel)
            .map(|n| (n, locate(n, &doc.text)))
    }

    /// Every note with its file's URI, current text and anchor, grouped by
    /// file. Open files use the editor's text; others are read from disk.
    fn located(&self) -> Vec<FileNotes<'_>> {
        let mut by_file: BTreeMap<&str, Vec<&Note>> = BTreeMap::new();
        for n in &self.notes {
            by_file.entry(n.meta.file.as_str()).or_default().push(n);
        }
        self.disk
            .borrow_mut()
            .retain(|rel, _| by_file.contains_key(rel.as_str()));
        by_file
            .into_iter()
            .filter_map(|(rel, notes)| self.file_notes(rel, notes))
            .collect()
    }

    /// One file's notes, located against the editor's text if the file is
    /// open, else against what is on disk.
    fn file_notes<'a>(&'a self, rel: &str, notes: Vec<&'a Note>) -> Option<FileNotes<'a>> {
        let (uri, text) = match self.docs.values().find(|d| d.rel.as_deref() == Some(rel)) {
            Some(doc) => (doc.uri.clone(), Some(doc.text.clone())),
            None => {
                let store = self.store.as_ref()?;
                let path = safety::confine(store.root(), rel).ok()?;
                (self.client_uri(&path)?, self.disk_text(rel, &path))
            }
        };
        let notes = notes
            .into_iter()
            .map(|n| match &text {
                Some(t) => (n, locate(n, t)),
                None => (
                    n,
                    Anchor::Stale {
                        start: n.meta.start_line,
                        end: n.meta.end_line,
                    },
                ),
            })
            .collect();
        Some(FileNotes {
            uri,
            text: text.unwrap_or_else(|| "".into()),
            notes,
        })
    }

    /// An unopened file's text, from the cache while its size and mtime are
    /// unchanged.
    fn disk_text(&self, rel: &str, path: &Path) -> Option<Rc<str>> {
        let mut cache = self.disk.borrow_mut();
        let Ok(meta) = std::fs::metadata(path) else {
            cache.remove(rel);
            return None;
        };
        let stamp = (meta.len(), meta.modified().ok());
        if let Some(c) = cache.get(rel)
            && c.stamp == stamp
        {
            return c.text.clone();
        }
        let text: Option<Rc<str>> = safety::read_limited(path, MAX_SOURCE_BYTES, rel)
            .ok()
            .map(Rc::from);
        cache.insert(
            rel.to_string(),
            DiskText {
                stamp,
                text: text.clone(),
            },
        );
        text
    }

    /// Publish diagnostics for every file with notes, open or not, so Zed's
    /// project diagnostics panel lists every note. Files that no longer have
    /// notes are cleared.
    fn publish_all(&mut self) {
        let mut out: HashMap<String, (Uri, Vec<Diagnostic>)> = self
            .located()
            .into_iter()
            .map(|FileNotes { uri, text, notes }| {
                let diags = notes
                    .into_iter()
                    .map(|(n, a)| diagnostic(n, a, &text, &self.config))
                    .collect();
                (uri.as_str().to_string(), (uri, diags))
            })
            .collect();
        for doc in self.docs.values() {
            out.entry(doc.uri.as_str().to_string())
                .or_insert_with(|| (doc.uri.clone(), Vec::new()));
        }
        for old in std::mem::take(&mut self.published) {
            if !out.contains_key(&old)
                && let Ok(uri) = old.parse::<Uri>()
            {
                out.insert(old, (uri, Vec::new()));
            }
        }
        for (key, (uri, diagnostics)) in out {
            if !diagnostics.is_empty() {
                self.published.insert(key);
            }
            self.send_diagnostics(uri, diagnostics);
        }
    }

    /// Republish one file, open or not, after its notes changed.
    fn publish_file(&mut self, rel: &str) {
        if let Some(key) = self
            .docs
            .iter()
            .find(|(_, d)| d.rel.as_deref() == Some(rel))
            .map(|(k, _)| k.clone())
        {
            return self.publish(&key);
        }
        let notes = self.notes.iter().filter(|n| n.meta.file == rel).collect();
        let Some(FileNotes { uri, text, notes }) = self.file_notes(rel, notes) else {
            return;
        };
        let diagnostics: Vec<Diagnostic> = notes
            .into_iter()
            .map(|(n, a)| diagnostic(n, a, &text, &self.config))
            .collect();
        let key = uri.as_str().to_string();
        if diagnostics.is_empty() {
            self.published.remove(&key);
        } else {
            self.published.insert(key);
        }
        self.send_diagnostics(uri, diagnostics);
    }

    /// Republish one open file after an edit.
    fn publish(&mut self, key: &str) {
        let Some(doc) = self.docs.get(key) else {
            return;
        };
        let diagnostics: Vec<Diagnostic> = self
            .notes_in(doc)
            .map(|(n, a)| diagnostic(n, a, &doc.text, &self.config))
            .collect();
        let uri = doc.uri.clone();
        if diagnostics.is_empty() {
            self.published.remove(key);
        } else {
            self.published.insert(key.to_string());
        }
        self.send_diagnostics(uri, diagnostics);
    }

    fn send_diagnostics(&self, uri: Uri, diagnostics: Vec<Diagnostic>) {
        let params = PublishDiagnosticsParams {
            uri,
            diagnostics,
            version: None,
        };
        self.notify("textDocument/publishDiagnostics", params);
    }

    /// Project symbol search (`cmd-t`): one symbol per note, named
    /// `[Status] title`. Zed fuzzy-filters too; matching here keeps large
    /// projects from sending every note on every keystroke.
    #[allow(deprecated)] // SymbolInformation::deprecated
    fn symbols(&self, query: &str) -> Vec<SymbolInformation> {
        let mut out = Vec::new();
        for FileNotes { uri, text, notes } in self.located() {
            for (n, a) in notes {
                let stale = if a.is_stale() { " (stale)" } else { "" };
                let name = format!(
                    "[{}] {}{stale}",
                    self.config.label(&n.meta.status),
                    n.plain_title()
                );
                // Zed filters again on the name alone, so match only that.
                if !fuzzy_match(query, &name) {
                    continue;
                }
                out.push(SymbolInformation {
                    name,
                    kind: SymbolKind::KEY,
                    tags: None,
                    deprecated: None,
                    location: Location {
                        uri: uri.clone(),
                        range: note_range(a, &text),
                    },
                    container_name: Some(n.meta.file.clone()),
                });
            }
        }
        out
    }

    // ---- requests ---------------------------------------------------------

    fn hover(&self, p: &HoverParams) -> Option<Hover> {
        let doc = self
            .docs
            .get(p.text_document_position_params.text_document.uri.as_str())?;
        let line = p.text_document_position_params.position.line + 1;
        let parts: Vec<String> = self
            .notes_in(doc)
            .filter(|(_, a)| (a.range().0..=a.range().1).contains(&line))
            .map(|(n, a)| hover_text(n, a, &self.config))
            .collect();
        (!parts.is_empty()).then(|| Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: parts.join("\n\n---\n\n"),
            }),
            range: None,
        })
    }

    fn code_actions(&self, p: &CodeActionParams) -> Vec<CodeActionOrCommand> {
        let mut out = Vec::new();
        let Some(doc) = self.docs.get(p.text_document.uri.as_str()) else {
            return out;
        };
        let Some(rel) = doc.rel.as_deref() else {
            return out;
        };

        // Inside a note file: change that note's status.
        if let Some(id) = Self::note_file_id(rel) {
            if let Some(note) = self.notes.iter().find(|n| n.meta.id == id) {
                out.extend(status_actions(note, &self.config, false));
            }
            return out;
        }

        // An open scanner report.
        if rel.ends_with(".sarif") || rel.ends_with(".json") {
            out.push(action(
                "Import into Code Review Notes",
                Some(CodeActionKind::SOURCE),
                CMD_IMPORT,
                vec![json!(doc.uri.as_str())],
            ));
        }

        let (start, end) = selected_lines(p.range);
        let here: Vec<&Note> = self
            .notes_in(doc)
            .filter(|(_, a)| a.range().0 <= end && start <= a.range().1)
            .map(|(n, _)| n)
            .collect();
        let several = here.len() > 1;
        for note in &here {
            out.extend(status_actions(note, &self.config, several));
            out.push(action(
                &suffixed("Open review note", note, several),
                None,
                CMD_OPEN,
                vec![json!(note.meta.id)],
            ));
            out.push(action(
                &suffixed("Delete review note", note, several),
                None,
                CMD_DELETE,
                vec![json!(note.meta.id)],
            ));
        }
        out.push(action(
            "Add review note",
            None,
            CMD_ADD,
            vec![json!(doc.uri.as_str()), json!(start), json!(end)],
        ));
        out
    }

    fn execute(&mut self, command: &str, args: &[Value]) -> anyhow::Result<()> {
        let store = self.store.as_ref().context("no project folder is open")?;
        match command {
            CMD_ADD => {
                let key = arg_str(args, 0)?;
                let start = arg_line(args, 1)?;
                let end = arg_line(args, 2)?;
                anyhow::ensure!(start <= end, "start line {start} is after end line {end}");
                let doc = self.docs.get(key).context("document is not open")?;
                let rel = doc.rel.clone().context("file is outside the project")?;
                let snippet = anchor::extract(&doc.text, start, end);
                anyhow::ensure!(
                    !snippet.is_empty(),
                    "line {start} is past the end of the file"
                );
                let end = start + snippet.lines().count().max(1) as u32 - 1;
                let note = Note {
                    meta: Meta {
                        id: store.new_id(&format!("{rel}:{start}")),
                        file: rel,
                        start_line: start,
                        end_line: end,
                        status: self.config.new_note_status().to_string(),
                        author: store.author(),
                        created: Utc::now().trunc_subsecs(0),
                        source: None,
                        rule: None,
                        fingerprint: None,
                        snippet,
                    },
                    body: "# New review note\n\nWrite your note here. The first line is the title."
                        .into(),
                };
                let path = store.save(&note)?;
                self.notes.push(note);
                self.publish_all();
                self.show_document(&path);
            }
            CMD_STATUS => {
                let id = arg_str(args, 0)?;
                let status = arg_str(args, 1)?;
                let label = self
                    .config
                    .get(status)
                    .with_context(|| format!("unknown status {status:?}"))?
                    .label
                    .clone();
                let author = store.author();
                let mut note = self
                    .notes
                    .iter()
                    .find(|n| n.meta.id == id)
                    .context("note not found")?
                    .clone();
                if note.meta.status != status {
                    note.meta.status = status.to_string();
                    note.body.push_str(&format!(
                        "\n\n_{} marked this {} on {}._",
                        md_escape(&author),
                        md_escape(&label),
                        Utc::now().format("%Y-%m-%d")
                    ));
                    self.write_note(note)?;
                }
                self.publish_all();
            }
            CMD_OPEN => {
                let id = arg_str(args, 0)?;
                let note = self
                    .notes
                    .iter()
                    .find(|n| n.meta.id == id)
                    .context("note not found")?;
                let path = store.note_path(&note.meta.id);
                self.show_document(&path);
            }
            CMD_DELETE => {
                let id = arg_str(args, 0)?;
                let note = self
                    .notes
                    .iter()
                    .find(|n| n.meta.id == id)
                    .context("note not found")?;
                store.delete(&note.meta.id)?;
                self.notes.retain(|n| n.meta.id != id);
                self.publish_all();
            }
            CMD_IMPORT => {
                let key = arg_str(args, 0)?;
                let doc = self.docs.get(key).context("document is not open")?;
                let summary = import::import_text(store, &self.config, &doc.text)?;
                for r in &summary.rejected {
                    eprintln!("code-review-notes: import rejected {r}");
                }
                let kind = if summary.rejected.is_empty() {
                    MessageType::INFO
                } else {
                    MessageType::WARNING
                };
                self.show_message(kind, format!("{NAME}: {summary}"));
                self.reload();
            }
            other => anyhow::bail!("unknown command {other}"),
        }
        Ok(())
    }

    // ---- outgoing ---------------------------------------------------------

    fn notify(&self, method: &str, params: impl serde::Serialize) {
        let _ = self
            .conn
            .sender
            .send(Message::Notification(Notification::new(
                method.into(),
                params,
            )));
    }

    fn send_request(&mut self, method: &str, params: impl serde::Serialize) {
        self.next_request += 1;
        let id = RequestId::from(format!("code-review-notes-{}", self.next_request));
        let _ = self
            .conn
            .sender
            .send(Message::Request(Request::new(id, method.into(), params)));
    }

    fn show_message(&self, typ: MessageType, message: String) {
        self.notify("window/showMessage", ShowMessageParams { typ, message });
    }

    /// URI for a path inside the canonical store root, spelled under the root
    /// Zed gave us (`/var/x/a.rb`, not `/private/var/x/a.rb`).
    fn client_uri(&self, path: &Path) -> Option<Uri> {
        if let (Some(store), Some(root)) = (&self.store, &self.client_root)
            && let Ok(rel) = path.strip_prefix(store.root())
        {
            return path_to_uri(&root.join(rel));
        }
        path_to_uri(path)
    }

    fn show_document(&mut self, path: &Path) {
        if let Some(uri) = self.client_uri(path) {
            self.send_request(
                "window/showDocument",
                ShowDocumentParams {
                    uri,
                    external: Some(false),
                    take_focus: Some(true),
                    selection: None,
                },
            );
        }
    }
}

/// Whether `text` is what is saved at `path` (Zed sends `\n` line endings).
fn matches_disk(path: &Path, text: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|disk| disk.replace("\r\n", "\n") == text)
}

/// The range covering all of `text`.
fn whole_document(text: &str) -> Range {
    let last = text.rsplit('\n').next().unwrap_or("");
    Range {
        start: Position::new(0, 0),
        end: Position::new(
            text.matches('\n').count() as u32,
            last.encode_utf16().count() as u32,
        ),
    }
}

fn locate(note: &Note, text: &str) -> Anchor {
    anchor::locate(
        &note.meta.snippet,
        note.meta.start_line,
        note.meta.end_line,
        text,
    )
}

/// 1-based inclusive lines covered by an LSP range; a selection ending at
/// column 0 does not include that last line.
fn selected_lines(r: Range) -> (u32, u32) {
    let start = r.start.line + 1;
    let mut end = r.end.line + 1;
    if r.end.character == 0 && r.end.line > r.start.line {
        end -= 1;
    }
    (start, end.max(start))
}

fn severity(s: Severity) -> DiagnosticSeverity {
    match s {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
        Severity::Info => DiagnosticSeverity::INFORMATION,
        Severity::Hint => DiagnosticSeverity::HINT,
    }
}

/// Case-insensitive subsequence match, like Zed's own fuzzy filtering.
fn fuzzy_match(query: &str, haystack: &str) -> bool {
    let mut hay = haystack.chars().flat_map(char::to_lowercase);
    query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .all(|q| hay.any(|h| h == q))
}

/// The whole lines a note covers, as an LSP range.
fn note_range(anchor: Anchor, text: &str) -> Range {
    let (start, end) = anchor.range();
    let last = text
        .lines()
        .nth(end.saturating_sub(1) as usize)
        .unwrap_or("");
    Range {
        start: Position {
            line: start.saturating_sub(1),
            character: 0,
        },
        end: Position {
            line: end.saturating_sub(1),
            character: last.encode_utf16().count() as u32,
        },
    }
}

fn diagnostic(note: &Note, anchor: Anchor, text: &str, config: &Config) -> Diagnostic {
    let stale = if anchor.is_stale() {
        " (stale: the noted code has changed)"
    } else {
        ""
    };
    Diagnostic {
        range: note_range(anchor, text),
        severity: Some(severity(config.severity(&note.meta.status))),
        code: Some(NumberOrString::String(note.meta.id.clone())),
        source: Some("code-review-notes".into()),
        message: format!(
            "[{}] {}{stale}",
            config.label(&note.meta.status),
            note.plain_title()
        ),
        ..Default::default()
    }
}

fn hover_text(note: &Note, anchor: Anchor, config: &Config) -> String {
    let m = &note.meta;
    let stale = if anchor.is_stale() { " · stale" } else { "" };
    let mut s = format!(
        "**Review note · {}**{stale}\n\n{}\n\n",
        md_escape(config.label(&m.status)),
        note.body.trim()
    );
    let mut footer = vec![
        md_escape(&m.author),
        m.created.format("%Y-%m-%d").to_string(),
    ];
    if let Some(rule) = &m.rule {
        footer.push(format!("rule {}", inline_code(rule)));
    }
    footer.push(inline_code(&m.id));
    s.push_str(&footer.join(" · "));
    s
}

fn suffixed(title: &str, note: &Note, several: bool) -> String {
    if several {
        let t: String = note.plain_title().chars().take(40).collect();
        format!("{title} ({t})")
    } else {
        title.to_string()
    }
}

fn status_actions(note: &Note, config: &Config, several: bool) -> Vec<CodeActionOrCommand> {
    config
        .statuses
        .iter()
        .filter(|s| s.id != note.meta.status)
        .map(|s| {
            action(
                &suffixed(&format!("Mark {}", s.label), note, several),
                Some(CodeActionKind::QUICKFIX),
                CMD_STATUS,
                vec![json!(note.meta.id), json!(s.id)],
            )
        })
        .collect()
}

fn action(
    title: &str,
    kind: Option<CodeActionKind>,
    command: &str,
    arguments: Vec<Value>,
) -> CodeActionOrCommand {
    CodeActionOrCommand::CodeAction(CodeAction {
        title: title.to_string(),
        kind,
        command: Some(Command {
            title: title.to_string(),
            command: command.to_string(),
            arguments: Some(arguments),
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_round_trip() {
        let p = PathBuf::from("/tmp/a dir/x#1.rb");
        let uri = path_to_uri(&p).unwrap();
        assert_eq!(uri.as_str(), "file:///tmp/a%20dir/x%231.rb");
        assert_eq!(uri_to_path(&uri).unwrap(), p);
    }

    #[test]
    fn selection_lines() {
        let r = |sl, sc, el, ec| Range {
            start: Position {
                line: sl,
                character: sc,
            },
            end: Position {
                line: el,
                character: ec,
            },
        };
        assert_eq!(selected_lines(r(4, 2, 4, 2)), (5, 5));
        assert_eq!(selected_lines(r(4, 0, 7, 0)), (5, 7));
        assert_eq!(selected_lines(r(4, 0, 7, 3)), (5, 8));
    }

    #[test]
    fn line_arguments_are_checked() {
        let args = [json!(0), json!(4_294_967_297u64), json!("3"), json!(7)];
        assert!(arg_line(&args, 0).is_err());
        assert!(arg_line(&args, 1).is_err());
        assert!(arg_line(&args, 2).is_err());
        assert_eq!(arg_line(&args, 3).unwrap(), 7);
        assert!(arg_line(&args, 9).is_err());
    }

    #[test]
    fn whole_document_range() {
        assert_eq!(whole_document("").end, Position::new(0, 0));
        assert_eq!(whole_document("a\nbé\n").end, Position::new(2, 0));
        assert_eq!(whole_document("a\n😀x").end, Position::new(1, 3));
    }

    #[test]
    fn note_file_ids() {
        assert_eq!(
            Server::note_file_id(".code-review-notes/7f3a9c21.md"),
            Some("7f3a9c21")
        );
        assert_eq!(Server::note_file_id("app/x.md"), None);
    }
}
