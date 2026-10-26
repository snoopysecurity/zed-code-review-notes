//! LSP server for Zed. Notes become diagnostics on the lines they cover;
//! code actions add, triage, open, delete and import them.

use anyhow::Context;
use lsp_server::{Connection, ErrorCode, Message, Notification, Request, RequestId, Response};
use lsp_types::{
    ApplyWorkspaceEditParams, CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams,
    Command, Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidChangeWatchedFilesParams, DidChangeWatchedFilesRegistrationOptions,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    ExecuteCommandOptions, ExecuteCommandParams, FileSystemWatcher, GlobPattern, Hover,
    HoverContents, HoverParams, HoverProviderCapability, InitializeParams, InlayHint,
    InlayHintLabel, InlayHintParams, Location, MarkupContent, MarkupKind, MessageType,
    NumberOrString, OneOf, Position, PublishDiagnosticsParams, Range, Registration,
    RegistrationParams, ServerCapabilities, ShowDocumentParams, ShowMessageParams,
    SymbolInformation, SymbolKind, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextDocumentSyncOptions, TextDocumentSyncSaveOptions, TextEdit, Uri, WorkspaceEdit,
    WorkspaceSymbolParams, WorkspaceSymbolResponse,
};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

use crate::anchor::{self, Anchor};
use crate::config::{self, Config, Severity};
use crate::import;
use crate::markdown::{defuse_links, inline_code, md_escape};
use crate::note::{Note, PLACEHOLDER_TITLE};
use crate::safety::{self, MAX_SOURCE_BYTES};
use crate::store::{self, LoadError, Store};

const CMD_ADD: &str = "codeReviewNotes.addNote";
const CMD_STATUS: &str = "codeReviewNotes.setStatus";
const CMD_OPEN: &str = "codeReviewNotes.openNote";
const CMD_DELETE: &str = "codeReviewNotes.deleteNote";
const CMD_IMPORT: &str = "codeReviewNotes.import";
const CMD_ACCEPT: &str = "codeReviewNotes.acceptChange";
const NAME: &str = "Code Review Notes";
/// Small `.json` files get re-sniffed for report content on every edit,
/// bigger ones only on save.
const RECHECK_REPORT_BYTES: usize = 1024 * 1024;
/// Debounce. Each publish re-locates every note in the file.
const PUBLISH_DELAY: Duration = Duration::from_millis(150);

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
        inlay_hint_provider: Some(OneOf::Left(true)),
        workspace_symbol_provider: Some(OneOf::Left(true)),
        code_action_provider: Some(true.into()),
        execute_command_provider: Some(ExecuteCommandOptions {
            commands: [
                CMD_ADD, CMD_STATUS, CMD_OPEN, CMD_DELETE, CMD_IMPORT, CMD_ACCEPT,
            ]
            .map(String::from)
            .to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let init = match conn.initialize(serde_json::to_value(caps)?) {
        Ok(init) => init,
        Err(e) => {
            // Give the writer thread a chance to flush what's queued (the
            // `initialize` reply, for one).
            drop(conn);
            io.join()?;
            return Err(e.into());
        }
    };
    let params: InitializeParams = serde_json::from_value(init)?;
    let mut server = Server::new(conn, workspace_root(&params));
    server.refresh_hints = params
        .capabilities
        .workspace
        .and_then(|w| w.inlay_hint)
        .and_then(|i| i.refresh_support)
        .unwrap_or(false);
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
    /// Worktree-relative. None outside the project
    rel: Option<String>,
    text: Rc<str>,
    /// Cached, since sniffing reads the whole file. Reset on edit for small
    /// files, on save for large ones
    is_report: Cell<Option<bool>>,
}

impl Doc {
    /// `.sarif` always. `.json` only if it's really SARIF or brakeman, not
    /// every `package.json`
    fn is_report(&self) -> bool {
        let Some(rel) = self.rel.as_deref() else {
            return false;
        };
        if rel.ends_with(".sarif") {
            return true;
        }
        if !rel.ends_with(".json") {
            return false;
        }
        if let Some(known) = self.is_report.get() {
            return known;
        }
        let known = import::is_report(&self.text);
        self.is_report.set(Some(known));
        known
    }
}

/// `generation` bumps on every change so cached anchors can't outlive the
/// notes they were computed for. Mutate only via [`Notes::edit`].
#[derive(Default)]
struct Notes {
    list: Vec<Note>,
    generation: u64,
}

impl Notes {
    fn edit(&mut self) -> &mut Vec<Note> {
        self.generation += 1;
        &mut self.list
    }
}

impl std::ops::Deref for Notes {
    type Target = [Note];

    fn deref(&self) -> &[Note] {
        &self.list
    }
}

/// Cached locate result for one (text, generation) pair. Locating is the
/// slow bit and diagnostics, hover, hints, actions and `cmd-t` all need it.
/// Holding the `Rc` keeps the address alive, so same pointer = same text.
struct Anchored {
    text: Rc<str>,
    generation: u64,
    notes: Rc<[(usize, Anchor)]>,
}

struct FileNotes<'a> {
    uri: Uri,
    text: Rc<str>,
    notes: Vec<(&'a Note, Anchor)>,
}

type Stamp = Option<(u64, Option<SystemTime>)>;

fn stamp(path: &Path) -> Stamp {
    std::fs::metadata(path)
        .ok()
        .map(|m| (m.len(), m.modified().ok()))
}

struct DiskText {
    stamp: (u64, Option<SystemTime>),
    text: Option<Rc<str>>,
}

struct Server {
    conn: Connection,
    store: Option<Store>,
    /// Root as Zed sent it, not canonicalized. Zed matches worktree paths
    /// textually, so outgoing URIs have to use this spelling.
    client_root: Option<PathBuf>,
    config: Config,
    config_warning: Option<String>,
    notes: Notes,
    anchored: RefCell<HashMap<String, Anchored>>,
    /// Last committer per note file. Shells out to git, so cached on stamp
    committers: RefCell<HashMap<String, (Stamp, Option<String>)>>,
    note_errors: Vec<LoadError>,
    announced_errors: HashSet<String>,
    docs: HashMap<String, Doc>,
    /// Unopened files' text, keyed on stamp. Saves re-reading on every
    /// publish / `cmd-t`
    disk: RefCell<HashMap<String, DiskText>>,
    /// what we've published to, so it can be cleared later
    published: HashSet<String>,
    refresh_hints: bool,
    hints_stale: bool,
    /// debounced publishes, see PUBLISH_DELAY
    pending: BTreeSet<String>,
    publish_due: Option<Instant>,
    next_request: u64,
}

fn arg(args: &[Value], i: usize) -> anyhow::Result<&Value> {
    args.get(i).with_context(|| format!("missing argument {i}"))
}

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
            notes: Notes::default(),
            anchored: RefCell::default(),
            committers: RefCell::default(),
            note_errors: Vec::new(),
            announced_errors: HashSet::new(),
            docs: HashMap::new(),
            disk: RefCell::default(),
            published: HashSet::new(),
            refresh_hints: false,
            hints_stale: false,
            pending: BTreeSet::new(),
            publish_due: None,
            next_request: 0,
        }
    }

    fn start(&mut self) {
        self.reload();
        // Catch note files changed outside the editor (git checkout etc).
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
        loop {
            let msg = match self.publish_due {
                None => self.conn.receiver.recv().ok(),
                Some(due) => match self
                    .conn
                    .receiver
                    .recv_timeout(due.saturating_duration_since(Instant::now()))
                {
                    Ok(msg) => Some(msg),
                    Err(e) if e.is_timeout() => {
                        self.publish_pending();
                        self.flush_hints();
                        continue;
                    }
                    Err(_) => None,
                },
            };
            let Some(msg) = msg else { break };
            match msg {
                Message::Request(req) => {
                    if req.method == "shutdown" {
                        return self.shut_down(req.id);
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
            self.flush_hints();
        }
        Ok(())
    }

    /// Not `Connection::handle_shutdown`, which errors on anything but `exit`.
    /// The reply to a request we sent just before (inlay hint refresh, say)
    /// can land in between.
    fn shut_down(&mut self, id: RequestId) -> anyhow::Result<()> {
        self.conn
            .sender
            .send(Message::Response(Response::new_ok(id, Value::Null)))?;
        while let Ok(msg) = self.conn.receiver.recv() {
            match msg {
                Message::Notification(n) if n.method == "exit" => return Ok(()),
                Message::Request(req) => {
                    self.conn.sender.send(Message::Response(Response::new_err(
                        req.id,
                        ErrorCode::InvalidRequest as i32,
                        "the server is shutting down".into(),
                    )))?;
                }
                _ => {}
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
            "textDocument/inlayHint" => {
                let p: InlayHintParams = serde_json::from_value(req.params)?;
                serde_json::to_value(self.inlay_hints(&p))?
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
                        is_report: Cell::new(None),
                    },
                );
                self.doc_opened(&key);
            }
            "textDocument/didChange" => {
                let p: DidChangeTextDocumentParams = serde_json::from_value(n.params)?;
                let key = p.text_document.uri.as_str().to_string();
                if let (Some(doc), Some(change)) = (
                    self.docs.get_mut(&key),
                    p.content_changes.into_iter().last(),
                ) {
                    doc.text = change.text.into();
                    if doc.text.len() <= RECHECK_REPORT_BYTES {
                        doc.is_report.set(None);
                    }
                }
                self.doc_changed(&key);
            }
            "textDocument/didSave" => {
                let p: DidSaveTextDocumentParams = serde_json::from_value(n.params)?;
                if let Some(doc) = self.docs.get(p.text_document.uri.as_str()) {
                    doc.is_report.set(None);
                }
                self.doc_saved(p.text_document.uri.as_str());
            }
            "textDocument/didClose" => {
                let p: DidCloseTextDocumentParams = serde_json::from_value(n.params)?;
                let rel = self
                    .docs
                    .remove(p.text_document.uri.as_str())
                    .and_then(|d| d.rel);
                // Unsaved edits are lost; use what's on disk.
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

    fn rel(&self, uri: &Uri) -> Option<String> {
        self.store.as_ref()?.relative(&uri_to_path(uri)?)
    }

    /// e.g. `.code-review-notes/7f3a9c21.md` -> `7f3a9c21`
    fn note_file_id(rel: &str) -> Option<&str> {
        rel.strip_prefix(store::DIR)?
            .strip_prefix('/')?
            .strip_suffix(".md")
    }

    /// Reload from disk, then overlay dirty note buffers. Only for notes still
    /// on disk, otherwise deleting a note with its file open resurrects it.
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
        let (mut notes, mut errors) = store.load_all();
        for doc in self.docs.values() {
            let Some(id) = doc.rel.as_deref().and_then(Self::note_file_id) else {
                continue;
            };
            let Ok(live) = Note::parse(&doc.text) else {
                continue;
            };
            if live.meta.id != id {
                continue;
            }
            if let Some(slot) = notes.iter_mut().find(|n| n.meta.id == id) {
                *slot = live;
            } else if let Some(i) = errors.iter().position(|e| is_error_for(e, id)) {
                // saved broken, being fixed in the editor
                errors.remove(i);
                notes.push(live);
            }
        }
        self.announce_errors(&errors);
        self.note_errors = errors;
        *self.notes.edit() = notes;
        self.publish_all();
    }

    /// Announce unreadable note files once each instead of silently dropping
    /// those notes.
    fn announce_errors(&mut self, errors: &[LoadError]) {
        let keys: HashSet<String> = errors.iter().map(ToString::to_string).collect();
        let new: Vec<&LoadError> = errors
            .iter()
            .filter(|e| !self.announced_errors.contains(&e.to_string()))
            .collect();
        for e in &new {
            eprintln!("code-review-notes: skipped note {e}");
        }
        // Full error (often multi-line) goes on the file's diagnostic.
        let message = match new.as_slice() {
            [] => None,
            [
                LoadError {
                    path: Some(path), ..
                },
            ] => Some(format!(
                "{NAME}: note {} can't be read, so it isn't shown; the diagnostics panel says why",
                path.file_name().unwrap_or_default().to_string_lossy()
            )),
            [
                LoadError {
                    path: None,
                    message,
                },
            ] => Some(format!("{NAME}: notes can't be read: {message}")),
            many => Some(format!(
                "{NAME}: {} notes can't be read, so they aren't shown; the diagnostics panel says why",
                many.len()
            )),
        };
        if let Some(m) = message {
            self.show_message(MessageType::WARNING, m);
        }
        // Forget fixed errors so one that comes back gets announced again.
        self.announced_errors = keys;
    }

    /// Note file buffer changed. If it parses as that note, it replaces the
    /// saved version and only the affected files are republished. Half-typed
    /// garbage keeps the last good version.
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
        if live.meta.id != id {
            return;
        }
        // Same rule as `reload`: only notes still on disk. One saved broken
        // counts, so fixing it in the buffer brings it back and clears its error.
        let Some(i) = self.notes.iter().position(|n| n.meta.id == id) else {
            if let Some(i) = self.note_errors.iter().position(|e| is_error_for(e, id)) {
                self.note_errors.remove(i);
                self.notes.edit().push(live);
                self.publish_all();
            }
            return;
        };
        if self.notes[i] == live {
            return;
        }
        let new = live.meta.file.clone();
        let old = std::mem::replace(&mut self.notes.edit()[i], live).meta.file;
        // Hover/hints see the new text right away; diagnostics wait for typing to stop.
        self.refresh_inlay_hints();
        self.schedule_publish(old);
        self.schedule_publish(new);
    }

    /// Back to the saved version, e.g. buffer closed without saving.
    fn revert_note(&mut self, id: &str) {
        let Some(store) = &self.store else { return };
        let Some(saved) = store.load(id).ok() else {
            // If it was deleted or saved broken, reload drops it or brings the
            // error back.
            return self.reload();
        };
        let mut files = vec![saved.meta.file.clone()];
        match self.notes.iter().position(|n| n.meta.id == id) {
            Some(i) => {
                let old = std::mem::replace(&mut self.notes.edit()[i], saved);
                files.push(old.meta.file);
            }
            None => self.notes.edit().push(saved),
        }
        files.dedup();
        for f in files {
            self.publish_file(&f);
        }
    }

    fn doc_opened(&mut self, key: &str) {
        if self.is_note_doc(key) {
            self.note_buffer_changed(key);
        } else {
            self.publish(key);
        }
    }

    fn doc_changed(&mut self, key: &str) {
        if self.is_note_doc(key) {
            self.note_buffer_changed(key);
        } else if let Some(rel) = self.docs.get(key).and_then(|d| d.rel.clone()) {
            self.schedule_publish(rel);
        }
    }

    fn is_note_doc(&self, key: &str) -> bool {
        self.docs
            .get(key)
            .and_then(|d| d.rel.as_deref())
            .and_then(Self::note_file_id)
            .is_some()
    }

    /// On save, write moved anchors back so note files follow the code, and
    /// backfill neighbour lines for older notes.
    /// Edited code gets new lines but keeps the old snippet. That's what was
    /// reviewed, and diffing against it keeps the note flagged as changed.
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
            .notes_in(doc)
            .filter_map(|(n, a)| match a {
                Anchor::Moved { start, end } => {
                    let mut n = n.clone();
                    n.meta.set(start, anchor::code_at(&doc.text, start, end)?);
                    Some(n)
                }
                // Older notes predate neighbour lines. Record them while the code is
                // still intact, they're what lets the note track edits later.
                Anchor::Exact { start, end }
                    if n.meta.context_before.is_none() && n.meta.context_after.is_none() =>
                {
                    let (before, after) = anchor::context(&doc.text, start, end);
                    if before.is_none() && after.is_none() {
                        return None;
                    }
                    let mut n = n.clone();
                    (n.meta.context_before, n.meta.context_after) = (before, after);
                    Some(n)
                }
                Anchor::Changed { start, end }
                    if (start, end) != (n.meta.start_line, n.meta.end_line) =>
                {
                    let mut n = n.clone();
                    n.meta.start_line = start;
                    n.meta.end_line = end;
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

    /// Persist a changed note. If its file is open and dirty, edit the buffer
    /// instead and leave saving to the user. Writing behind a dirty buffer
    /// makes Zed flag a conflict and someone's edits get lost.
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
                // `reload` already merged the buffer in, unless it doesn't parse yet or
                // names a different note.
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
        if let Some(i) = self.notes.iter().position(|n| n.meta.id == id) {
            self.notes.edit()[i] = note;
        }
        Ok(())
    }

    /// Re-anchor to the current code if it was edited. The snippet becomes the
    /// current code, so it stops showing as changed. Also backfills context.
    fn with_current_code(&self, note: &Note) -> Note {
        let mut out = note.clone();
        let Some(FileNotes { text, notes, .. }) = self.file_notes(&note.meta.file) else {
            return out;
        };
        match notes.iter().find(|(n, _)| n.meta.id == note.meta.id) {
            Some(&(_, Anchor::Changed { start, end })) => {
                if let Some(code) = anchor::code_at(&text, start, end) {
                    out.meta.set(start, code);
                }
            }
            Some(&(_, Anchor::Exact { start, end }))
                if note.meta.context_before.is_none() && note.meta.context_after.is_none() =>
            {
                (out.meta.context_before, out.meta.context_after) =
                    anchor::context(&text, start, end);
            }
            _ => {}
        }
        out
    }

    fn notes_in<'a>(&'a self, doc: &Doc) -> impl Iterator<Item = (&'a Note, Anchor)> + 'a {
        let anchors = match doc.rel.as_deref() {
            Some(rel) => self.anchors(rel, &doc.text),
            None => Rc::from([]),
        };
        (0..anchors.len()).map(move |k| {
            let (i, a) = anchors[k];
            (&self.notes[i], a)
        })
    }

    /// Cached per text + generation.
    fn anchors(&self, rel: &str, text: &Rc<str>) -> Rc<[(usize, Anchor)]> {
        let generation = self.notes.generation;
        if let Some(a) = self.anchored.borrow().get(rel)
            && a.generation == generation
            && Rc::ptr_eq(&a.text, text)
        {
            return a.notes.clone();
        }
        let notes: Rc<[(usize, Anchor)]> = self
            .notes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.meta.file == rel)
            .map(|(i, n)| (i, locate(n, text)))
            .collect();
        self.anchored.borrow_mut().insert(
            rel.to_string(),
            Anchored {
                text: text.clone(),
                generation,
                notes: notes.clone(),
            },
        );
        notes
    }

    /// All notes grouped by file, with URI, text and anchor. Open files use the
    /// buffer, others disk.
    fn located(&self) -> Vec<FileNotes<'_>> {
        let files: BTreeSet<&str> = self.notes.iter().map(|n| n.meta.file.as_str()).collect();
        self.disk
            .borrow_mut()
            .retain(|rel, _| files.contains(rel.as_str()));
        self.anchored
            .borrow_mut()
            .retain(|rel, _| files.contains(rel.as_str()));
        files
            .into_iter()
            .filter_map(|rel| self.file_notes(rel))
            .collect()
    }

    fn file_notes(&self, rel: &str) -> Option<FileNotes<'_>> {
        let (uri, text) = match self.docs.values().find(|d| d.rel.as_deref() == Some(rel)) {
            Some(doc) => (doc.uri.clone(), Some(doc.text.clone())),
            None => {
                let store = self.store.as_ref()?;
                let path = safety::confine(store.root(), rel).ok()?;
                (self.client_uri(&path)?, self.disk_text(rel, &path))
            }
        };
        let notes = match &text {
            Some(t) => self
                .anchors(rel, t)
                .iter()
                .map(|&(i, a)| (&self.notes[i], a))
                .collect(),
            None => self
                .notes
                .iter()
                .filter(|n| n.meta.file == rel)
                .map(|n| {
                    let (start, end) = (n.meta.start_line, n.meta.end_line);
                    (n, Anchor::Stale { start, end })
                })
                .collect(),
        };
        Some(FileNotes {
            uri,
            text: text.unwrap_or_else(|| "".into()),
            notes,
        })
    }

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

    /// Every noted file, open or not, so the project diagnostics panel lists
    /// all notes. Files that lost their last note get cleared.
    fn publish_all(&mut self) {
        self.refresh_inlay_hints();
        self.pending.clear();
        self.publish_due = None;
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
        for e in &self.note_errors {
            if let Some(uri) = e.path.as_deref().and_then(|p| self.client_uri(p)) {
                out.entry(uri.as_str().to_string())
                    .or_insert_with(|| (uri, Vec::new()))
                    .1
                    .push(load_error_diagnostic(e));
            }
        }
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

    /// Zed re-requests hints by itself after an edit, but not when notes change
    /// some other way. Batched: [`Server::flush_hints`] sends it once per message.
    fn refresh_inlay_hints(&mut self) {
        self.hints_stale = true;
    }

    fn flush_hints(&mut self) {
        if std::mem::take(&mut self.hints_stale) && self.refresh_hints {
            self.send_request("workspace/inlayHint/refresh", ());
        }
    }

    fn schedule_publish(&mut self, rel: String) {
        self.pending.insert(rel);
        self.publish_due = Some(Instant::now() + PUBLISH_DELAY);
    }

    /// No hint refresh here. Open files got one when their notes changed, and
    /// Zed re-asks after edits anyway.
    fn publish_pending(&mut self) {
        self.publish_due = None;
        for rel in std::mem::take(&mut self.pending) {
            match self.doc_key(&rel) {
                Some(key) => self.publish(&key),
                None => self.publish_file(&rel),
            }
        }
    }

    fn doc_key(&self, rel: &str) -> Option<String> {
        self.docs
            .iter()
            .find(|(_, d)| d.rel.as_deref() == Some(rel))
            .map(|(k, _)| k.clone())
    }

    fn publish_file(&mut self, rel: &str) {
        self.refresh_inlay_hints();
        if let Some(key) = self.doc_key(rel) {
            return self.publish(&key);
        }
        self.pending.remove(rel);
        let Some(FileNotes { uri, text, notes }) = self.file_notes(rel) else {
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

    fn publish(&mut self, key: &str) {
        let Some(doc) = self.docs.get(key) else {
            return;
        };
        if let Some(rel) = &doc.rel {
            self.pending.remove(rel);
        }
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

    /// `cmd-t`, one symbol per note named `[Status] title`. Zed fuzzy-filters
    /// too, but filtering here avoids shipping every note per keystroke.
    #[allow(deprecated)] // SymbolInformation::deprecated
    fn symbols(&self, query: &str) -> Vec<SymbolInformation> {
        let mut out = Vec::new();
        for FileNotes { uri, text, notes } in self.located() {
            for (n, a) in notes {
                let tags: String = n.meta.tags.iter().map(|t| format!(" #{t}")).collect();
                let name = format!(
                    "[{}] {}{tags}{}",
                    self.config.label(&n.meta.status),
                    n.plain_title(),
                    anchor_suffix(a, " (stale)", " (changed)")
                );
                // Zed re-filters on the name only, so match just that.
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

    fn hover(&self, p: &HoverParams) -> Option<Hover> {
        let doc = self
            .docs
            .get(p.text_document_position_params.text_document.uri.as_str())?;
        let line = p.text_document_position_params.position.line + 1;
        let store = self.store.as_ref()?;
        let author = store.author();
        let me: Vec<&str> = std::iter::once(author.as_str())
            .chain(store.git_user())
            .collect();
        let parts: Vec<String> = self
            .notes_in(doc)
            .filter(|(_, a)| (a.range().0..=a.range().1).contains(&line))
            .map(|(n, a)| {
                let committer = self.committer(store, &n.meta.id);
                let by = provenance(n, &me, committer.as_deref());
                hover_text(n, a, &self.config, &by)
            })
            .collect();
        (!parts.is_empty()).then(|| Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: parts.join("\n\n---\n\n"),
            }),
            range: None,
        })
    }

    fn committer(&self, store: &Store, id: &str) -> Option<String> {
        let stamp = stamp(&store.note_path(id));
        let mut cache = self.committers.borrow_mut();
        if let Some((s, c)) = cache.get(id)
            && *s == stamp
        {
            return c.clone();
        }
        let c = store.last_committer(id);
        cache.insert(id.to_string(), (stamp, c.clone()));
        c
    }

    /// Hint at the end of each note's first line, so notes below warning
    /// severity are still visible (when inlay hints are on).
    fn inlay_hints(&self, p: &InlayHintParams) -> Vec<InlayHint> {
        let Some(doc) = self.docs.get(p.text_document.uri.as_str()) else {
            return Vec::new();
        };
        let lines: Vec<&str> = doc.text.lines().collect();
        let mut hints: Vec<InlayHint> = self
            .notes_in(doc)
            .filter_map(|(n, a)| {
                let line = a.range().0.checked_sub(1)?;
                if line < p.range.start.line || line > p.range.end.line {
                    return None;
                }
                let end = lines.get(line as usize)?.encode_utf16().count() as u32;
                Some(InlayHint {
                    position: Position::new(line, end),
                    label: InlayHintLabel::String(hint_label(n, a, &self.config)),
                    kind: None,
                    text_edits: None,
                    tooltip: None,
                    padding_left: Some(true),
                    padding_right: None,
                    data: None,
                })
            })
            .collect();
        hints.sort_by_key(|h| (h.position.line, h.position.character));
        hints
    }

    fn code_actions(&self, p: &CodeActionParams) -> Vec<CodeActionOrCommand> {
        let mut out = Vec::new();
        let Some(doc) = self.docs.get(p.text_document.uri.as_str()) else {
            return out;
        };
        let Some(rel) = doc.rel.as_deref() else {
            return out;
        };

        if let Some(id) = Self::note_file_id(rel) {
            if let Some(note) = self.notes.iter().find(|n| n.meta.id == id) {
                out.extend(status_actions(note, &self.config, false));
            }
            return out;
        }

        if doc.is_report() {
            out.push(action(
                "Import into Code Review Notes",
                Some(CodeActionKind::SOURCE),
                CMD_IMPORT,
                vec![json!(doc.uri.as_str())],
            ));
        }

        let (start, end) = selected_lines(p.range);
        let here: Vec<(&Note, Anchor)> = self
            .notes_in(doc)
            .filter(|(_, a)| a.range().0 <= end && start <= a.range().1)
            .collect();
        let several = here.len() > 1;
        for (note, anchor) in &here {
            out.extend(status_actions(note, &self.config, several));
            if anchor.is_changed() {
                out.push(action(
                    &suffixed("Accept edited code", note, several),
                    Some(CodeActionKind::QUICKFIX),
                    CMD_ACCEPT,
                    vec![json!(note.meta.id)],
                ));
            }
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
                let note = Note::new_on(
                    store.new_id(&format!("{rel}:{start}")),
                    rel,
                    &doc.text,
                    start,
                    end,
                    self.config.new_note_status(),
                    store.author(),
                    format!(
                        "# {PLACEHOLDER_TITLE}\n\nWrite your note here. The first line is the title."
                    ),
                )?;
                let title = note.title_position();
                let path = store.save(&note)?;
                self.notes.edit().push(note);
                self.publish_all();
                // With the placeholder title selected, typing replaces it.
                let selection = title.map(|(line, start, end)| Range {
                    start: Position::new(line, start),
                    end: Position::new(line, end),
                });
                self.show_document(&path, selection);
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
                let note = self
                    .notes
                    .iter()
                    .find(|n| n.meta.id == id)
                    .context("note not found")?;
                if note.meta.status != status {
                    // Marking a note on edited code counts as reviewing it again.
                    let mut note = self.with_current_code(note);
                    note.mark(status, &label, &author);
                    self.write_note(note)?;
                }
                self.publish_all();
            }
            CMD_ACCEPT => {
                let id = arg_str(args, 0)?;
                let author = store.author();
                let note = self
                    .notes
                    .iter()
                    .find(|n| n.meta.id == id)
                    .context("note not found")?;
                // The menu may be stale if the code was undone or the note deleted since.
                let changed = self.file_notes(&note.meta.file).is_some_and(|f| {
                    f.notes
                        .iter()
                        .any(|(n, a)| n.meta.id == id && a.is_changed())
                });
                anyhow::ensure!(changed, "the note's code is no longer marked changed");
                let mut note = self.with_current_code(note);
                note.history(&format!("{} accepted the edited code", md_escape(&author)));
                self.write_note(note)?;
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
                self.show_document(&path, None);
            }
            CMD_DELETE => {
                let id = arg_str(args, 0)?;
                let note = self
                    .notes
                    .iter()
                    .find(|n| n.meta.id == id)
                    .context("note not found")?;
                store.delete(&note.meta.id)?;
                self.notes.edit().retain(|n| n.meta.id != id);
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

    fn show_document(&mut self, path: &Path, selection: Option<Range>) {
        if let Some(uri) = self.client_uri(path) {
            self.send_request(
                "window/showDocument",
                ShowDocumentParams {
                    uri,
                    external: Some(false),
                    take_focus: Some(true),
                    selection,
                },
            );
        }
    }
}

/// Does `text` match what's saved at `path`? Zed sends `\n` endings.
fn matches_disk(path: &Path, text: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|disk| disk.replace("\r\n", "\n") == text)
}

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
    anchor::locate_in(
        &note.meta.snippet,
        note.meta.context(),
        note.meta.start_line,
        note.meta.end_line,
        text,
    )
}

/// 1-based, inclusive. A selection ending at column 0 doesn't count that
/// last line.
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

/// Case-insensitive subsequence match, roughly what Zed's fuzzy filter does.
fn fuzzy_match(query: &str, haystack: &str) -> bool {
    let mut hay = haystack.chars().flat_map(char::to_lowercase);
    query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .all(|q| hay.any(|h| h == q))
}

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
    let suffix = anchor_suffix(
        anchor,
        " (stale: the noted code is gone)",
        " (the noted code has changed)",
    );
    Diagnostic {
        range: note_range(anchor, text),
        severity: Some(severity(config.severity(&note.meta.status))),
        code: Some(NumberOrString::String(note.meta.id.clone())),
        source: Some("code-review-notes".into()),
        message: format!(
            "[{}] {}{suffix}",
            config.label(&note.meta.status),
            note.plain_title()
        ),
        ..Default::default()
    }
}

/// `◆ [Status] title`, shortened to fit at the end of a line.
fn hint_label(note: &Note, anchor: Anchor, config: &Config) -> String {
    const MAX: usize = 60;
    let full = format!(
        "◆ [{}] {}{}",
        config.label(&note.meta.status),
        note.plain_title(),
        anchor_suffix(anchor, " (stale)", " (changed)")
    );
    if full.chars().count() <= MAX {
        return full;
    }
    let mut short: String = full.chars().take(MAX - 1).collect();
    short.push('…');
    short
}

fn anchor_suffix(anchor: Anchor, stale: &'static str, changed: &'static str) -> &'static str {
    match anchor {
        Anchor::Stale { .. } => stale,
        Anchor::Changed { .. } => changed,
        _ => "",
    }
}

fn is_error_for(e: &LoadError, id: &str) -> bool {
    e.path
        .as_deref()
        .and_then(Path::file_stem)
        .is_some_and(|stem| *stem == *id)
}

fn load_error_diagnostic(e: &LoadError) -> Diagnostic {
    Diagnostic {
        range: Range::default(),
        severity: Some(DiagnosticSeverity::ERROR),
        source: Some("code-review-notes".into()),
        message: format!("This note can't be read, so it isn't shown: {}", e.message),
        ..Default::default()
    }
}

/// Authorship bit of the hover. Flags notes you didn't write (except scanner
/// findings, which show their rule) and the last committer if not you.
/// `author` is only what the file claims, and a repo can ship its own notes.
fn provenance(note: &Note, me: &[&str], committer: Option<&str>) -> String {
    let mine = |name: &str| {
        me.iter()
            .any(|m| name == *m || name.strip_suffix(" (agent)") == Some(m))
    };
    let mut out = String::new();
    if note.meta.source.is_none() && !mine(&note.meta.author) {
        out.push_str(" · not written by you");
    }
    if let Some(c) = committer.filter(|c| !mine(c)) {
        out.push_str(&format!(" · last committed by {}", md_escape(c)));
    }
    out
}

/// Hover markdown. Links get flattened to text because Zed follows hover
/// links on click without asking.
fn hover_text(note: &Note, anchor: Anchor, config: &Config, provenance: &str) -> String {
    let m = &note.meta;
    let state = anchor_suffix(anchor, " · stale", " · code changed since this note");
    let mut s = format!(
        "**Review note · {}**{state}{provenance}\n\n{}\n\n",
        md_escape(config.label(&m.status)),
        defuse_links(note.body.trim())
    );
    let mut footer = vec![
        md_escape(&m.author),
        m.created.format("%Y-%m-%d").to_string(),
    ];
    if let Some(rule) = &m.rule {
        footer.push(format!("rule {}", inline_code(rule)));
    }
    if !m.tags.is_empty() {
        footer.push(format!("tags {}", md_escape(&m.tags.join(", "))));
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
    fn anchors_are_cached_per_text_and_notes() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _client) = Connection::memory();
        let mut server = Server::new(conn, Some(dir.path().to_path_buf()));
        let text: Rc<str> = "a()\nb()\nc()\n".into();
        let note = |id: &str, line| {
            Note::new_on(
                id.into(),
                "x.py".into(),
                &text,
                line,
                line,
                "open",
                "t".into(),
                "# n".into(),
            )
            .unwrap()
        };
        server.notes.edit().push(note("aaaaaaaa", 2));
        let first = server.anchors("x.py", &text);
        assert_eq!(&first[..], [(0, Anchor::Exact { start: 2, end: 2 })]);
        assert!(Rc::ptr_eq(&first, &server.anchors("x.py", &text)));

        // New text, even with the same content, is located again.
        let moved: Rc<str> = format!("z()\n{text}").into();
        assert_eq!(
            &server.anchors("x.py", &moved)[..],
            [(0, Anchor::Moved { start: 3, end: 3 })]
        );
        let same: Rc<str> = text.to_string().into();
        assert!(!Rc::ptr_eq(&first, &server.anchors("x.py", &same)));

        // So are changed notes.
        server.notes.edit().push(note("bbbbbbbb", 3));
        assert_eq!(server.anchors("x.py", &same).len(), 2);
        server.notes.edit()[0] = note("aaaaaaaa", 1);
        assert_eq!(
            server.anchors("x.py", &same)[0],
            (0, Anchor::Exact { start: 1, end: 1 })
        );
        assert!(server.anchors("y.py", &same).is_empty());
    }

    fn written_by(author: &str, source: Option<&str>, body: &str) -> Note {
        let mut n = Note::new_on(
            "aaaaaaaa".into(),
            "x.py".into(),
            "a()\n",
            1,
            1,
            "open",
            author.into(),
            body.into(),
        )
        .unwrap();
        n.meta.source = source.map(String::from);
        n
    }

    #[test]
    fn notes_you_did_not_write_are_marked() {
        let me = ["Sam", "sam-git"];
        let by = |author, source, committer| {
            provenance(&written_by(author, source, "# n"), &me, committer)
        };
        assert_eq!(by("Sam", None, None), "");
        assert_eq!(by("sam-git (agent)", None, Some("Sam")), "");
        assert_eq!(by("Mallory", None, None), " · not written by you");
        assert_eq!(by("Mallory (agent)", None, None), " · not written by you");
        // A scanner's finding shows its rule instead.
        assert_eq!(by("semgrep", Some("semgrep"), Some("sam-git")), "");
        // The author is what the file says; git says who put it there.
        assert_eq!(
            by("Sam", Some("semgrep"), Some("Mal_lory")),
            r" · last committed by Mal\_lory"
        );
    }

    #[test]
    fn hover_links_are_not_clickable() {
        let body = "# Title [t](http://evil)\n\nSee <http://evil> and [ref][r], `[code](http://ok)`\n\n```\n[fenced](http://ok)\n```\n\n[r]: http://evil/r";
        let note = written_by("Mallory", None, body);
        let text = hover_text(
            &note,
            Anchor::Exact { start: 1, end: 1 },
            &Config::default(),
            " · not written by you",
        );
        assert!(
            text.starts_with("**Review note · Open** · not written by you\n\n# Title t (`http://evil`)\n\nSee `http://evil` and ref (`http://evil/r`), `[code](http://ok)`\n\n```\n[fenced](http://ok)\n```\n\n\\[r\\]: `http://evil/r`\n\n"),
            "{text}"
        );
    }

    #[test]
    fn tags_are_searchable_and_shown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.py"), "a()\n").unwrap();
        let (conn, _client) = Connection::memory();
        let mut server = Server::new(conn, Some(dir.path().to_path_buf()));
        let mut note = written_by("semgrep", Some("semgrep"), "# SQL injection");
        note.meta.tags = vec!["cwe-89".into(), "sec_rity".into()];
        server.notes.edit().push(note.clone());
        let names =
            |q: &str| -> Vec<String> { server.symbols(q).into_iter().map(|s| s.name).collect() };
        assert_eq!(names("cwe89"), ["[Open] SQL injection #cwe-89 #sec_rity"]);
        assert_eq!(names("sql cwe"), names("cwe89"));
        assert!(names("cwe-22").is_empty());
        let text = hover_text(
            &note,
            Anchor::Exact { start: 1, end: 1 },
            &Config::default(),
            "",
        );
        assert!(text.contains(r" · tags cwe-89, sec\_rity · "), "{text}");
    }

    #[test]
    fn accepting_code_that_is_not_changed_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.py"), "a()\n").unwrap();
        let (conn, _client) = Connection::memory();
        let mut server = Server::new(conn, Some(dir.path().to_path_buf()));
        let note = written_by("me", None, "# n");
        let store = Store::new(dir.path());
        store.save(&note).unwrap();
        server.reload();
        let err = server
            .execute(CMD_ACCEPT, &[json!(note.meta.id)])
            .unwrap_err();
        assert!(
            err.to_string().contains("no longer marked changed"),
            "{err}"
        );
        assert_eq!(store.load(&note.meta.id).unwrap(), note);
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
