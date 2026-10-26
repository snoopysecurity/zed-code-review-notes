"""End-to-end check: drive `code-review-notes lsp` over stdio like Zed does.

Usage: cargo build && python3 scripts/lsp_e2e.py [BINARY]
"""
import atexit, json, pathlib, queue, shutil, subprocess, sys, tempfile, threading, time

REPO = pathlib.Path(__file__).resolve().parent.parent
BIN = sys.argv[1] if len(sys.argv) > 1 else str(REPO / "target/debug/code-review-notes")
FIXTURES = REPO / "fixtures"
WORK = pathlib.Path(tempfile.mkdtemp(prefix="code-review-notes-e2e-"))
atexit.register(shutil.rmtree, WORK, ignore_errors=True)  # runs on failure too
root = WORK / "lsp-demo"
shutil.rmtree(root, ignore_errors=True)
shutil.copytree(FIXTURES / "demo-app", root)
subprocess.run(["git", "init", "-q"], cwd=root, check=True)
subprocess.run([BIN, "import", str(FIXTURES / "semgrep.sarif")], cwd=root, check=True, capture_output=True)
subprocess.run([BIN, "import", str(FIXTURES / "brakeman.json")], cwd=root, check=True, capture_output=True)
shutil.copy(FIXTURES / "semgrep.sarif", root / "scan.sarif")
root = root.resolve()

proc = subprocess.Popen([BIN, "lsp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
atexit.register(proc.kill)
inbox = queue.Queue()

def reader():
    while True:
        headers = {}
        while True:
            line = proc.stdout.readline()
            if not line:
                return
            line = line.decode().strip()
            if not line:
                break
            k, v = line.split(":", 1)
            headers[k.lower()] = v.strip()
        inbox.put(json.loads(proc.stdout.read(int(headers["content-length"]))))

threading.Thread(target=reader, daemon=True).start()
next_id = 0

def send(msg):
    body = json.dumps({"jsonrpc": "2.0", **msg}).encode()
    proc.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    proc.stdin.flush()

backlog = []

def wait(pred, what, timeout=5):
    for m in backlog:
        if pred(m):
            backlog.remove(m)
            return m
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            m = inbox.get(timeout=0.1)
        except queue.Empty:
            continue
        # answer server->client requests
        if "method" in m and "id" in m:
            send({"id": m["id"], "result": {"success": True} if m["method"] == "window/showDocument" else None})
        if pred(m):
            return m
        backlog.append(m)
    raise SystemExit(f"FAIL: timed out waiting for {what}")

def request(method, params):
    global next_id
    next_id += 1
    rid = next_id
    send({"id": rid, "method": method, "params": params})
    m = wait(lambda m: m.get("id") == rid and "method" not in m, method)
    if "error" in m:
        raise SystemExit(f"FAIL: {method} -> {m['error']}")
    return m["result"]

def notify(method, params):
    send({"method": method, "params": params})

def diags(uri, what, pred=lambda d: True):
    # only the latest publish for the file counts
    pubs = [m for m in backlog if m.get("method") == "textDocument/publishDiagnostics" and m["params"]["uri"] == uri]
    for m in pubs:
        backlog.remove(m)
    if pubs and pred(pubs[-1]["params"]["diagnostics"]):
        return pubs[-1]["params"]["diagnostics"]
    return wait(lambda m: m.get("method") == "textDocument/publishDiagnostics"
                and m["params"]["uri"] == uri and pred(m["params"]["diagnostics"]), what)["params"]["diagnostics"]

def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)

uri = lambda p: (root / p).as_uri()
py = uri("app/users.py")
text = (root / "app/users.py").read_text()

request("initialize", {"processId": None, "rootUri": root.as_uri(),
                       "capabilities": {"workspace": {"inlayHint": {"refreshSupport": True}}},
                       "workspaceFolders": [{"uri": root.as_uri(), "name": "demo"}]})
notify("initialized", {})
wait(lambda m: m.get("method") == "client/registerCapability", "watcher registration")
ok(True, "server registers a file watcher for .code-review-notes/*.md")

# Notes in unopened files still show in the project diagnostics panel.
rb = uri("app/controllers/users_controller.rb")
d = diags(rb, "diagnostics for an unopened file", lambda d: len(d) == 2)
ok(sorted(x["range"]["start"]["line"] for x in d) == [2, 6], "notes in an unopened file are published (project-wide diagnostics)")

syms = request("workspace/symbol", {"query": ""})
ok(len(syms) == 4 and all(s["name"].startswith("[Open] ") for s in syms), f"cmd-t lists every note: {[s['name'] for s in syms]}")
syms = request("workspace/symbol", {"query": "redirect"})
ok(len(syms) == 1 and syms[0]["location"]["uri"] == rb and syms[0]["location"]["range"]["start"]["line"] == 6,
   f"cmd-t search finds a note by title and jumps to it: {[s['name'] for s in syms]}")
syms = request("workspace/symbol", {"query": "opn fstring"})
ok(len(syms) == 1 and "f-string" in syms[0]["name"], "symbol search is fuzzy and includes the status")

notify("textDocument/didOpen", {"textDocument": {"uri": py, "languageId": "python", "version": 1, "text": text}})
d = diags(py, "initial diagnostics", lambda d: len(d) == 2)
sql = next(x for x in d if "f-string" in x["message"])
ok(sql["range"]["start"]["line"] == 8 and sql["severity"] == 2, f"imported finding starts as Open (warning) on line 9: {sql['message']}")

hints = request("textDocument/inlayHint", {"textDocument": {"uri": py}, "range": {"start": {"line": 0, "character": 0}, "end": {"line": 30, "character": 0}}})
ok([h["position"]["line"] for h in hints] == [8, 13] and all(h["label"].startswith("◆ [Open] ") for h in hints)
   and hints[0]["position"]["character"] == len(text.splitlines()[8]), f"inlay hints at the end of noted lines: {[h['label'] for h in hints]}")
hints = request("textDocument/inlayHint", {"textDocument": {"uri": py}, "range": {"start": {"line": 10, "character": 0}, "end": {"line": 30, "character": 0}}})
ok(len(hints) == 1, "inlay hints only for the range asked")

h = request("textDocument/hover", {"textDocument": {"uri": py}, "position": {"line": 8, "character": 4}})
ok(h and "f-string" in h["contents"]["value"] and "Open" in h["contents"]["value"], "hover shows the note")
ok(request("textDocument/hover", {"textDocument": {"uri": py}, "position": {"line": 0, "character": 0}}) is None, "no hover off-note")

rng = {"start": {"line": 16, "character": 0}, "end": {"line": 19, "character": 0}}
acts = request("textDocument/codeAction", {"textDocument": {"uri": py}, "range": rng, "context": {"diagnostics": []}})
add = next(a for a in acts if a["title"] == "Add review note")
ok(len(acts) == 1, "only 'Add review note' offered on un-noted lines")
request("workspace/executeCommand", add["command"])
show = wait(lambda m: m.get("method") == "window/showDocument", "showDocument")
note_path = pathlib.Path(show["params"]["uri"].removeprefix("file://"))
ok(note_path.exists() and note_path.parent.name == ".code-review-notes", f"new note written and opened: {note_path.name}")
sel = show["params"].get("selection")
title_line = note_path.read_text().splitlines()[sel["start"]["line"]] if sel else ""
ok(sel and title_line[sel["start"]["character"]:sel["end"]["character"]] == "New review note",
   f"the new note opens with its placeholder title selected: {sel}")
wait(lambda m: m.get("method") == "workspace/inlayHint/refresh", "inlay hint refresh")
ok(True, "adding a note asks Zed to refresh inlay hints")
d = diags(py, "diagnostics incl. new note", lambda d: len(d) == 3)
new = next(x for x in d if "New review note" in x["message"])
ok((new["range"]["start"]["line"], new["range"]["end"]["line"]) == (16, 18), "new note covers the selected lines 17-19")
ok(new["message"].startswith("[Note]") and new["severity"] == 3, f"hand-written note starts as Note (info): {new['message']}")

acts = request("textDocument/codeAction", {"textDocument": {"uri": py}, "range": {"start": {"line": 8, "character": 2}, "end": {"line": 8, "character": 2}}, "context": {"diagnostics": []}})
titles = [a["title"] for a in acts]
ok({"Mark Issue", "Mark Question", "Mark Note", "Mark OK", "Open review note", "Delete review note"} <= set(titles), f"actions on a note: {titles}")
request("workspace/executeCommand", next(a for a in acts if a["title"] == "Mark Issue")["command"])
d = diags(py, "issue", lambda d: any(x["severity"] == 1 for x in d))
sql_id = next(x for x in d if "f-string" in x["message"])["code"]
ok("status = \"issue\"" in (root / f".code-review-notes/{sql_id}.md").read_text(), "status written to note file")

# config.toml statuses, no restart needed
(root / ".code-review-notes/config.toml").write_text(
    '[[status]]\nid = "todo"\nlabel = "TODO"\nseverity = "warning"\n'
    '[[status]]\nid = "issue"\nlabel = "Vulnerable"\nseverity = "error"\n'
    '[[status]]\nid = "fine"\nlabel = "Not Vulnerable"\nseverity = "hint"\n')
notify("workspace/didChangeWatchedFiles", {"changes": [{"uri": uri(".code-review-notes/config.toml"), "type": 1}]})
d = diags(py, "relabelled", lambda d: any(x["message"].startswith("[Vulnerable]") for x in d))
acts = request("textDocument/codeAction", {"textDocument": {"uri": py}, "range": {"start": {"line": 8, "character": 2}, "end": {"line": 8, "character": 2}}, "context": {"diagnostics": []}})
titles = [a["title"] for a in acts]
ok({"Mark TODO", "Mark Not Vulnerable"} <= set(titles) and "Mark OK" not in titles, f"config.toml statuses used live: {titles}")
(root / ".code-review-notes/config.toml").unlink()
notify("workspace/didChangeWatchedFiles", {"changes": [{"uri": uri(".code-review-notes/config.toml"), "type": 3}]})
diags(py, "default labels back", lambda d: any(x["message"].startswith("[Issue]") for x in d))

# Editing the note file updates hover before saving.
note_uri = note_path.as_uri()
note_text = note_path.read_text().replace("# New review note", "# Missing authorization on safe_show")
notify("textDocument/didOpen", {"textDocument": {"uri": note_uri, "languageId": "markdown", "version": 1, "text": note_text}})
d = diags(py, "renamed note", lambda d: any("Missing authorization" in x["message"] for x in d))
ok(True, "editing the note file updates the diagnostic live")

# Dirty note buffer: status change goes to the buffer, disk untouched.
acts = request("textDocument/codeAction", {"textDocument": {"uri": py}, "range": {"start": {"line": 16, "character": 0}, "end": {"line": 16, "character": 0}}, "context": {"diagnostics": []}})
request("workspace/executeCommand", next(a for a in acts if a["title"] == "Mark Question")["command"])
edit = wait(lambda m: m.get("method") == "workspace/applyEdit", "applyEdit to the open note")
new_text = next(iter(edit["params"]["edit"]["changes"].values()))[0]["newText"]
ok("Missing authorization" in new_text and 'status = "question"' in new_text and "Missing authorization" not in note_path.read_text(),
   "status change on a note with unsaved edits goes to its buffer, keeping the edits")

# Close without saving -> back to the saved version.
notify("textDocument/didClose", {"textDocument": {"uri": note_uri}})
diags(py, "reverted note", lambda d: any(x["message"] == "[Note] New review note" for x in d))
ok(True, "closing a note with unsaved edits reverts it to the saved version")

def settle(seconds):
    """Drain server messages for `seconds`, replying to requests."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            m = inbox.get(timeout=0.05)
        except queue.Empty:
            continue
        if "method" in m and "id" in m:
            send({"id": m["id"], "result": None})
        backlog.append(m)

# Burst of edits -> one publish after typing stops, for the final text.
is_py_pub = lambda m: m.get("method") == "textDocument/publishDiagnostics" and m["params"]["uri"] == py
settle(0.3)
backlog[:] = [m for m in backlog if not is_py_pub(m)]
for k in range(1, 6):
    notify("textDocument/didChange", {"textDocument": {"uri": py, "version": 100 + k}, "contentChanges": [{"text": "# pad\n" * k + text}]})
settle(0.6)
pubs = [m for m in backlog if is_py_pub(m)]
lines = sorted(x["range"]["start"]["line"] for x in pubs[-1]["params"]["diagnostics"]) if pubs else []
ok(len(pubs) == 1 and lines == [13, 18, 21], f"a burst of edits is published once, for the last text: {len(pubs)} publishes, lines {lines}")

shifted = "# pad\n" * 40 + text
notify("textDocument/didChange", {"textDocument": {"uri": py, "version": 2}, "contentChanges": [{"text": shifted}]})
d = diags(py, "shifted", lambda d: any(x["range"]["start"]["line"] == 48 for x in d))
ok(sorted(x["range"]["start"]["line"] for x in d) == [48, 53, 56], f"all notes follow a 40-line insertion: {sorted(x['range']['start']['line'] for x in d)}")
(root / "app/users.py").write_text(shifted)
notify("textDocument/didSave", {"textDocument": {"uri": py}})
time.sleep(0.3)
ok("start_line = 49" in (root / f".code-review-notes/{sql_id}.md").read_text(), "save writes moved anchor back to the note")

# Model a fresh scan after the source moved, then import it through the editor.
# This exercises the code action in CI without a scanner installation.
report = json.loads((root / "scan.sarif").read_text())
for result in report["runs"][0]["results"]:
    region = result["locations"][0]["physicalLocation"]["region"]
    region["startLine"] += 40
    region["endLine"] += 40
(root / "scan.sarif").write_text(json.dumps(report))
sarif = uri("scan.sarif")
notify("textDocument/didOpen", {"textDocument": {"uri": sarif, "languageId": "json", "version": 1, "text": (root / "scan.sarif").read_text()}})
acts = request("textDocument/codeAction", {"textDocument": {"uri": sarif}, "range": rng, "context": {"diagnostics": []}})
imp = next(a for a in acts if a["title"] == "Import into Code Review Notes")
request("workspace/executeCommand", imp["command"])
msg = wait(lambda m: m.get("method") == "window/showMessage", "import summary")
ok("imported 0, skipped 2" in msg["params"]["message"], f"re-import after the code moved adds nothing: {msg['params']['message']}")
ok(len(list((root / ".code-review-notes").glob("*.md"))) == 5, "editor import does not duplicate notes")

# Editing the noted line keeps the note on it, marked as changed.
edited = shifted.replace('"ping -c 1 " + host,', '"ping -c 1 " + hostname,')
notify("textDocument/didChange", {"textDocument": {"uri": py, "version": 3}, "contentChanges": [{"text": edited}]})
d = diags(py, "changed", lambda d: any("has changed" in x["message"] for x in d))
ping = next(x for x in d if "has changed" in x["message"])
ok(ping["range"]["start"]["line"] == 53 and "shell=True" in ping["message"], f"a note on an edited line stays on it, marked changed: {ping['message']}")
h = request("textDocument/hover", {"textDocument": {"uri": py}, "position": {"line": 53, "character": 4}})
ok(h and "code changed since this note" in h["contents"]["value"], "hover says the code changed")
acts = request("textDocument/codeAction", {"textDocument": {"uri": py}, "range": {"start": {"line": 53, "character": 0}, "end": {"line": 53, "character": 0}}, "context": {"diagnostics": []}})
request("workspace/executeCommand", next(a for a in acts if a["title"] == "Accept edited code")["command"])
d = diags(py, "accepted", lambda d: not any("has changed" in x["message"] for x in d))
ping_file = next(f for f in (root / ".code-review-notes").glob("*.md") if "# subprocess call with shell=True" in f.read_text())
ok("+ hostname," in ping_file.read_text() and "accepted the edited code" in ping_file.read_text(),
   "'Accept edited code' takes the current code as the note's snippet, and clears the mark")

gone = shifted.replace('    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n', "")
notify("textDocument/didChange", {"textDocument": {"uri": py, "version": 4}, "contentChanges": [{"text": gone}]})
d = diags(py, "stale", lambda d: any("stale" in x["message"] for x in d))
ok(sum("stale" in x["message"] for x in d) == 1, "deleting the noted code marks exactly that note stale")

acts = request("textDocument/codeAction", {"textDocument": {"uri": py}, "range": {"start": {"line": 56, "character": 0}, "end": {"line": 56, "character": 0}}, "context": {"diagnostics": []}})
request("workspace/executeCommand", next(a for a in acts if a["title"] == "Delete review note")["command"])
diags(py, "after delete", lambda d: len(d) == 2)
ok(not note_path.exists(), "delete removes the note file")

# Deleting the last note in an unopened file clears its diagnostics.
for f in (root / ".code-review-notes").glob("*.md"):
    if 'file = "app/controllers/users_controller.rb"' in f.read_text():
        f.unlink()
notify("workspace/didChangeWatchedFiles", {"changes": [{"uri": rb, "type": 3}]})
diags(rb, "cleared", lambda d: d == [])
ok(True, "diagnostics for an unopened file are cleared when its notes go")

# Non-report .json: no import action.
(root / "package.json").write_text('{"name": "demo", "dependencies": {}}')
pkg = uri("package.json")
notify("textDocument/didOpen", {"textDocument": {"uri": pkg, "languageId": "json", "version": 1, "text": (root / "package.json").read_text()}})
acts = request("textDocument/codeAction", {"textDocument": {"uri": pkg}, "range": rng, "context": {"diagnostics": []}})
ok(not any(a["title"] == "Import into Code Review Notes" for a in acts), f"no import action on package.json: {[a['title'] for a in acts]}")
report = (FIXTURES / "semgrep.sarif").read_text()
notify("textDocument/didChange", {"textDocument": {"uri": pkg, "version": 2}, "contentChanges": [{"text": report}]})
(root / "package.json").write_text(report)
notify("textDocument/didSave", {"textDocument": {"uri": pkg}})
acts = request("textDocument/codeAction", {"textDocument": {"uri": pkg}, "range": rng, "context": {"diagnostics": []}})
ok(any(a["title"] == "Import into Code Review Notes" for a in acts), "a .json file is checked again for being a report when saved")
brakeman_uri = uri("brakeman.json")
shutil.copy(FIXTURES / "brakeman.json", root / "brakeman.json")
notify("textDocument/didOpen", {"textDocument": {"uri": brakeman_uri, "languageId": "json", "version": 1, "text": (root / "brakeman.json").read_text()}})
acts = request("textDocument/codeAction", {"textDocument": {"uri": brakeman_uri}, "range": rng, "context": {"diagnostics": []}})
ok(any(a["title"] == "Import into Code Review Notes" for a in acts), "import action on a brakeman .json report")
gl_uri = uri("gl-sast-report.json")
shutil.copy(FIXTURES / "gl-sast-report.json", root / "gl-sast-report.json")
notify("textDocument/didOpen", {"textDocument": {"uri": gl_uri, "languageId": "json", "version": 1, "text": (root / "gl-sast-report.json").read_text()}})
acts = request("textDocument/codeAction", {"textDocument": {"uri": gl_uri}, "range": rng, "context": {"diagnostics": []}})
ok(any(a["title"] == "Import into Code Review Notes" for a in acts), "import action on a GitLab SAST report")

# Unreadable note file gets reported, not silently dropped.
bad = root / ".code-review-notes/deadbeef.md"
bad.write_text("+++\nid = \"deadbeef\"\n+++\n\n# Broken\n")
notify("workspace/didChangeWatchedFiles", {"changes": [{"uri": bad.as_uri(), "type": 1}]})
msg = wait(lambda m: m.get("method") == "window/showMessage" and "can't be read" in m["params"]["message"], "unreadable note message")
ok("deadbeef.md" in msg["params"]["message"], f"unreadable note announced: {msg['params']['message']}")
d = diags(bad.as_uri(), "unreadable note diagnostic", lambda d: len(d) == 1)
ok(d[0]["severity"] == 1 and "can't be read" in d[0]["message"], f"unreadable note gets an error on its file: {d[0]['message']}")
fixed = ('+++\nid = "deadbeef"\nfile = "app/users.py"\nstart_line = 1\nend_line = 1\nstatus = "open"\n'
         'author = "t"\ncreated = "2026-10-14T00:00:00Z"\nsnippet = "import sqlite3\\n"\n+++\n\n# Fixed in the editor\n')
notify("textDocument/didOpen", {"textDocument": {"uri": bad.as_uri(), "languageId": "markdown", "version": 1, "text": fixed}})
diags(py, "fixed note shown", lambda d: any("Fixed in the editor" in x["message"] for x in d))
diags(bad.as_uri(), "fixed note error cleared", lambda d: d == [])
ok(True, "fixing a broken note in the editor shows it, and clears its error, before saving")
notify("textDocument/didClose", {"textDocument": {"uri": bad.as_uri()}})
diags(bad.as_uri(), "error back after close", lambda d: len(d) == 1)
diags(py, "fixed note gone after close", lambda d: not any("Fixed in the editor" in x["message"] for x in d))
ok(True, "closing it unsaved brings the error back")
bad.unlink()
notify("workspace/didChangeWatchedFiles", {"changes": [{"uri": bad.as_uri(), "type": 3}]})
diags(bad.as_uri(), "unreadable note cleared", lambda d: d == [])
ok(True, "the error clears when the bad note file goes")

# Someone else's note is flagged, and its links are defanged.
planted = root / ".code-review-notes/feedf00d.md"
planted.write_text('+++\nid = "feedf00d"\nfile = "app/users.py"\nstart_line = 1\nend_line = 1\nstatus = "ok"\n'
                   'author = "Mallory"\ncreated = "2026-10-14T00:00:00Z"\nsnippet = "# pad\\n"\n+++\n\n'
                   '# Reviewed, all fine\n\nDetails [here](http://evil.example/x) and <http://evil.example/y>.\n')
notify("workspace/didChangeWatchedFiles", {"changes": [{"uri": planted.as_uri(), "type": 1}]})
diags(py, "planted note shown", lambda d: any("Reviewed, all fine" in x["message"] for x in d))
h = request("textDocument/hover", {"textDocument": {"uri": py}, "position": {"line": 0, "character": 0}})
value = h["contents"]["value"] if h else ""
ok("not written by you" in value and "here (`http://evil.example/x`)" in value and "`http://evil.example/y`" in value
   and "](http" not in value and "<http" not in value, f"a planted note is marked, and its links are plain text: {value!r}")

request("shutdown", None)
notify("exit", None)
proc.wait(timeout=5)
ok(proc.returncode == 0, "clean shutdown")
err = proc.stderr.read().decode()
if err.strip():
    print("server stderr:\n" + err)
