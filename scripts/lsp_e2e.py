"""Drive `code-review-notes lsp` over stdio the way Zed would, and check each behaviour.

Usage: cargo build && python3 scripts/lsp_e2e.py [BINARY]
"""
import atexit, json, pathlib, queue, shutil, subprocess, sys, tempfile, threading, time

REPO = pathlib.Path(__file__).resolve().parent.parent
BIN = sys.argv[1] if len(sys.argv) > 1 else str(REPO / "target/debug/code-review-notes")
FIXTURES = REPO / "fixtures"
WORK = pathlib.Path(tempfile.mkdtemp(prefix="code-review-notes-e2e-"))
atexit.register(shutil.rmtree, WORK, ignore_errors=True)  # also when a check fails
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
        # Answer server->client requests like Zed would.
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
    # Only the newest buffered diagnostics for a file count.
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

request("initialize", {"processId": None, "rootUri": root.as_uri(), "capabilities": {},
                       "workspaceFolders": [{"uri": root.as_uri(), "name": "demo"}]})
notify("initialized", {})
wait(lambda m: m.get("method") == "client/registerCapability", "watcher registration")
ok(True, "server registers a file watcher for .code-review-notes/*.md")

# Notes in files that are not open still reach the project diagnostics panel.
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

# Custom statuses from config.toml apply without a restart.
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

# Live edit of the note file updates hover without saving.
note_uri = note_path.as_uri()
note_text = note_path.read_text().replace("# New review note", "# Missing authorization on safe_show")
notify("textDocument/didOpen", {"textDocument": {"uri": note_uri, "languageId": "markdown", "version": 1, "text": note_text}})
d = diags(py, "renamed note", lambda d: any("Missing authorization" in x["message"] for x in d))
ok(True, "editing the note file updates the diagnostic live")

# While the note has unsaved edits, a status change edits the buffer, not the file on disk.
acts = request("textDocument/codeAction", {"textDocument": {"uri": py}, "range": {"start": {"line": 16, "character": 0}, "end": {"line": 16, "character": 0}}, "context": {"diagnostics": []}})
request("workspace/executeCommand", next(a for a in acts if a["title"] == "Mark Question")["command"])
edit = wait(lambda m: m.get("method") == "workspace/applyEdit", "applyEdit to the open note")
new_text = next(iter(edit["params"]["edit"]["changes"].values()))[0]["newText"]
ok("Missing authorization" in new_text and 'status = "question"' in new_text and "Missing authorization" not in note_path.read_text(),
   "status change on a note with unsaved edits goes to its buffer, keeping the edits")

# Closing the note without saving shows the saved version again.
notify("textDocument/didClose", {"textDocument": {"uri": note_uri}})
diags(py, "reverted note", lambda d: any(x["message"] == "[Note] New review note" for x in d))
ok(True, "closing a note with unsaved edits reverts it to the saved version")

shifted = "# pad\n" * 40 + text
notify("textDocument/didChange", {"textDocument": {"uri": py, "version": 2}, "contentChanges": [{"text": shifted}]})
d = diags(py, "shifted", lambda d: any(x["range"]["start"]["line"] == 48 for x in d))
ok(sorted(x["range"]["start"]["line"] for x in d) == [48, 53, 56], f"all notes follow a 40-line insertion: {sorted(x['range']['start']['line'] for x in d)}")
(root / "app/users.py").write_text(shifted)
notify("textDocument/didSave", {"textDocument": {"uri": py}})
time.sleep(0.3)
ok("start_line = 49" in (root / f".code-review-notes/{sql_id}.md").read_text(), "save writes moved anchor back to the note")

if shutil.which("semgrep"):
    subprocess.run(["semgrep", "--metrics=off", "--disable-version-check", "--no-git-ignore", "--config", str(FIXTURES / "rules/demo.yml"),
                    "--sarif", "-o", str(root / "scan.sarif"), "app/users.py"], cwd=root, check=True, capture_output=True)
    sarif = uri("scan.sarif")
    notify("textDocument/didOpen", {"textDocument": {"uri": sarif, "languageId": "json", "version": 1, "text": (root / "scan.sarif").read_text()}})
    acts = request("textDocument/codeAction", {"textDocument": {"uri": sarif}, "range": rng, "context": {"diagnostics": []}})
    imp = next(a for a in acts if a["title"] == "Import into Code Review Notes")
    request("workspace/executeCommand", imp["command"])
    msg = wait(lambda m: m.get("method") == "window/showMessage", "import summary")
    ok("imported 0, skipped 2" in msg["params"]["message"], f"re-scan after the code moved, imported from the editor, adds nothing: {msg['params']['message']}")

else:
    print("SKIP re-scan check (semgrep not installed)")

gone = shifted.replace('    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n', "")
notify("textDocument/didChange", {"textDocument": {"uri": py, "version": 3}, "contentChanges": [{"text": gone}]})
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

request("shutdown", None)
notify("exit", None)
proc.wait(timeout=5)
ok(proc.returncode == 0, "clean shutdown")
err = proc.stderr.read().decode()
if err.strip():
    print("server stderr:\n" + err)
