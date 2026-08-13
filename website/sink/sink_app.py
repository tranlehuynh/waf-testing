"""
Friday Night Poker - detonation chamber (REAL execution, contained).

This service runs the genuinely-vulnerable backends the WAF lab needs so a GoTestWAF
"bypass" can be confirmed as a real compromise instead of a status code. Unlike the
old api/sinks.py, the payloads here ARE executed: shell metacharacters reach /bin/sh,
templates reach Jinja2, YAML reaches an unsafe loader, `../` reaches open(), SQL reaches
SQLite, filters reach a real LDAP evaluator, XML reaches lxml with entities on.

It is deliberately exploitable. It is safe ONLY because of how it is deployed
(see docker-compose.yml), not because of anything it does:

  * reachable only from `api`, on a Docker network with `internal: true` - so it has NO
    route to the internet, the LAN, or the host. Code execution here cannot phone home,
    exfiltrate, or pivot.
  * non-root (uid 65534), all Linux capabilities dropped, no-new-privileges, read-only
    root filesystem with a tmpfs /tmp, pids/memory limited.
  * every code-exec payload runs as a short-lived subprocess with a hard 2s wall-clock
    timeout and CPU / address-space / file-size rlimits.
  * only fake, randomly-seeded data lives here (see seed.py).

Never publish this service directly and never move it onto an egress-capable network.
"""
import json
import os
import re
import resource
import sqlite3
import subprocess
import tempfile

from flask import Flask, jsonify, request

import seed

app = Flask(__name__)

# Build the fake filesystem + DB once, in the gunicorn master (started with --preload).
seed.build()

TIMEOUT = 2                 # wall-clock seconds per code-exec payload
OUT_MAX = 4000             # cap returned output so one finding stays readable
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"   # python lives in /usr/local/bin on this image

# What each category's vulnerable line looks like, for the report. The matching handler
# below is what actually runs.
SINK_SIG = {
    "shell_injection": "subprocess.run(f'ping -c1 {host}', shell=True)",
    "ss_include": 'os.system(ssi_exec_cmd)  # <!--#exec cmd="..."-->',
    "sst_injection": "jinja2.Template(user_input).render()",
    "path_traversal": "open(os.path.join('/var/www', user_path))",
    "sql_injection": "cursor.execute(\"...WHERE handle = '%s'\" % q)",
    "nosql_injection": "db.players.find(json.loads(user_json))",
    "ldap_injection": "conn.search(base, '(uid=%s)' % user)",
    "mail_injection": "message = 'To: %s\\r\\n...' % user_email",
    "xml_injection": "lxml.etree.fromstring(body, resolve_entities=True)",
    "crlf_injection": "Response(headers={'X-Search': q})",
    "xss_scripting": "element.innerHTML = q",
    "scanner_ua": "request logging / bot detection",
}
DETAIL = {
    "shell_injection": "remote command execution as the app user",
    "ss_include": "server-side include leading to command execution",
    "sst_injection": "server-side template injection leading to code execution",
    "path_traversal": "arbitrary file read as the app user",
    "sql_injection": "SQL injection: full player table incl. password hashes",
    "nosql_injection": "NoSQL injection: authentication bypass / server-side JS",
    "ldap_injection": "LDAP injection: directory authentication bypass",
    "mail_injection": "SMTP header injection: silent Bcc / extra recipients",
    "xml_injection": "XXE: local file read via external entity",
    "crlf_injection": "response splitting / header injection",
    "xss_scripting": "reflected XSS: session theft, account takeover",
    "scanner_ua": "automated scanner not fingerprinted or rate-limited",
}


# ---------- contained execution primitive ---------------------------------
def _rlimits():
    """Child-side limits applied after fork, before exec. Bounds a runaway payload.

    No RLIMIT_AS: it caps *virtual* memory, and CPython reserves large virtual ranges at
    startup, so a low RLIMIT_AS makes `python -c` (the Jinja/YAML sinks) die with a spurious
    MemoryError. Real memory is bounded by the container's mem_limit instead.
    """
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))


def run(argv, stdin=None):
    """Run argv in a fresh tmp cwd with a hard timeout and rlimits; return stdout+stderr."""
    with tempfile.TemporaryDirectory() as cwd:
        try:
            proc = subprocess.run(
                argv, cwd=cwd, input=stdin, capture_output=True, text=True,
                timeout=TIMEOUT, preexec_fn=_rlimits,
                env={"PATH": SAFE_PATH, "HOME": cwd},
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            return out[:OUT_MAX] or "[executed: no output]"
        except subprocess.TimeoutExpired:
            return f"[killed: exceeded {TIMEOUT}s wall-clock timeout]"
        except OSError as exc:
            return f"[exec error: {exc}]"


_YAML_CODE = (
    "import sys, yaml\n"
    "try:\n"
    "    d = yaml.load(sys.stdin.read(), Loader=yaml.Loader)\n"   # unsafe loader = RCE
    "    print('deserialized:', repr(d)[:400])\n"
    "except Exception as e:\n"
    "    print('unsafe yaml.load ran, raised:', type(e).__name__, str(e)[:300])\n"
)
_JINJA_CODE = (
    "import sys, jinja2\n"
    "try:\n"
    "    print(jinja2.Template(sys.stdin.read()).render())\n"
    "except Exception as e:\n"
    "    print('render error:', type(e).__name__, str(e)[:300])\n"
)


# ---------- per-category handlers -----------------------------------------
def h_shell(payload):
    # YAML deserialization RCE classifies as shell_injection (the !!python/object marker),
    # so branch on it and hand the raw YAML to an unsafe loader in a subprocess.
    if "!!python/" in payload:
        return run(["python", "-c", _YAML_CODE], stdin=payload)
    # Classic command-injection sink: user "host" concatenated into a shell command.
    return run(["/bin/sh", "-c", "ping -c1 -W1 " + payload])


def h_ssi(payload):
    match = re.search(r'#\s*exec\s+cmd\s*=\s*"([^"]*)"', payload, re.IGNORECASE)
    if match:
        return run(["/bin/sh", "-c", match.group(1)])
    match = re.search(r'#\s*include\s+(?:virtual|file)\s*=\s*"([^"]*)"', payload, re.IGNORECASE)
    if match:
        return h_lfi(match.group(1))
    return "[ssi directive parsed, no exec/include cmd found]"


def h_ssti(payload):
    return run(["python", "-c", _JINJA_CODE], stdin=payload)


def h_lfi(payload):
    # The vulnerable pattern: user path joined onto a docroot with no normalisation, so
    # `../` climbs out. Confined to this container's filesystem (no secrets, no egress).
    target = payload
    if target.startswith("file://"):
        target = target[7:]
    path = os.path.join(seed.DOCROOT, target)
    try:
        with open(path, "rb") as fh:
            data = fh.read(OUT_MAX)
        return f"opened: {path}\n---\n" + data.decode("utf-8", "replace")
    except OSError as exc:
        return f"open({path!r}) failed: {exc}"


def h_sqli(payload):
    # String-formatted query = injectable by construction. SQLite runs a single statement
    # per execute(), so stacked `; DROP` does not fire - true to a real sqlite3 app.
    sql = "SELECT id, handle, chips, pw_hash FROM players WHERE handle = '%s'" % payload
    con = sqlite3.connect(seed.DB_PATH)
    try:
        rows = con.execute(sql).fetchall()
        body = "\n".join("|".join(str(col) for col in row) for row in rows[:50])
        return f"query: {sql}\nrows_returned: {len(rows)}\n{body}"
    except sqlite3.Error as exc:
        return f"query: {sql}\nsqlite error: {exc}"
    finally:
        con.close()


def _mongo_collection():
    url = os.environ.get("MONGO_URL")
    if not url:
        return None
    try:
        import pymongo
        client = pymongo.MongoClient(url, serverSelectionTimeoutMS=800)
        coll = client["lab"]["players"]
        # A unique index makes the lazy seed safe under the four gunicorn workers: the
        # first writer wins, and a racing worker's duplicate rows are rejected one by one
        # (ordered=False) instead of doubling the collection.
        coll.create_index("username", unique=True)
        if coll.estimated_document_count() == 0:
            try:
                coll.insert_many([dict(p) for p in seed.PLAYERS], ordered=False)
            except Exception:
                pass
        return coll
    except Exception:
        return None


def _match_in_memory(doc, query):
    """Tiny Mongo-operator evaluator for the no-mongo fallback ($ne/$gt/$regex/$or)."""
    if "$or" in query:
        return any(_match_in_memory(doc, sub) for sub in query["$or"])
    for key, cond in query.items():
        val = doc.get(key)
        if isinstance(cond, dict):
            for op, operand in cond.items():
                if op == "$ne" and not (val != operand):
                    return False
                if op == "$gt" and not (val is not None and val > operand):
                    return False
                if op == "$regex" and not (val is not None and re.search(operand, str(val))):
                    return False
        elif val != cond:
            return False
    return True


def h_nosql(payload):
    # Reconstruct a query from the payload: a JSON object is used as the filter directly
    # (operator injection / auth bypass); anything else is treated as server-side $where JS.
    try:
        query = json.loads(payload)
    except ValueError:
        query = None
    if not isinstance(query, dict):
        query = {"$where": payload}

    coll = _mongo_collection()
    if coll is not None:
        try:
            docs = list(coll.find(query, {"_id": 0}).max_time_ms(1500).limit(20))
            return (f"mongo_query: {json.dumps(query)[:400]}\n"
                    f"documents_returned: {len(docs)}\n"
                    + "\n".join(json.dumps(doc) for doc in docs))
        except Exception as exc:
            return f"mongo_query: {json.dumps(query)[:400]}\nmongo error: {exc}"

    # Fallback: real operator evaluation over the fake directory ($where JS not available).
    if "$where" in query:
        return ("mongo unavailable; $where server-side JS needs the mongo sidecar.\n"
                f"detected $where: {query['$where'][:200]}")
    hits = [dict(p) for p in seed.PLAYERS if _match_in_memory(p, query)]
    return (f"query: {json.dumps(query)[:400]}\n"
            f"documents_returned: {len(hits)} (of {len(seed.PLAYERS)})\n"
            + "\n".join(json.dumps(h) for h in hits))


def _ldap_all():
    return "\n".join(f"{e['dn']} uid={e['uid']} role={e['role']}" for e in seed.DIRECTORY)


def h_ldap(payload):
    # Vulnerable app builds (uid=<payload>) with no escaping. The canonical injections
    # neutralise the filter - a bare *, a `)(` breakout, or an OR'd (objectclass=*) - so
    # the search returns every entry: authentication bypass.
    built = "(uid=%s)" % payload
    low = payload.lower()
    bypass = (payload.strip() == "*" or ")(" in payload
              or "(|(objectclass" in low.replace(" ", "") or "objectclass=*" in low)
    if bypass:
        return (f"built_filter: {built}\n"
                f"filter neutralised by injection -> matched ALL entries:\n{_ldap_all()}")
    # Well-formed (uid=x) lookup against the real directory.
    uid = payload.strip("() ")
    hits = [e for e in seed.DIRECTORY if e["uid"] == uid
            or (uid.endswith("*") and e["uid"].startswith(uid[:-1]))]
    return (f"built_filter: {built}\nentries_returned: {len(hits)}\n"
            + "\n".join(f"{e['dn']} uid={e['uid']}" for e in hits))


def h_mail(payload):
    # User value dropped straight into the header block: CRLF in the payload forges
    # extra headers / recipients. Nothing is sent (no socket, no egress).
    message = ("From: noreply@fridaynightpoker.local\r\n"
               "To: %s\r\n"
               "Subject: Your seat is reserved\r\n\r\nSee you Friday." % payload)
    head = message.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    injected = [ln for ln in lines[2:] if ln and not ln.startswith("Subject:")]
    return ("constructed_message:\n" + message[:2000]
            + "\n\ninjected_headers: " + json.dumps(injected))


def h_xxe(payload):
    from lxml import etree
    # resolve_entities on = XXE; no_network on = SSRF/exfil blocked; huge_tree off = no
    # billion-laughs. file:// entities read this container's files (inert, contained).
    parser = etree.XMLParser(resolve_entities=True, no_network=True,
                             load_dtd=True, huge_tree=False)
    try:
        root = etree.fromstring(payload.encode("utf-8", "replace"), parser)
        text = (root.text or "").strip()
        return ("entity_resolved: true\n"
                f"parsed_text: {text[:2000]}\n"
                f"note: file:// entities read local files; http/expect/netdoc blocked")
    except Exception as exc:
        return f"[xml parse: {type(exc).__name__}: {str(exc)[:300]}]"


def h_crlf(payload):
    synthesized = "X-Search: %s" % payload
    extra = [ln.strip("\r") for ln in synthesized.split("\n")[1:] if ln.strip()]
    return ("would_set_header: X-Search\nresulting_header_block:\n" + synthesized[:2000]
            + "\ninjected_lines: " + json.dumps(extra)
            + "\nnote: gunicorn/Flask reject bare CRLF in real response headers, so a "
              "genuine on-wire split is not reproducible on this stack")


def h_xss(payload):
    return ("browser_would_execute: true\n"
            "reflection_endpoint: GET /api/sink/xss?q=<payload>  (returns unescaped HTML)\n"
            "payload: " + payload[:1000]
            + "\nnote: open that endpoint in a browser to see real reflected execution")


def h_scanner(payload):
    return "client_fingerprint: automated security scanner\nrequest served normally (nothing executed)"


HANDLERS = {
    "shell_injection": h_shell,
    "ss_include": h_ssi,
    "sst_injection": h_ssti,
    "path_traversal": h_lfi,
    "sql_injection": h_sqli,
    "nosql_injection": h_nosql,
    "ldap_injection": h_ldap,
    "mail_injection": h_mail,
    "xml_injection": h_xxe,
    "crlf_injection": h_crlf,
    "xss_scripting": h_xss,
    "scanner_ua": h_scanner,
}


@app.route("/run", methods=["POST"])
def run_category():
    data = request.get_json(silent=True) or {}
    category = data.get("category", "")
    payload = data.get("payload", "") or ""
    handler = HANDLERS.get(category)
    if handler is None:
        return jsonify({"error": f"no sink for category {category!r}"}), 200
    try:
        result = handler(payload)
    except Exception as exc:   # never 500: the api must always get a scoreable answer
        result = f"[sink handler raised: {type(exc).__name__}: {str(exc)[:300]}]"
    return jsonify({
        "sink": SINK_SIG.get(category, category),
        "result": result,
        "detail": DETAIL.get(category, ""),
        "executed": True,
        "contained": True,
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "sink"}), 200


# Warm the Mongo players collection at import time (best-effort, runs once in the
# --preload master) so `mongosh` shows the accounts even before the first NoSQL request.
# If Mongo is not accepting connections yet, this fails fast and the lazy seed in
# _mongo_collection populates it on the first real request instead.
try:
    _mongo_collection()
except Exception:
    pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
