"""
Friday Night Poker - origin API.

This is deliberately a permissive test origin: every route accepts every HTTP method
and returns 200. It performs NO filtering and blocks nothing, so a GoTestWAF scan
measures the WAF sitting in front of it, not this server. Do not add
validation/blocking here.

What it does now do is *classify* each request and, for a recognised attack, actually
execute it against fake data to prove the impact (see sinks.py -> the `sink` service).
That is still not filtering - the status code is 200 either way. It exists because
GoTestWAF derives its verdict from the status code alone, so without this a report can
only say "the WAF returned 200", never "the payload reached my application and read
/etc/passwd". The execution is contained: attacker input runs in the no-egress, non-root
`sink` container, never in this process (the one exception is the scoped Log4Shell
callback in sinks.py). See docker-compose.yml for the isolation guarantees.
"""
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from html import escape

from flask import Flask, Response, g, jsonify, request

from sinks import classify, detonate

app = Flask(__name__)
# Never enable debug: Werkzeug's debugger is remote code execution. gunicorn serves
# this in the container (see Dockerfile), which does not set it.

# Bumped whenever this file or sinks.py changes. Returned as X-Origin-Build and by
# /api/health so a scan can prove in one request that server A is running current
# code - an undeployed origin silently voided ~40% of two earlier scans.
BUILD = "real-1"

ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Headers worth carrying into the evidence log alongside every X-* header. GoTestWAF's
# Header and UserAgent placeholders put payloads here, and its --addDebugHeader flag
# tags each request with its set/case/placeholder, which is the exact join key between
# a log line and a row in the CSV report.
WATCHED_HEADERS = ("User-Agent", "Referer", "Cookie", "Content-Type", "SOAPAction")

# The advertised attack surface: documentation for humans, and a label in the response.
# No routes are needed - the /api/<path> catch-all already serves all of them - and the
# classifier below fires on ANY surface regardless, because GoTestWAF sends its payloads
# to "/" rather than to these paths.
SINKS = {
    "/api/reports/download": ("file_read", ("file", "path")),
    "/api/players/search": ("sql_query", ("q", "handle")),
    "/api/tools/ping": ("shell", ("host",)),
    "/api/templates/preview": ("template", ("tpl", "name")),
    "/api/import/feed": ("xml_parse", ("xml",)),
}

# Keep a log line inside PIPE_BUF (4096) so a single write from any of gunicorn's four
# workers is atomic and lines never interleave. json.dumps(ensure_ascii=True) makes
# character count equal byte count, so this bound is exact.
LINE_MAX = 3900


def _surfaces(raw_body):
    """Every place a payload can arrive, as [(name, value), ...] for sinks.classify."""
    found = [("path", request.path)]
    found += [(f"query:{key}", value) for key, value in request.args.items(multi=True)]
    found += [(f"header:{name}", value) for name, value in _watched_headers().items()]
    if raw_body:
        found.append(("body", raw_body))
    return found


def _watched_headers():
    return {name: value for name, value in request.headers.items()
            if name.upper().startswith("X-") or name in WATCHED_HEADERS}


def _surface_raw(surface):
    """Full raw value of the surface classify() flagged, so detonate() gets the whole
    payload - classify() returns only a short snippet window, not enough to execute."""
    if surface == "path":
        return request.path
    if surface == "body":
        return g.get("raw_body", "")
    if surface.startswith("query:"):
        return request.args.get(surface.split(":", 1)[1], "")
    if surface.startswith("header:"):
        return request.headers.get(surface.split(":", 1)[1], "")
    return ""


def _emit(record):
    """Write one JSON line to stdout.

    JSONL rather than any printf format because the input is hostile by construction:
    json.dumps escapes newlines and control characters, so a payload cannot forge or
    split a log line. Docker captures stdout and owns rotation (see docker-compose.yml);
    a RotatingFileHandler would corrupt under four gunicorn workers.
    """
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    if len(line) > LINE_MAX:
        body = record.get("body") or ""
        record["body"] = body[:max(0, len(body) - (len(line) - LINE_MAX))]
        record["body_truncated"] = True
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


@app.before_request
def _observe():
    """Mint a request id, read the body once, and classify every surface.

    Reading the body here is load-bearing and order-sensitive: get_data() consumes
    Werkzeug's stream, so request.form is empty afterwards. echo() therefore reports
    the raw body text instead of a parsed form dict - which is better evidence anyway.
    """
    g.rid = uuid.uuid4().hex[:12]
    g.raw_bytes = request.get_data(cache=True)
    g.raw_body = g.raw_bytes.decode("utf-8", "replace")
    g.found = classify(_surfaces(g.raw_body))


@app.after_request
def _label(response):
    found = g.get("found")
    response.headers["X-Origin-Build"] = BUILD
    response.headers["X-Origin-Request-Id"] = g.get("rid", "-")
    response.headers["X-Origin-Sink"] = found[0] if found else "none"
    # Every response is JSON. nosniff is what keeps echoing a payload back inert: this
    # host is on the public internet, so reflecting raw markup into an HTML response
    # would be a genuine exploitable XSS on the domain - and it would buy nothing,
    # since GoTestWAF scores on the status code alone.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"

    raw_bytes = g.get("raw_bytes", b"")
    _emit({
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "rid": g.get("rid", "-"),
        "remote": (request.headers.get("X-Forwarded-For")
                   or request.headers.get("X-Real-IP") or request.remote_addr),
        "method": request.method,
        "path": request.path,
        "query": request.args.to_dict(flat=False),
        # Values kept verbatim: the log is never served over HTTP, so it is where the
        # byte-exact "this payload arrived" proof lives.
        "headers": {name: value[:200] for name, value in _watched_headers().items()},
        "body_len": len(raw_bytes),
        "body_sha256": hashlib.sha256(raw_bytes).hexdigest()[:16],
        "body": g.get("raw_body", "")[:1024],
        "category": found[0] if found else None,
        "surface": found[1] if found else None,
        "status": response.status_code,
        "build": BUILD,
    })
    return response


def echo(resource):
    """Return a 200 JSON echo of the request, plus real exploitation evidence if any."""
    raw_body = g.get("raw_body", "")
    body = request.get_json(silent=True)
    if body is None:
        body = raw_body or None

    attack = None
    found = g.get("found")
    if found:
        category, surface, snippet = found
        # Run the payload for real (in the contained sink, or the scoped JNDI callback).
        # detonate() never raises, so the response stays 200 for GoTestWAF.
        attack = dict(
            detonate(category, _surface_raw(surface)),
            category=category,
            surface=surface,
            # Escaped here only: this field is the one a human or a report generator is
            # most likely to paste into HTML. The raw bytes stay in the evidence log.
            matched=escape(snippet),
        )

    return jsonify({
        "resource": resource,
        "request_id": g.get("rid"),
        "method": request.method,
        "path": request.path,
        "query": request.args.to_dict(flat=False),
        "body": body,
        "body_len": len(g.get("raw_bytes", b"")),
        "content_type": request.headers.get("Content-Type"),
        "user_agent": request.headers.get("User-Agent"),
        "sink_available": SINKS.get(request.path, (None, ()))[0],
        "attack": attack,
    }), 200


# ---- Realistic poker REST endpoints (all accept every method) -----------
@app.route("/api/players", methods=ALL_METHODS)
def players():
    return echo("players")


@app.route("/api/tables", methods=ALL_METHODS)
def tables():
    return echo("tables")


@app.route("/api/games", methods=ALL_METHODS)
def games():
    return echo("games")


@app.route("/api/login", methods=ALL_METHODS)
def login():
    return echo("login")


@app.route("/api/health", methods=ALL_METHODS)
def health():
    return jsonify({"status": "ok", "build": BUILD}), 200


# The one endpoint that reflects a payload into HTML unescaped: genuine reflected XSS,
# so a bypass of an XSS rule can be confirmed by opening this in a browser. It is a
# deliberate, isolated exception to the JSON/nosniff response policy - the real site
# pages (React, auto-escaping) never do this. GoTestWAF scores on status alone, so this
# does not change any score; it exists purely for manual confirmation.
@app.route("/api/sink/xss", methods=ALL_METHODS)
def sink_xss():
    q = request.values.get("q", "")
    page = ("<!doctype html><html><head><meta charset=\"utf-8\"><title>Search</title></head>"
            "<body><h1>Results</h1><p>You searched for: " + q + "</p></body></html>")
    return Response(page, mimetype="text/html")


# ---- Catch-all: any /api/* path, any method -> 200 echo -----------------
@app.route("/api/<path:subpath>", methods=ALL_METHODS)
def catch_all(subpath):
    return echo(subpath)


# ---- Site paths that nginx cannot serve statically ----------------------
# nginx hands every non-GET method and every unknown path over here (see
# nginx/default.conf), because its static handler would answer 405 or 404 without
# reading the body. Answering 200 keeps the origin uniformly permissive, so a GoTestWAF
# result reflects the WAF rather than the origin's method and path handling.
@app.route("/", methods=ALL_METHODS)
@app.route("/<path:subpath>", methods=ALL_METHODS)
def site_catch_all(subpath=""):
    return echo(subpath or "site")


# A method outside ALL_METHODS (PROPFIND, MKCALENDAR, LOCK, TRACE - GoTestWAF's
# owasp-api/non-crud set sends these) never matches a route, so Werkzeug raises 405.
# Answering 200 here covers every verb without maintaining a list of them; 404 is
# belt-and-braces, since the catch-alls above already match every path.
@app.errorhandler(404)
@app.errorhandler(405)
def unmatched(_error):
    return echo("unmatched")


if __name__ == "__main__":
    # Dev only; in the container gunicorn serves the app (see Dockerfile).
    app.run(host="0.0.0.0", port=5000)
