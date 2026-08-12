"""
Friday Night Poker - attack classifier + dispatcher to the detonation chamber.

Recognises an attack payload in any request surface (query, header, path, body) and
routes it to a backend that ACTUALLY executes it against fake data, so a GoTestWAF
"bypass" can be confirmed as a real compromise rather than just "the WAF returned 200".

Where execution happens (this file never executes attacker input itself, with the one
scoped exception below):
  - every code-exec / data-disclosure class is POSTed to the `sink` service, which runs
    it inside a hardened, NO-EGRESS, non-root, disposable container (see sink/sink_app.py
    and the isolation guarantees in docker-compose.yml). RCE there cannot reach out.
  - jndi_lookup (Log4Shell) is the exception: the outbound OOB callback is performed
    here in `api` (which has egress), and only to a host matching JNDI_CALLBACK_ALLOW.

So the classifier below stays the same; only the evidence step changed from canned
strings to real dispatch. classify() still fires on attack *syntax*, so GoTestWAF's
benign false-positive corpus stays unclassified and is never detonated.
"""
import base64
import binascii
import html
import json
import os
import re
import socket
import urllib.request
from urllib.parse import unquote, unquote_plus

# Only the first 8 KB of each surface is matched. GoTestWAF sends bodies up to
# 128 KB and every one of them is hostile, so the scan cost stays bounded.
MAX_SCAN = 8192

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# "autof<x>ocus o<x>nfocus=alert<x>(1)" splits keywords with throwaway tags. Removing
# them is the normalisation a WAF is expected to do before matching.
_TAG_NOISE = re.compile(r"<[^\s>]{0,16}>")

# Ordered; first match wins. Patterns match attack *syntax* rather than keywords so
# GoTestWAF's false-positive corpus ("union was a great select", "exec noun",
# "JavaScript: Basics of JavaScript Language") stays unclassified.
PATTERNS = [
    ("jndi_lookup", r"\$\{jndi:"),
    ("ss_include", r"<!--\s*#\s*(exec|include|echo)\b"),
    ("sst_injection", r"<#assign\b|\?new\(\)|\{\{[^{}]{0,64}\}\}|[$#]\{[^{}]{0,64}\}"),
    # Only genuinely dangerous XML constructs. A bare <?xml / <soap:Envelope is not
    # one: GoTestWAF wraps other classes' payloads in a SOAP envelope, and those must
    # classify as what they actually are.
    ("xml_injection", r"<!ENTITY\b|<!DOCTYPE[^>]{0,120}SYSTEM|xsi:schemaLocation|xs:include|encoding\s*=\s*[\"']utf-7"),
    ("ldap_injection", r"\(\s*&\s*\(uid=|\(\|\(objectclass|userpassword\s*[:=]|:2\.5\.13\.\d+:"),
    ("nosql_injection", r"\$(where|ne|gt|lt|regex|or)\b|db\.\w+\.(insert|find|update)|new\s+Date\(\)"),
    # The keyword may be preceded by an IMAP tag ("\r\nV100 CAPABILITY").
    ("mail_injection",
     r"(?:\r|\n|%0[ad])+\s*(?:\w{1,8}\s+)?(RCPT\s+TO|MAIL\s+FROM|QUIT|DATA|CAPABILITY|FETCH|LOGIN)\b"),
    ("shell_injection",
     r"[;&|]\s*(cat|ls|id|whoami|uname|wget|curl|getent|nc|bash|sh|set\s+/a)\b"
     r"|`\s*(id|cat|ls|whoami|uname|curl|wget)\b"
     r"|\$IFS|\$\(\(|\bcmd\s*=|\(\)\s*\{\s*:\s*;\s*\}"
     r"|!!python/object|Server\.ScriptTimeout|Response\.Write|WScript\.Shell|MSXML2\."),
    ("path_traversal", r"\.\./|\.\.\\|%c0%ae|file://|ntuser\.dat|/etc/(?:\./)*passwd|\\\\[.:\w]"),
    # "'or 1st parfume" is legitimate user input, so an OR needs a comparison after it.
    ("sql_injection",
     r"union\s+select|/\*!|'\s*or\s+\d+\s*=|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|information_schema"
     r"|json_(extract|depth)|xp_cmdshell|declare\s+@|group_concat\s*\("),
    # U+560A/U+560D are the overlong forms of LF/CR used to smuggle a header past a
    # decoder that normalises them late. %3a covers a still-encoded colon.
    ("crlf_injection",
     r"(?:\r|\n|%0[ad]|%e5%98%8[cd]|[嘊嘍])+\s*[\w-]{2,32}\s*(?::|%3a)"),
    ("xss_scripting",
     r"</?(script|svg|iframe|img|video|object|body|details|textarea)\b"
     r"|\bon(error|load|click|focus|toggle|scroll|wheel|auxclick|submit|mouse\w*|pointer\w*)\s*="
     r"|javascript:(?!\s|%20)|\b(alert|confirm|prompt)\s*[?.()]|document\s*\??\s*[.\[]|innerHTML"),
    # Last: these strings also appear inside other classes' payloads as out-of-band
    # callback domains, and those must classify as the attack, not as a scanner.
    ("scanner_ua",
     r"sqlmap/|\bnuclei\b|Fuzz Faster U Fool|OpenVAS|\bnikto\b|\bwpscan\b|masscan"
     r"|\.nasl\b|interact\.sh|oast\.me|burpcollaborator"),
]
PATTERNS = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in PATTERNS]
PATTERN_BY_NAME = dict(PATTERNS)


def _b64_variants(text):
    """Decoded forms of any long base64-looking tokens in text."""
    out = []
    for token in _B64_TOKEN.findall(text)[:8]:
        pad = "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(token + pad, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Only keep it if it looks like text, so binary noise never reaches the regexes.
        if decoded and sum(c.isprintable() for c in decoded) / len(decoded) > 0.9:
            out.append(decoded)
    return out


def variants(text):
    """Every form of one surface worth matching against.

    GoTestWAF's Base64Flat and URL encoders, and payloads that arrive
    double-encoded or HTML-entity-encoded, only reveal themselves after decoding.
    Doing it here is also what lets the report say the WAF failed to decode what
    thirty lines of stdlib did.
    """
    text = (text or "")[:MAX_SCAN]
    if not text:
        return []
    seen, out = set(), []
    once = unquote(text)
    for form in (text, once, unquote_plus(text), unquote(once), html.unescape(once),
                 _TAG_NOISE.sub("", once), *_b64_variants(text)):
        form = form[:MAX_SCAN]
        if form and form not in seen:
            seen.add(form)
            out.append(form)
    return out


def classify(surfaces):
    """Find the first attack class present.

    surfaces: [(name, value), ...] e.g. [('query:file', '../../etc/passwd')].
    Returns (category, surface_name, matched_snippet) or None. Patterns are tried
    outermost so the most specific class wins regardless of surface order.
    """
    decoded = [(name, forms) for name, value in surfaces
               for forms in [variants(value)] if forms]
    for category, pattern in PATTERNS:
        for name, forms in decoded:
            for form in forms:
                found = pattern.search(form)
                if found:
                    start = max(0, found.start() - 24)
                    return category, name, form[start:found.end() + 56]
    return None


def best_payload(category, raw_value):
    """The full decoded form of raw_value that actually matches this category.

    classify() returns only a short snippet window; the sink needs the complete payload
    to execute, so re-decode the surface's raw value and pick the variant that matches.
    """
    pattern = PATTERN_BY_NAME.get(category)
    if pattern is not None:
        for form in variants(raw_value):
            if pattern.search(form):
                return form
    return raw_value or ""


SINK_URL = os.environ.get("SINK_URL", "http://sink:5001/run")
SINK_TIMEOUT = 3.5

# Log4Shell callbacks fire from api (which has egress), but only to a host whose name
# ends with this suffix - set it to your own collaborator domain. Empty = never call out:
# a scan's payloads target *.oast.me / burpcollaborator.net, which you do not control, so
# the JNDI lookup is detected and logged but no outbound request is made by default.
JNDI_CALLBACK_ALLOW = os.environ.get("JNDI_CALLBACK_ALLOW", "").strip().lower()

_JNDI_HOST = re.compile(r"jndi:\w+://([^/]+)", re.IGNORECASE)


def _jndi_host(payload):
    match = _JNDI_HOST.search(payload)
    if not match:
        return None
    host = re.sub(r"\$\{[^}]*\}\.?", "", match.group(1))   # drop nested ${hostName}.
    host = host.split(":")[0].strip()                       # drop :port
    return host or None


def _jndi_callback(raw_value):
    """Real Log4Shell OOB callback, scoped to JNDI_CALLBACK_ALLOW (see above)."""
    base = {
        "sink": "logger.info('User-Agent: {}', ua)  # vulnerable Log4j",
        "detail": "Log4Shell-style JNDI lookup; a vulnerable Java logger would resolve it",
        "executed": True,
        "contained": True,
    }
    host = _jndi_host(raw_value)
    if not host:
        return dict(base, executed=False,
                    result="no JNDI host could be parsed from the payload")
    if not JNDI_CALLBACK_ALLOW or not host.lower().endswith(JNDI_CALLBACK_ALLOW):
        return dict(base, executed=False, result=(
            f"jndi_host: {host}\ncallback suppressed: host does not match "
            f"JNDI_CALLBACK_ALLOW ({JNDI_CALLBACK_ALLOW or 'unset'}). Set that env var to "
            f"your own collaborator suffix to fire a real outbound lookup."))
    lines = [f"jndi_host: {host}"]
    try:
        lines.append(f"dns_resolved: {socket.gethostbyname(host)}")
    except OSError as exc:
        lines.append(f"dns_error: {exc}")
    try:
        with urllib.request.urlopen(f"http://{host}/", timeout=3) as resp:
            lines.append(f"http_callback: {resp.status}")
    except Exception as exc:
        lines.append(f"http_callback_error: {type(exc).__name__}")
    lines.append("outbound OOB callback performed - check your collaborator for the hit")
    return dict(base, result="\n".join(lines))


def detonate(category, raw_value):
    """Execute the classified payload for real and return evidence, or an error dict.

    Never raises: the caller (echo) must always return 200 so GoTestWAF stays scoreable.
    jndi_lookup fires the api-side callback; every other class is run in the sink.
    """
    if category == "jndi_lookup":
        return _jndi_callback(raw_value)

    payload = best_payload(category, raw_value)
    body = json.dumps({"category": category, "payload": payload}).encode()
    req = urllib.request.Request(SINK_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=SINK_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"error": f"sink unreachable: {type(exc).__name__}", "executed": False}
