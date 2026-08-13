# Friday Night Poker — WAF test origin

A small React site + Flask API, packaged with nginx and Docker Compose. It is the
**origin website** that sits behind your WAF so you can scan the WAF with
[`../script/run_gotestwaf.sh`](../script/run_gotestwaf.sh).

Two pages:

| Page | What it does |
| --- | --- |
| `/` | Landing page. Content only — **no API calls at all**. |
| `/rules` | House rules. Carries all the request traffic: a search that sends the payload in the **URL query** (`GET /api/rules?q=…`) and a note box that sends it in the **request body** (`POST /api/notes`). Each shows the status code and the raw origin response, so you can see whether the WAF blocked a payload or the origin echoed it back. |
| anything else | Handed to the Flask app, which answers **`200`** with a JSON echo. |

The two real routes are listed twice — as `ROUTES` in `web/src/App.jsx` and as exact-match
`location` blocks in `nginx/default.conf`. **Add a new page to both**, or nginx will hand
a route the app knows about to the API instead of serving the app shell.

> Unknown paths deliberately return `200`, not `404`. GoTestWAF puts payloads in the URL
> path, and a `404` there is scored as "not blocked" even though the payload never reached
> an application — so the origin answers every path. The consequence is that the SPA's
> styled Not Found page is now reached only by in-app navigation.

## Where it fits

```
                     TLS cert issued by ../script/waf_cert.sh
                                     │
   Player / GoTestWAF ──HTTPS──▶  [ WAF ]  ──HTTP:80──▶  [ this server ]
   (https://your-domain)          DNS points          nginx + Flask API
                                  here                 (the origin)
```

1. Issue a cert for your domain with [`../script/waf_cert.sh`](../script/waf_cert.sh) and install it on the **WAF**.
2. Point the domain's **DNS at the WAF**.
3. Configure the **WAF to forward to this server's IP on port 80**.
4. Run the website here (below), then scan:
   `../script/run_gotestwaf.sh https://your-domain --waf-name poker-waf`.

> The origin is intentionally **permissive** — every endpoint returns `200` and echoes
> input, with no filtering. That way GoTestWAF measures your **WAF**, not this server.
> Scan the WAF domain (`https://…`), not the origin directly.

## Run it

```bash
./setup.sh            # installs Docker if missing, then builds + starts
./setup.sh status     # container status
./setup.sh logs       # follow logs
./setup.sh restart    # rebuild + restart, after editing web/ or nginx/
./setup.sh down       # stop
```

Serving is split across two containers. `web` (`web/Dockerfile`, `node:20-alpine`)
compiles the React app with Vite at **image-build** time, then on start copies the output
into the `site` volume and exits; `nginx` is the stock `nginx:alpine` image and serves
that volume. So nothing needs installing on the host — but the build does need
`registry.npmjs.org` reachable. Two consequences:

- editing `web/` requires `./setup.sh restart` (a rebuild), not just a container bounce —
  the compiled assets live in the `web` image;
- editing `nginx/default.conf` only needs `docker compose restart nginx`, since the config
  is bind-mounted.

Then check locally:

```bash
curl -s http://localhost/       | grep -o '<div id="root">'   # app shell
curl -so /dev/null -w '%{http_code}\n' http://localhost/rules # 200 — a real route
curl -so /dev/null -w '%{http_code}\n' http://localhost/nope  # 200 — handed to the API
curl -so /dev/null -w '%{http_code}\n' -X POST -d a=1 http://localhost/  # 200 — body read
curl -s http://localhost/api/health                           # {"status":"ok","build":"real-2"}
curl -s 'http://localhost/api/reports/download?file=../../../../etc/passwd'  # REAL file read (sink container)
```

## API endpoints

All of these accept **every HTTP method** (`GET POST PUT DELETE PATCH OPTIONS HEAD`) and
return `200` with a JSON echo of the request:

| Endpoint | Notes |
| --- | --- |
| `/api/rules?q=…` | **Used by `/rules`** — payload arrives in the URL query |
| `/api/notes` | **Used by `/rules`** — payload arrives in the JSON body |
| `/api/players` | Poker players resource |
| `/api/tables` | Live tables resource |
| `/api/games` | Games resource |
| `/api/login` | Login resource |
| `/api/health` | `{"status":"ok","build":"…"}` — the `build` is the deployed-version check |
| `/api/<anything>` | Catch-all → `200` echo, so any path/method the WAF test throws lands on the origin |

`/api/rules` and `/api/notes` need no code in `api/app.py` — the catch-all route already
returns a `200` echo for any `/api/*` path. There is no datastore: posting a note echoes
it back, and the site appends it client-side only.

### Real attack surface (detonation chamber)

`api/sinks.py` recognises an attack payload in any query value, header, URL path or
request body and — for a recognised attack — **actually executes it against fake data**,
then adds an `attack` block (`executed: true`, `contained: true`, plus the real `result`)
to the response. This is what turns a GoTestWAF *bypass* into a confirmed compromise:
a shell payload runs in a real shell, `../` reads a real file, SQL hits a real SQLite DB,
a template renders in real Jinja2, XML resolves real external entities.

It exists because GoTestWAF derives its verdict from the HTTP status code alone. Without
it a report can only say "the WAF returned 200"; with it, each unblocked payload is tied
to a named feature **and proven impact**. The status code stays `200` either way, so the
scan score is unchanged.

**Where execution happens — and why it is safe.** Attacker input never runs in the `api`
process. It is POSTed to a separate `sink` service that is deliberately vulnerable but
contained by deployment (see the `networks` and `sink` hardening in `docker-compose.yml`):

- `sink` and `mongo` sit only on the `detonation` network (`internal: true`) — **no route
  to the internet, the LAN, or the host**, so even genuine RCE there cannot phone home or
  pivot.
- `sink` runs non-root, all Linux capabilities dropped, `no-new-privileges`, read-only
  root filesystem, with process/memory caps. Every code-exec payload runs as a subprocess
  with a 2s timeout and rlimits.
- Only fake, randomly-seeded data lives there (`sink/seed.py`): random players, a planted
  fake `/etc/passwd` and `db.conf`, a fake directory.

The one exception is **Log4Shell/JNDI**: the outbound OOB callback fires from `api` (which
has egress), and only to a host matching the `JNDI_CALLBACK_ALLOW` env var — set it to your
own collaborator suffix. Left empty (the default), JNDI is detected and logged but no
outbound call is made, so a scan does not blast third-party OOB domains.

> **Operator hardening (recommended):** because these sinks genuinely execute, firewall
> this origin's port 80 to accept traffic **only from your WAF's egress IPs**. Origin IPs
> are often discoverable, and a payload that reaches the origin directly skips the very WAF
> you are testing.

These paths advertise a sink even for benign input. GoTestWAF itself never visits them —
it sends everything to the base URL — so they are for the report's reproduction commands
and for targeted scans (`--url https://your-domain/api/players/search`):

| Endpoint | Parameters | Models |
| --- | --- | --- |
| `/api/reports/download` | `file`, `path` | path traversal / local file read |
| `/api/players/search` | `q`, `handle` | SQL injection |
| `/api/tools/ping` | `host` | OS command injection |
| `/api/templates/preview` | `tpl`, `name` | server-side template injection |
| `/api/import/feed` | XML body | XXE / XML injection |

Every request also writes one JSON line to stdout with the payload, the classified
category, a request id, and the detonation verdict — `attack_executed` plus a 200-char
`attack_result` digest. Those last two are what separate *arrived* from *ran*: the full
exploitation output goes back in the HTTP response, and GoTestWAF reads the status code
and discards the body, so the log is the only place the proof survives a scan.

```bash
docker compose logs --no-color api | grep '^{' > evidence.jsonl

# every payload that got through the WAF *and* really executed
jq -c 'select(.attack_executed) | {rid, category, surface, attack_result}' evidence.jsonl
```

Each line also carries GoTestWAF's own test tag under `.headers` (the `X-Gotestwaf-Test`
header, added by `--addDebugHeader`, which `../script/run_gotestwaf.sh` passes by default).
That tag is the join key from a line here to a per-test row of the scan's report (the
`.json` artifact, and the `.csv` too if the gotestwaf image still emits one), so a
"bypassed" row can be tied to the payload that arrived and what it did on the origin.

One behavioural note: the app reads the raw request body before Flask parses it, so a
form-encoded body appears in the echo as the raw string rather than a parsed dict.

Example:

```bash
curl -s "http://localhost/api/rules?q=string+bets"
curl -s -X POST http://localhost/api/notes \
  -H 'Content-Type: application/json' -d '{"note":"bringing the good whiskey"}'
curl -s -X DELETE http://localhost/api/tables/42
```

## Layout

```
web/     React app (Vite) + Dockerfile — compiled into the `site` volume for nginx
  index.html            Vite entry
  src/App.jsx           shell + route switch
  src/router.jsx         ~30-line router (no routing library for two pages)
  src/styles.css        design tokens + all styles
  src/pages/Home.jsx    landing page (no API calls)
  src/pages/Rules.jsx   house rules + the two API targets
api/     Flask app + Dockerfile (the API backend / orchestrator)
  app.py                routes, request classification, evidence log
  sinks.py              payload classifier + dispatch to the sink; scoped JNDI callback
sink/    Detonation chamber + Dockerfile — the real, contained vulnerable backends
  sink_app.py           per-category handlers that actually execute the payload
  seed.py               fake, randomly-seeded data (players DB, files, directory)
nginx/   default.conf — bind-mounted into the stock nginx:alpine container; serves the
         built app from the `site` volume and proxies /api/ to the api service
docker-compose.yml   nginx + web (build-only) + api (edge) · sink + mongo
                     (detonation, internal:true, no egress)
setup.sh             install Docker + run/maintain the stack
```
