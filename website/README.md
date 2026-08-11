# Friday Night Poker — WAF test origin

A small React site + Flask API, packaged with nginx and Docker Compose. It is the
**origin website** that sits behind your WAF so you can scan the WAF with
[`../script/run_gotestwaf.sh`](../script/run_gotestwaf.sh).

Two pages:

| Page | What it does |
| --- | --- |
| `/` | Landing page. Content only — **no API calls at all**. |
| `/rules` | House rules. Carries all the request traffic: a search that sends the payload in the **URL query** (`GET /api/rules?q=…`) and a note box that sends it in the **request body** (`POST /api/notes`). Each shows the status code and the raw origin response, so you can see whether the WAF blocked a payload or the origin echoed it back. |
| anything else | Not-found page, served with a **real `404`** status. |

The two real routes are listed twice — as `ROUTES` in `web/src/App.jsx` and as exact-match
`location` blocks in `nginx/default.conf`. **Add a new page to both**, or nginx will 404 a
route the app knows about.

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

The React app is compiled by Vite **inside the web image** (`web/Dockerfile`, a
`node:20-alpine` build stage feeding `nginx:alpine`), so nothing needs installing on the
host — but the build does need `registry.npmjs.org` reachable. Because the assets are
baked into the image, edits to `web/` require `./setup.sh restart` (a rebuild), not just
a container bounce.

Then check locally:

```bash
curl -s http://localhost/       | grep -o '<div id="root">'   # app shell
curl -so /dev/null -w '%{http_code}\n' http://localhost/rules # 200 — a real route
curl -so /dev/null -w '%{http_code}\n' http://localhost/nope  # 404 — not-found page
curl -s http://localhost/api/health                           # {"status":"ok"}
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
| `/api/health` | `GET` only → `{"status":"ok"}` |
| `/api/<anything>` | Catch-all → `200` echo, so any path/method the WAF test throws lands on the origin |

`/api/rules` and `/api/notes` need no code in `api/app.py` — the catch-all route already
returns a `200` echo for any `/api/*` path. There is no datastore: posting a note echoes
it back, and the site appends it client-side only.

Example:

```bash
curl -s "http://localhost/api/rules?q=string+bets"
curl -s -X POST http://localhost/api/notes \
  -H 'Content-Type: application/json' -d '{"note":"bringing the good whiskey"}'
curl -s -X DELETE http://localhost/api/tables/42
```

## Layout

```
web/     React app (Vite) + Dockerfile — built, then served by nginx
  index.html            Vite entry
  src/App.jsx           shell + route switch
  src/router.jsx         ~30-line router (no routing library for two pages)
  src/styles.css        design tokens + all styles
  src/pages/Home.jsx    landing page (no API calls)
  src/pages/Rules.jsx   house rules + the two API targets
api/     Flask app + Dockerfile (the API backend)
nginx/   default.conf — serves the built app, proxies /api/ to the api service
docker-compose.yml   web (build) + api (Flask)
setup.sh             install Docker + run/maintain the stack
```
