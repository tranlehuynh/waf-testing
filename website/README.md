# Royal Flush Poker — WAF test origin

A simple poker landing page + API, packaged with nginx and Docker Compose. It is the
**origin website** that sits behind your WAF so you can scan the WAF with
[`../script/run_gotestwaf.sh`](../script/run_gotestwaf.sh).

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
./setup.sh restart    # after editing web/ or nginx/
./setup.sh down       # stop
```

Then check locally:

```bash
curl -s http://localhost/            | grep -i poker   # landing page
curl -s http://localhost/api/health                    # {"status":"ok"}
```

## API endpoints

All of these accept **every HTTP method** (`GET POST PUT DELETE PATCH OPTIONS HEAD`) and
return `200` with a JSON echo of the request:

| Endpoint | Notes |
| --- | --- |
| `/api/players` | Poker players resource |
| `/api/tables` | Live tables resource |
| `/api/games` | Games resource |
| `/api/login` | Login form target (the landing-page form posts here) |
| `/api/health` | `GET` only → `{"status":"ok"}` |
| `/api/<anything>` | Catch-all → `200` echo, so any path/method the WAF test throws lands on the origin |

Example:

```bash
curl -s -X POST http://localhost/api/login -d 'user=alice&pass=secret'
curl -s -X DELETE http://localhost/api/tables/42
```

## Layout

```
web/     static poker landing page (served by nginx)
api/     Flask app + Dockerfile (the API backend)
nginx/   default.conf — serves web/, proxies /api/ to the api service
docker-compose.yml   nginx (web) + Flask (api)
setup.sh             install Docker + run/maintain the stack
```
