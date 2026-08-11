# waf-testing

Helper scripts and a demo origin site for working with a WAF-fronted domain:

| Path | What it does |
| --- | --- |
| [`script/run_gotestwaf.sh`](script/run_gotestwaf.sh) | Run a Wallarm **GoTestWAF** scan against a target URL to measure how well its WAF blocks attack payloads. |
| [`script/waf_cert.sh`](script/waf_cert.sh) | Issue / auto-renew **Let's Encrypt** certificates (DNS-01 via acme.sh) and export them (PEM + PKCS#12) for a WAF appliance. |
| [`website/`](website/) | A demo poker site (nginx + Flask API) to run **behind your WAF** as the origin/target for GoTestWAF. See [`website/README.md`](website/README.md). |

Detailed reference: [`docs/WAF.md`](docs/WAF.md).

### Layout

```
script/
  run_gotestwaf.sh   GoTestWAF scan wrapper (Docker)
  waf_cert.sh        acme.sh / Let's Encrypt cert issuer + exporter
website/             demo origin site (nginx + Flask), see its own README
docs/WAF.md          detailed reference for both scripts
```

---

## Requirements

- **Linux** (Ubuntu/Debian or RHEL/Fedora). `run_gotestwaf.sh` targets Ubuntu and can
  auto-install Docker; `waf_cert.sh` auto-detects `apt-get` / `dnf` / `yum`.
- `bash`, `curl`, `openssl`.
- `run_gotestwaf.sh`: **Docker** (auto-installed on Ubuntu if missing).
- `waf_cert.sh`: a DNS provider account whose API can create TXT records
  (Cloudflare, Route53, GoDaddy, …).

```bash
chmod +x script/run_gotestwaf.sh script/waf_cert.sh
```

---

## 1. Test a WAF — `script/run_gotestwaf.sh`

Runs the `wallarm/gotestwaf` Docker image, which fires attack payloads (SQLi, XSS, RCE,
path traversal, …) plus benign requests, then scores how many the WAF blocks vs.
bypasses and reports a false-positive rate.

### Quick start

```bash
# Simplest form (prompts for confirmation after a benign-request pre-check)
./script/run_gotestwaf.sh https://example.com

# Name the WAF in the report and add extra "blocked" status codes
./script/run_gotestwaf.sh --url https://example.com --waf-name "my-waf" --block-codes 403,468

# Non-interactive (CI/cron): skip the pre-check prompt
./script/run_gotestwaf.sh --url https://example.com --skip-precheck
```

### Options

| Option | Meaning | Default |
| --- | --- | --- |
| `--url URL` | Target URL (prompted if omitted) | — |
| `--waf-name NAME` | Label shown in the report | `unknown-waf` |
| `--block-codes LIST` | Status codes meaning "blocked" | `403` |
| `--pass-codes LIST` | Status codes meaning "not blocked" | `200,404` |
| `--workers N` | Parallel workers | `5` |
| `--strict` | Count anything that is neither a pass nor a block code as **BLOCKED** | off |
| `--skip-precheck` | Skip the benign-request sanity check | off |
| `--no-pull` | Don't pull a fresh image | off |
| `-h`, `--help` | Show help | — |

A URL without a scheme gets `https://` prepended; a trailing slash is stripped.

> **Scoring note:** by default the script passes `--nonBlockedAsPassed`. Without it
> (i.e. with `--strict`), GoTestWAF scores any response matching *neither* list as
> "blocked", which silently drives the false-positive score to 0%. Use `--strict` only
> when you deliberately want that stricter behaviour.

### Output

HTML + JSON reports are written to `reports/<timestamp>/` **relative to your current
directory**, not to `script/` — so run it from the repo root to collect reports in
`./reports/`. The script prints the file list when it finishes.

---

## 2. Get certificates for HTTPS WAF apps — `script/waf_cert.sh`

Uses **acme.sh** + Let's Encrypt with a **DNS-01** challenge (works for wildcards; no
inbound port 80/443 needed on the origin).

### Multi-domain model

- Each entry in the `DOMAINS` array gets its **own independent certificate**, key and
  `.p12` — one per WAF application.
- All domains share **one DNS provider account** (one set of API credentials).
- **HTTP-only apps need no certificate — leave them out of `DOMAINS`.**

Example: three WAF apps, one HTTP and two HTTPS —

| App | Domain | Scheme | Cert? |
| --- | --- | --- | --- |
| A | `a.example.com` | HTTP | ❌ omit from `DOMAINS` |
| B | `b.example.com` | HTTPS | ✅ own cert |
| C | `c.example.com` | HTTPS | ✅ own cert |

### Step 1 — Configure

Edit the config block at the top of [`script/waf_cert.sh`](script/waf_cert.sh):

```bash
DOMAINS=("b.example.com" "c.example.com")   # A is HTTP → not listed

declare -A EXTRA_SANS=(
  # ["b.example.com"]="*.b.example.com"     # optional per-domain extra SANs
)

EMAIL="you@example.com"
DNS_API="dns_cf"                            # dns_cf=Cloudflare, dns_aws=Route53, …
export CF_Token="…"                         # Cloudflare token (Zone:DNS:Edit)
export CF_Account_ID="…"

OUT_BASE="/etc/waf-certs"                   # per-domain dir: ${OUT_BASE}/<domain>
P12_PASS=""                                 # .p12 password, empty = none
PUSH_SCRIPT=""                              # optional: uploads the cert via the WAF API
```

For a different provider set `DNS_API` (see `acme.sh --dnshelp`) and export its
matching credentials. The script fails early with a clear message if the credentials for
`dns_cf` / `dns_aws` are empty.

### Step 2 — Run

```bash
sudo ./script/waf_cert.sh install            # one-time: install acme.sh + auto-renew cron
./script/waf_cert.sh issue                   # issue certs for ALL domains (B and C)
./script/waf_cert.sh issue b.example.com     # …or just one domain

./script/waf_cert.sh list                    # list configured HTTPS domains
./script/waf_cert.sh show                    # print key + fullchain to paste into the WAF UI
./script/waf_cert.sh show b.example.com      # …for one domain
./script/waf_cert.sh renew b.example.com     # force a renewal now (cron normally handles this)
```

### Output files

Per domain, in `${OUT_BASE}/<domain>/`:

| File | Use in the WAF |
| --- | --- |
| `privkey.pem` | Private key |
| `fullchain.pem` | Certificate (leaf + intermediate) |
| `chain.pem` | CA bundle (if requested separately) |
| `cert.pem` | Leaf only |
| `<domain>.p12` | PKCS#12 bundle for F5 / Imperva / Barracuda |

### Auto-renewal

`issue` registers a per-domain acme.sh **deploy hook**. When acme.sh's daily cron
renews a cert (under 30 days remaining), it re-exports **only that domain's** files and,
if `PUSH_SCRIPT` is set, uploads them via the WAF API. Do not call `deploy-hook` by hand.

---

## 3. Demo origin site — `website/`

An intentionally permissive poker landing page + Flask API (nginx on port 80, Docker
Compose) to place **behind** the WAF so a scan measures the WAF rather than the origin.

```bash
cd website
./setup.sh            # installs Docker if missing, then builds + starts
./setup.sh status     # container status
./setup.sh logs       # follow logs
./setup.sh down       # stop
```

Full details, endpoint list and the traffic-flow diagram: [`website/README.md`](website/README.md).

---

## End-to-end example

```bash
# 1. Stand up the origin, then point the WAF at this host on port 80
cd website && ./setup.sh && cd ..

# 2. Get certs for the two HTTPS apps (domain A is HTTP, so no cert)
sudo ./script/waf_cert.sh install
./script/waf_cert.sh issue
./script/waf_cert.sh show b.example.com     # paste into the WAF UI, repeat for c.example.com

# 3. After the WAF is serving HTTPS, test each app's WAF
./script/run_gotestwaf.sh https://b.example.com --waf-name "app-B"
./script/run_gotestwaf.sh https://c.example.com --waf-name "app-C"
./script/run_gotestwaf.sh http://a.example.com  --waf-name "app-A"   # HTTP app
```

Always scan the **WAF domain**, never the origin IP directly — otherwise the report
measures nothing.

---

## Security notes

- DNS-provider credentials are filled into `script/waf_cert.sh` in plaintext. They ship
  empty in this repo; if you fill them in, move them to a gitignored `.env` or a secret
  store before committing.
- `waf_cert.sh show` prints the **private key** to stdout — run it only where that's safe.
- The GoTestWAF pre-check uses `curl -k` (skips TLS verification) purely for the sanity
  probe; the scan itself still hits the real endpoint.
- The `website/` origin returns `200` for every path and method by design. Do not expose
  it anywhere other than behind the WAF you are testing.
```
