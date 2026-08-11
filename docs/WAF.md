# WAF Testing & Certificate Scripts

Two Bash scripts for working with a WAF-fronted domain:

| Script | Purpose |
| --- | --- |
| `run_gotestwaf.sh` | Run a Wallarm **GoTestWAF** scan against a target URL to measure how well its WAF blocks attack payloads. |
| `waf_cert.sh` | Issue / auto-renew **Let's Encrypt** certificates (DNS-01 via acme.sh) and export them (PEM + PKCS#12) for a WAF appliance. |

---

## `run_gotestwaf.sh` — WAF effectiveness scan

Wraps the `wallarm/gotestwaf` Docker image. GoTestWAF fires a battery of attack
payloads (SQLi, XSS, RCE, path traversal, …) plus benign requests, then scores how
many the WAF blocks vs. bypasses, and its false-positive rate.

### Usage

```bash
./run_gotestwaf.sh https://example.com
./run_gotestwaf.sh --url https://example.com --waf-name "my-waf" --block-codes 403,468
./run_gotestwaf.sh --url https://example.com --strict --skip-precheck
```

### Key options

| Option | Meaning | Default |
| --- | --- | --- |
| `--url URL` | Target URL (prompted if omitted) | — |
| `--waf-name NAME` | Label shown in the report | `unknown-waf` |
| `--block-codes LIST` | Status codes meaning "blocked" | `403` |
| `--pass-codes LIST` | Status codes meaning "not blocked" | `200,404` |
| `--workers N` | Parallel workers | `5` |
| `--strict` | Count anything that is neither a pass nor a block code as **BLOCKED** (GoTestWAF's own default) | off |
| `--skip-precheck` | Skip the benign-request sanity check | off |
| `--no-pull` | Don't pull a fresh image | off |

### Scoring nuance (important)

By default the script passes `--nonBlockedAsPassed`. Without it, GoTestWAF scores any
response matching **neither** the block nor the pass list as *blocked*, which silently
drives the false-positive score to 0% and inflates the results. Use `--strict` only if
you deliberately want that stricter behaviour — and make sure benign paths return a
listed pass code first (the pre-flight check reports this).

Reports are written to `reports/<timestamp>/` as HTML + JSON.

> The script auto-installs Docker CE on Ubuntu if missing and falls back to
> `sudo docker` when the daemon isn't reachable in the current session.

---

## `waf_cert.sh` — TLS certificates for WAF apps

Uses **acme.sh** + Let's Encrypt with a **DNS-01** challenge (so wildcard certs work
and no inbound port 80/443 is needed on the origin).

### Multi-domain model

- Each entry in the `DOMAINS` array gets its **own independent certificate**, key and
  `.p12` — one per WAF application.
- All domains share **one DNS provider account** (one set of API credentials).
- **HTTP-only apps need no certificate — simply leave them out of `DOMAINS`.**

#### Worked example

You run three WAF applications:

| App | Domain | Scheme | Cert? |
| --- | --- | --- | --- |
| A | `a.example.com` | HTTP | ❌ not needed — omit from `DOMAINS` |
| B | `b.example.com` | HTTPS | ✅ own cert |
| C | `c.example.com` | HTTPS | ✅ own cert |

Config block:

```bash
DOMAINS=("b.example.com" "c.example.com")   # A is HTTP → not listed
declare -A EXTRA_SANS=(
  # ["b.example.com"]="*.b.example.com"     # optional per-domain SANs
)
DNS_API="dns_cf"
export CF_Token="…"      # Cloudflare token, Zone:DNS:Edit (shared by B and C)
export CF_Account_ID="…"
```

### Workflow

```bash
./waf_cert.sh install            # one-time: install acme.sh + auto-renew cron
./waf_cert.sh issue              # issue certs for ALL domains (B and C)
./waf_cert.sh issue b.example.com   # …or just one
./waf_cert.sh show               # print key + fullchain to paste into the WAF UI
./waf_cert.sh list               # list configured HTTPS domains
./waf_cert.sh renew b.example.com   # force a renewal (cron normally handles this)
```

Files land in `${OUT_BASE}/<domain>/` (default `/etc/waf-certs/<domain>/`):

| File | Use |
| --- | --- |
| `privkey.pem` | Private key |
| `fullchain.pem` | Certificate (leaf + intermediate) |
| `chain.pem` | CA bundle (if the WAF wants it separately) |
| `cert.pem` | Leaf only |
| `<domain>.p12` | PKCS#12 bundle for F5 / Imperva / Barracuda |

### Auto-renewal

`issue` registers a per-domain acme.sh **deploy hook** (`--reloadcmd`). When acme.sh's
daily cron renews a cert (under 30 days remaining), it re-runs
`waf_cert.sh deploy-hook <domain>`, which re-exports **only that domain's** files and,
if `PUSH_SCRIPT` is set, uploads them to the WAF API. `deploy-hook` is internal — never
call it by hand.

### Notes

- `install` auto-detects the OS package manager (`apt-get` / `dnf` / `yum`).
- The script fails early with a clear message if the DNS credentials for the selected
  `DNS_API` are empty.
- For a different DNS provider set `DNS_API` (see `acme.sh --dnshelp`) and export the
  matching credentials.
