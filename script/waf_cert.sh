#!/bin/bash
#
# waf_cert.sh - Issue / renew Let's Encrypt certs (acme.sh in Docker) and export them for a WAF
#
#   ./waf_cert.sh setup                   EVERYTHING: install, issue every domain, print the certs
#   ./waf_cert.sh install                 Pull the acme.sh image + start the auto-renew container
#   ./waf_cert.sh issue  [domain]         Issue cert(s) for the first time (all, or one)
#   ./waf_cert.sh continue <domain>       VALIDATION=dns-manual only: finish after adding the TXT record
#   ./waf_cert.sh show   [domain]         Print private key + fullchain (paste into WAF UI)
#   ./waf_cert.sh renew  [domain]         Force a renewal now (normally the container handles this)
#   ./waf_cert.sh export [domain]         Re-export the files and re-arm the after-renewal hook
#   ./waf_cert.sh list                    List configured HTTPS domains
#   ./waf_cert.sh status                  Show the renew container + acme.sh's own cert list
#   ./waf_cert.sh uninstall               Remove container + volume + image (exported certs are kept)
#
# Nothing is installed on the host: acme.sh, the Let's Encrypt account key and all
# renewal state live in a Docker volume; only the exported certs land on disk under
# OUT_BASE. 'uninstall' takes the whole thing back off the box in one command.
#
# Multi-domain model:
#   Each entry in DOMAINS gets its OWN independent certificate, key and .p12.
#   HTTP-only apps need no cert - simply leave them OUT of the DOMAINS list.
#   Example: domain A is HTTP (not listed); domains B and C are HTTPS (listed).
#
set -euo pipefail

# ==================== CONFIGURATION ====================
# HTTPS domains that need a cert - ONE independent cert per entry.
# HTTP-only apps (e.g. domain A) are simply NOT listed here: no cert is issued.
DOMAINS=("superman.chubbyduck.org")

# Optional extra SANs per domain (wildcards / aliases), keyed by the domain above.
# Leave an entry out for a plain single-name cert.
declare -A EXTRA_SANS=(
  # ["b.example.com"]="*.b.example.com"
  # ["c.example.com"]="www.c.example.com"
)

EMAIL="linhpn@vng.com.vn"            # must be a real address - Let's Encrypt rejects example.com

# How Let's Encrypt verifies you own the domain. It never talks to your WAF - it only
# checks the DOMAIN, so a custom/self-built WAF is fine.
#
#   auto        Use dns-api if DNS credentials are filled in below, otherwise webroot.
#   dns-api     acme.sh adds the TXT record itself through your DNS host's API.
#               Needs DNS_API + credentials below. Fully automatic.
#   dns-manual  acme.sh prints a TXT record and you add it by hand in any DNS panel.
#               Works with ANY DNS host, no API needed. You must repeat it every 90 days.
#   webroot     Let's Encrypt fetches a file over plain HTTP port 80. No DNS credentials
#               at all. acme.sh drops the file in WEBROOT and the origin nginx serves it,
#               so port 80 is NOT taken over and the site keeps running. Renews
#               automatically. Requires: http://<domain>/ reaches the origin nginx.
VALIDATION="auto"

WEBROOT=""                           # VALIDATION=webroot only - host dir shared with the origin
                                     # nginx (see website/docker-compose.yml).
                                     # Empty = <repo>/website/acme-challenge

DNS_API="dns_cf"                     # VALIDATION=dns-api only - which DNS host's API to use
                                     # dns_cf=Cloudflare, dns_aws=Route53,
                                     # dns_gd=GoDaddy, dns_namecheap...
                                     # see: ./waf_cert.sh -- --dnshelp

# DNS provider credentials (VALIDATION=dns-api only; fill in the lines matching DNS_API)
export CF_Token=""                   # Cloudflare API token (Zone:DNS:Edit)
export CF_Account_ID=""
# export AWS_ACCESS_KEY_ID=""
# export AWS_SECRET_ACCESS_KEY=""

# Under sudo, $HOME is /root - resolve back to the invoking user so the certs do not
# end up split between /root/waf-certs and /home/<user>/waf-certs.
if [[ -n "${SUDO_USER:-}" ]]; then
  REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  REAL_OWNER="${SUDO_UID}:${SUDO_GID}"
else
  REAL_HOME="$HOME"
  REAL_OWNER="$(id -u):$(id -g)"
fi

OUT_BASE="${REAL_HOME}/waf-certs"    # must be an ABSOLUTE path (it is bind-mounted into the container)
                                     # per-domain files live in ${OUT_BASE}/<domain>
KEY_LENGTH="ec-256"                  # ec-256 = ECDSA (acme.sh default); use 2048/4096 if the WAF wants RSA
P12_PASS=""                          # password for the .p12 file, empty = no password
PUSH_SCRIPT=""                       # (optional) script that uploads the cert via WAF API - see note in cmd_export

DOCKER="docker"                      # set to "sudo docker" if your user is not in the docker group
IMAGE="neilpang/acme.sh:latest"      # official acme.sh image
VOLUME="waf-acme"                    # docker volume holding acme.sh + account key + renewal state
CONTAINER="waf-acme-renew"           # long-lived container that runs acme.sh's daily cron
# =======================================================

SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
HOST_OWNER="$REAL_OWNER"

# acme.sh needs --ecc on every command that touches an ECDSA cert
if [[ "$KEY_LENGTH" == ec-* ]]; then ECC=(--ecc); else ECC=(); fi

log() { echo "[$(date '+%F %T')] $*"; }
die() { echo "[$(date '+%F %T')] ERROR: $*" >&2; exit 1; }

# A URL or a path here ends up as a bogus SAN and acme.sh fails deep inside openssl,
# so reject anything that is not a bare hostname before it gets that far.
check_domain() {
  local d="$1"
  case "$d" in
    *://*|*/*|*:*|*\ *)
      die "'$d' is not a domain name - pass just the hostname, e.g. superman.chubbyduck.org" ;;
  esac
  [[ "$d" == *.* ]] || die "'$d' does not look like a domain name (no dot in it)."
}

# --- Translate VALIDATION into acme.sh flags + docker run options ---------
# Only 'issue'/'continue' need this; every other command reads state from the volume.
CRED_ENV=()      # -e flags forwarded to the container (values stay out of the process list)
RUN_OPTS=()      # extra docker run options
ISSUE_ARGS=()    # how acme.sh should validate

# Prove a challenge file can actually be written, repairing ownership if it cannot.
# Without this a root-owned WEBROOT surfaces later as a confusing "origin returns 404".
ensure_webroot_writable() {
  # subshells: a failing redirection is reported by the shell itself, so 2>/dev/null
  # has to wrap the whole thing to keep a bare "Permission denied" out of the output
  local probe="${WEBROOT}/.well-known/acme-challenge/.waf-write-test"
  if ! ( : > "$probe" ) 2>/dev/null; then
    log "Challenge directory is not writable - taking ownership (needs sudo)..."
    sudo chown -R "$REAL_OWNER" "$WEBROOT" 2>/dev/null || true
    ( : > "$probe" ) 2>/dev/null \
      || die "cannot write to ${WEBROOT}/.well-known/acme-challenge
       Fix it with: sudo chown -R ${REAL_OWNER} ${WEBROOT}"
  fi
  rm -f "$probe"
}

setup_validation() {
  # 'auto': DNS API if credentials are present, otherwise the no-credentials webroot path
  if [[ "$VALIDATION" == "auto" ]]; then
    if [[ -n "${CF_Token:-}" || ( -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ) ]]; then
      VALIDATION="dns-api"
    else
      VALIDATION="webroot"
    fi
    log "VALIDATION=auto -> using '${VALIDATION}'."
  fi

  case "$VALIDATION" in
    dns-api)
      case "$DNS_API" in
        dns_cf)  CRED_ENV=(-e CF_Token -e CF_Account_ID) ;;
        dns_aws) CRED_ENV=(-e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY) ;;
      esac
      ISSUE_ARGS=(--dns "$DNS_API")
      ;;
    dns-manual)
      ISSUE_ARGS=(--dns --yes-I-know-dns-manual-mode-enough-go-ahead-please)
      ;;
    webroot)
      [[ -n "$WEBROOT" ]] || WEBROOT="$(dirname "$SELF")/../website/acme-challenge"
      # Docker creates a missing bind-mount source as root, and an earlier 'sudo' run
      # leaves it root-owned, so take ownership back instead of failing.
      mkdir -p "${WEBROOT}/.well-known/acme-challenge" 2>/dev/null \
        || sudo mkdir -p "${WEBROOT}/.well-known/acme-challenge" \
        || die "cannot create ${WEBROOT} - check the permissions on that directory."
      WEBROOT="$(cd "$WEBROOT" && pwd)"        # docker needs a clean absolute path
      ensure_webroot_writable
      chmod -R 755 "$WEBROOT" 2>/dev/null || true   # nginx must be able to read the challenge file
      ISSUE_ARGS=(--webroot /webroot)
      RUN_OPTS=(-v "${WEBROOT}:/webroot")
      ;;
    *)
      die "VALIDATION must be dns-api, dns-manual or webroot (got '$VALIDATION')."
      ;;
  esac
}

# Credentials are only needed to CREATE a DNS record, i.e. dns-api mode.
check_creds() {
  [[ "$VALIDATION" == "dns-api" ]] || return 0
  case "$DNS_API" in
    dns_cf)
      [[ -n "${CF_Token:-}" ]] \
        || die "CF_Token is empty - set your Cloudflare API token in the config block, or switch VALIDATION to webroot/dns-manual."
      ;;
    dns_aws)
      [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]] \
        || die "AWS credentials are empty - set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY."
      ;;
    *)
      log "Note: cannot pre-validate credentials for '$DNS_API' - relying on acme.sh to report errors."
      ;;
  esac
}

check_docker() {
  command -v "${DOCKER%% *}" >/dev/null || die "docker not found - install Docker, or set DOCKER=\"sudo docker\"."
  $DOCKER info >/dev/null 2>&1 \
    || die "cannot talk to the Docker daemon - is it running, and is your user in the docker group? (or set DOCKER=\"sudo docker\")"
}

# --- Insert TEXT right after the first line containing PATTERN -----------------
# awk rather than 'sed -i', whose in-place and 'r' syntax differ between GNU and BSD.
# The text goes through the environment, not -v: awk rejects newlines in a -v value.
insert_after() {
  local file="$1" pattern="$2" tmp="$1.waf-cert-tmp"
  WAF_INS="$3" awk -v pat="$pattern" '
    { print }
    !done && index($0, pat) { print ENVIRON["WAF_INS"]; done = 1 }
  ' "$file" > "$tmp" && mv "$tmp" "$file"
  # under sudo the rewritten file would end up root-owned inside the git checkout
  chown "$REAL_OWNER" "$file" 2>/dev/null || true
}

# --- Serve a token from WEBROOT and fetch it straight from the origin ----------
# 127.0.0.1 deliberately: this proves the ORIGIN serves the challenge, with no DNS,
# NAT or WAF in the way. A 404 here means Let's Encrypt would get a 404 too.
verify_origin_local() {
  local dir="${WEBROOT}/.well-known/acme-challenge"
  mkdir -p "$dir"
  ( printf 'ok' > "${dir}/waf-cert-selftest" ) 2>/dev/null || return 1
  chmod 644 "${dir}/waf-cert-selftest" 2>/dev/null || true
  local got=""
  got="$(http_get "http://127.0.0.1/.well-known/acme-challenge/waf-cert-selftest" 2>/dev/null || true)"
  rm -f "${dir}/waf-cert-selftest"
  [[ "$got" == "ok" ]]
}

# --- webroot mode: make the origin nginx actually serve /.well-known/ ----------
ensure_origin() {
  [[ "$VALIDATION" == "webroot" ]] || return 0
  local site_dir="$(dirname "$SELF")/../website"
  [[ -f "${site_dir}/docker-compose.yml" ]] || return 0
  site_dir="$(cd "$site_dir" && pwd)"

  local compose
  if $DOCKER compose version >/dev/null 2>&1; then compose="$DOCKER compose"
  elif command -v docker-compose >/dev/null 2>&1;  then compose="docker-compose"
  else log "WARNING: docker compose not found - start the origin site yourself (website/setup.sh up)."; return 0; fi

  # The vhost must have the challenge location, and the dir must be mounted in.
  # Both are added if missing so an older checkout repairs itself.
  local conf="${site_dir}/nginx/default.conf"
  local yml="${site_dir}/docker-compose.yml"
  if [[ -f "$conf" ]] && ! grep -q 'acme-challenge' "$conf"; then
    log "Adding the ACME challenge location to nginx/default.conf..."
    insert_after "$conf" 'server_name' '
    # ACME HTTP-01 challenge for Lets Encrypt (added by ../script/waf_cert.sh).
    # ^~ so it beats the SPA locations and is never rewritten to index.html.
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type "text/plain";
    }'
  fi
  if ! grep -q 'acme-challenge:/var/www/acme' "$yml"; then
    log "Adding the challenge mount to docker-compose.yml..."
    insert_after "$yml" '/etc/nginx/conf.d/default.conf' \
      '      - ./acme-challenge:/var/www/acme:ro'
  fi

  log "Making sure the origin site serves the challenge path..."
  ( cd "$site_dir" && $compose up -d ) \
    || log "WARNING: could not start the origin site - run website/setup.sh up yourself."

  if verify_origin_local; then
    log "Origin self-test OK - nginx serves /.well-known/acme-challenge/."
    return 0
  fi

  # 'up -d' leaves a running container alone, so an edited nginx conf is still
  # the OLD config in memory. Force the web container to be rebuilt from scratch.
  log "Origin did not serve the challenge yet - recreating the web container..."
  ( cd "$site_dir" && $compose up -d --force-recreate web ) || true

  if verify_origin_local; then
    log "Origin self-test OK - nginx serves /.well-known/acme-challenge/."
    return 0
  fi

  die "the origin still returns 404 for http://127.0.0.1/.well-known/acme-challenge/.
       Let's Encrypt would get the same 404, so issuance was not attempted.
       Check:  ${conf}      (needs a 'location ^~ /.well-known/acme-challenge/' block)
               ${yml}       (web service needs '- ./acme-challenge:/var/www/acme:ro')
       Then:   cd ${site_dir} && ${compose} up -d --force-recreate web"
}

# --- Fetch a URL using the host's curl, or the container's if the host has none ---
http_get() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 15 "$1"
  else
    $DOCKER run --rm --entrypoint curl "$IMAGE" -fsS --max-time 15 "$1"
  fi
}

# --- Catch the usual causes of failure BEFORE burning a Let's Encrypt attempt ---
# Never fatal: a server behind NAT may fail to reach its own public name even
# though Let's Encrypt can, so this diagnoses rather than blocks.
preflight() {
  local domain="$1"

  getent hosts "$domain" >/dev/null 2>&1 \
    || log "[${domain}] WARNING: this name does not resolve from here yet - if DNS is not set up, issuance will fail."

  [[ "$VALIDATION" == "webroot" ]] || return 0

  # The origin itself was already proven by ensure_origin's 127.0.0.1 self-test, so a
  # failure here is about the path from the internet, not about nginx. Many servers
  # cannot reach their own public IP (no NAT hairpin), so this can only ever warn.
  local token="waf-cert-preflight" dir="${WEBROOT}/.well-known/acme-challenge"
  mkdir -p "$dir"
  ( printf 'ok' > "${dir}/${token}" ) 2>/dev/null || return 0
  chmod 644 "${dir}/${token}" 2>/dev/null || true
  local got=""
  got="$(http_get "http://${domain}/.well-known/acme-challenge/${token}" 2>/dev/null || true)"
  rm -f "${dir}/${token}"

  if [[ "$got" == "ok" ]]; then
    log "[${domain}] Pre-flight OK - the challenge is reachable over the public name too."
  else
    log "[${domain}] Note: could not fetch the challenge via http://${domain}/ from this server."
    log "[${domain}] That is normal when the server cannot reach its own public IP (no NAT"
    log "[${domain}] hairpin). The origin self-test passed, so Let's Encrypt is likely fine."
  fi
}

# --- Run acme.sh in a throw-away container (state comes from the volume) --------
acme() {
  mkdir -p "$OUT_BASE"; chmod 700 "$OUT_BASE" 2>/dev/null || true
  $DOCKER run --rm "${RUN_OPTS[@]}" \
    -v "${VOLUME}:/acme.sh" \
    -v "${OUT_BASE}:/out" \
    "${CRED_ENV[@]}" \
    "$IMAGE" "$@"
}

# --- Install: no packages, no host cron - just an image, a volume and a container ---
cmd_install() {
  check_docker

  log "Pulling ${IMAGE}..."
  $DOCKER pull "$IMAGE"

  $DOCKER volume inspect "$VOLUME" >/dev/null 2>&1 || $DOCKER volume create "$VOLUME" >/dev/null
  mkdir -p "$OUT_BASE"; chmod 700 "$OUT_BASE"

  # The image ships busybox crond; 'daemon' runs acme.sh's daily renewal check inside
  # the container, so the host needs no cron package at all. No credentials are passed
  # here on purpose - acme.sh stores them in the volume during 'issue' and reuses them.
  # The daemon needs the same extras as an issue run (e.g. the webroot mount) to renew
  setup_validation

  $DOCKER rm -f "$CONTAINER" >/dev/null 2>&1 || true
  $DOCKER run -d --name "$CONTAINER" --restart unless-stopped "${RUN_OPTS[@]}" \
    -v "${VOLUME}:/acme.sh" \
    -v "${OUT_BASE}:/out" \
    "$IMAGE" daemon >/dev/null

  ensure_origin

  log "Done. State lives in volume '${VOLUME}', renewals run in container '${CONTAINER}'."
  if [[ "$VALIDATION" == "dns-manual" ]]; then
    log "VALIDATION=dns-manual: renewals are NOT automatic, you re-run issue/continue by hand."
  fi
  log "Next: $0 issue"
}

# --- One command that does the whole job ---------------------------------
cmd_setup() {
  cmd_install
  run_all cmd_issue
  run_all cmd_show
}

# --- Issue the certificate for one domain --------------------------------
cmd_issue() {
  local domain="$1"
  check_domain "$domain"
  check_docker
  setup_validation
  check_creds

  local args=(-d "$domain")
  # Append any extra SANs configured for this domain
  local extra="${EXTRA_SANS[$domain]:-}"
  for d in $extra; do [[ -n "$d" ]] && args+=(-d "$d"); done

  log "Requesting certificate for: ${domain} ${extra} (validation: ${VALIDATION})"

  if [[ "$VALIDATION" == "dns-manual" ]]; then
    # Manual mode is a two-step dance: this run only PRINTS the TXT record to add.
    acme --issue "${ISSUE_ARGS[@]}" "${args[@]}" --keylength "$KEY_LENGTH" --server letsencrypt -m "$EMAIL" || true
    log "[${domain}] Add the TXT record(s) printed above in your DNS panel, wait a few"
    log "[${domain}] minutes for them to propagate, then run: $0 continue ${domain}"
    return 0
  fi

  ensure_origin
  preflight "$domain"

  # acme.sh exits 2 ("skipped, cert is still valid") when re-run on a good cert, so
  # treat that as success and just re-export - that makes 'issue' safe to re-run.
  local rc=0
  acme --issue "${ISSUE_ARGS[@]}" "${args[@]}" --keylength "$KEY_LENGTH" --server letsencrypt -m "$EMAIL" || rc=$?
  case "$rc" in
    0) ;;
    2) log "[${domain}] Certificate is still valid - skipping issuance, re-exporting the existing one." ;;
    *) die "[${domain}] acme.sh failed (exit ${rc}). Nothing was exported - see the output above." ;;
  esac

  cmd_export "$domain"   # export the files AND arm the after-renewal hook
}

# --- Second half of the manual-DNS flow, after the TXT record exists -----
cmd_continue() {
  local domain="$1"
  check_domain "$domain"
  check_docker
  setup_validation
  [[ "$VALIDATION" == "dns-manual" ]] || die "'continue' only applies to VALIDATION=dns-manual."

  acme --renew -d "$domain" "${ECC[@]}" --yes-I-know-dns-manual-mode-enough-go-ahead-please
  cmd_export "$domain"
  log "[${domain}] NOTE: manual DNS cannot auto-renew - repeat 'issue' + 'continue' before day 90."
}

# --- Export the files for the WAF + arm the renewal hook -----------------
cmd_export() {
  local domain="$1"
  check_domain "$domain"
  local out_dir="${OUT_BASE}/${domain}"
  mkdir -p "$out_dir"; chmod 700 "$out_dir"
  write_p12_helper

  # --install-cert copies the PEMs into out_dir (bind-mounted as /out) and stores the
  # reloadcmd in the volume, so every future renewal re-exports ONLY this domain's files
  # and rebuilds its .p12 - no host cron and no host openssl involved.
  acme --install-cert -d "$domain" "${ECC[@]}" \
    --key-file       "/out/${domain}/privkey.pem" \
    --fullchain-file "/out/${domain}/fullchain.pem" \
    --cert-file      "/out/${domain}/cert.pem" \
    --ca-file        "/out/${domain}/chain.pem" \
    --reloadcmd      "sh /out/waf-p12.sh ${domain}"

  log "[${domain}] Files ready in ${out_dir}:"
  log "  privkey.pem      -> Private Key"
  log "  fullchain.pem    -> Certificate (leaf + intermediate)"
  log "  chain.pem        -> CA Bundle (if the WAF asks for it separately)"
  log "  ${domain}.p12    -> for WAFs that only accept PKCS#12"

  # If the WAF exposes an API, upload the new cert right away.
  # NOTE: this runs on the HOST, so it fires on issue/export only - the in-container
  # auto-renewal cannot call it. Re-run "$0 export ${domain}" after a renewal to push.
  if [[ -n "$PUSH_SCRIPT" && -x "$PUSH_SCRIPT" ]]; then
    log "[${domain}] Pushing cert to the WAF via ${PUSH_SCRIPT}..."
    "$PUSH_SCRIPT" "$domain" "${out_dir}/fullchain.pem" "${out_dir}/privkey.pem" \
      && log "[${domain}] Push succeeded." \
      || log "[${domain}] WARNING: push to the WAF FAILED - upload manually!"
  else
    log "[${domain}] PUSH_SCRIPT not configured -> upload to the WAF manually."
  fi
}

# --- Helper invoked INSIDE the container after every renewal -------------
# Lives in OUT_BASE (visible to the container as /out) because that is the only
# host path the container can see; it uses the container's openssl.
write_p12_helper() {
  local helper="${OUT_BASE}/waf-p12.sh"
  cat > "$helper" <<EOF
#!/bin/sh
# Generated by waf_cert.sh - do not edit. Runs inside the acme.sh container. \$1 = domain.
# OpenSSL 3.x defaults to algorithms some appliances reject, so retry with -legacy.
d="\$1"; dir="/out/\$d"
openssl pkcs12 -export -in "\$dir/fullchain.pem" -inkey "\$dir/privkey.pem" \\
  -out "\$dir/\$d.p12" -name "\$d" -passout "pass:${P12_PASS}" 2>/dev/null ||
openssl pkcs12 -export -legacy -in "\$dir/fullchain.pem" -inkey "\$dir/privkey.pem" \\
  -out "\$dir/\$d.p12" -name "\$d" -passout "pass:${P12_PASS}"
chmod 600 "\$dir"/*.pem "\$dir/\$d.p12"
chown ${HOST_OWNER} "\$dir"/* 2>/dev/null || true
EOF
  chmod 700 "$helper"
}

# --- Print to stdout for copy-pasting into the WAF UI --------------------
cmd_show() {
  local domain="$1"
  check_domain "$domain"
  check_docker
  local out_dir="${OUT_BASE}/${domain}"
  [[ -s "${out_dir}/fullchain.pem" ]] \
    || die "no certificate for ${domain} in ${out_dir} yet - run: $0 issue ${domain}"
  echo "########## ${domain} ##########"
  echo "===== PRIVATE KEY (${out_dir}/privkey.pem) ====="
  read_file "${out_dir}/privkey.pem"
  echo
  echo "===== CERTIFICATE + CHAIN (${out_dir}/fullchain.pem) ====="
  read_file "${out_dir}/fullchain.pem"
  echo
  echo "===== VALIDITY ====="
  # openssl comes from the container - the host does not need it installed
  $DOCKER run --rm -v "${OUT_BASE}:/out" --entrypoint openssl "$IMAGE" \
    x509 -in "/out/${domain}/cert.pem" -noout -subject -dates
  echo
}

# Renewals write as root inside the container; fall back to sudo if we cannot read.
read_file() { if [[ -r "$1" ]]; then cat "$1"; else sudo cat "$1"; fi; }

cmd_renew() {
  local domain="$1"
  check_domain "$domain"
  check_docker
  setup_validation   # webroot mode needs its mount again; dns-api needs the creds
  check_creds
  acme --renew -d "$domain" "${ECC[@]}" --force
}

cmd_status() {
  check_docker
  echo "===== RENEW CONTAINER ====="
  $DOCKER ps -a --filter "name=^/${CONTAINER}$" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
  echo
  echo "===== CERTIFICATES KNOWN TO ACME.SH ====="
  acme --list
}

cmd_uninstall() {
  check_docker
  log "This deletes the Let's Encrypt account key and all renewal state in volume '${VOLUME}'."
  $DOCKER rm -f "$CONTAINER" >/dev/null 2>&1 || true
  $DOCKER volume rm "$VOLUME" >/dev/null 2>&1 || true
  $DOCKER rmi "$IMAGE" >/dev/null 2>&1 || true
  log "Removed container, volume and image. Exported certs in ${OUT_BASE} were left in place."
  log "To wipe those too: rm -rf ${OUT_BASE}"
}

# --- Run a per-domain command over all DOMAINS, or a single given one ----
run_all() {
  local fn="$1"
  [[ ${#DOMAINS[@]} -gt 0 ]] || die "DOMAINS is empty - add at least one HTTPS domain to the config block."
  for d in "${DOMAINS[@]}"; do "$fn" "$d"; done
}

usage() { sed -n '3,24p' "$SELF" | sed 's/^# \?//'; exit "${1:-0}"; }

# NOTE: 'cmd || run_all' would put the function in a tested context, which switches
# OFF 'set -e' inside it - a failing acme.sh would then fall through to the export
# step and report success for a cert that was never issued. Hence if/else.
one_or_all() {
  local fn="$1" arg="${2:-}"
  if [[ -n "$arg" ]]; then "$fn" "$arg"; else run_all "$fn"; fi
}

case "${1:-}" in
  setup)       cmd_setup ;;
  install)     cmd_install ;;
  issue)       one_or_all cmd_issue  "${2:-}" ;;
  continue)    cmd_continue "${2:?continue needs a domain}" ;;
  renew)       one_or_all cmd_renew  "${2:-}" ;;
  export)      one_or_all cmd_export "${2:-}" ;;
  show)        one_or_all cmd_show   "${2:-}" ;;
  list)        printf '%s\n' "${DOMAINS[@]}" ;;
  status)      cmd_status ;;
  uninstall)   cmd_uninstall ;;
  --)          shift; acme "$@" ;;   # escape hatch: pass any acme.sh args straight through
  -h|--help)   usage 0 ;;
  *)           usage 1 ;;
esac
