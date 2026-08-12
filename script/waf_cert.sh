#!/bin/bash
#
# waf_cert.sh - Issue / renew Let's Encrypt certs via DNS-01 (acme.sh in Docker) and export them for a WAF
#
#   ./waf_cert.sh install                 Pull the acme.sh image + start the auto-renew container
#   ./waf_cert.sh issue  [domain]         Issue cert(s) for the first time (all, or one)
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
DOMAINS=("b.example.com" "c.example.com")

# Optional extra SANs per domain (wildcards / aliases), keyed by the domain above.
# Leave an entry out for a plain single-name cert.
declare -A EXTRA_SANS=(
  # ["b.example.com"]="*.b.example.com"
  # ["c.example.com"]="www.c.example.com"
)

EMAIL="you@example.com"

DNS_API="dns_cf"                     # shared across all domains (same provider account)
                                     # dns_cf=Cloudflare, dns_aws=Route53,
                                     # dns_gd=GoDaddy, dns_namecheap...
                                     # see: ./waf_cert.sh -- --dnshelp

# DNS provider credentials (fill in only the lines matching DNS_API above)
export CF_Token=""                   # Cloudflare API token (Zone:DNS:Edit)
export CF_Account_ID=""
# export AWS_ACCESS_KEY_ID=""
# export AWS_SECRET_ACCESS_KEY=""

OUT_BASE="${HOME}/waf-certs"         # must be an ABSOLUTE path (it is bind-mounted into the container)
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
HOST_OWNER="$(id -u):$(id -g)"

# acme.sh needs --ecc on every command that touches an ECDSA cert
if [[ "$KEY_LENGTH" == ec-* ]]; then ECC=(--ecc); else ECC=(); fi

log() { echo "[$(date '+%F %T')] $*"; }
die() { echo "[$(date '+%F %T')] ERROR: $*" >&2; exit 1; }

# --- Which -e flags to forward to the container (values stay out of the process list) ---
cred_env() {
  case "$DNS_API" in
    dns_cf)
      [[ -n "${CF_Token:-}" ]] || die "CF_Token is empty - set your Cloudflare API token in the config block."
      CRED_ENV=(-e CF_Token -e CF_Account_ID)
      ;;
    dns_aws)
      [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]] \
        || die "AWS credentials are empty - set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY."
      CRED_ENV=(-e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY)
      ;;
    *)
      log "Note: cannot pre-validate credentials for '$DNS_API' - relying on acme.sh to report errors."
      CRED_ENV=()
      ;;
  esac
}

check_docker() {
  command -v "${DOCKER%% *}" >/dev/null || die "docker not found - install Docker, or set DOCKER=\"sudo docker\"."
  $DOCKER info >/dev/null 2>&1 \
    || die "cannot talk to the Docker daemon - is it running, and is your user in the docker group? (or set DOCKER=\"sudo docker\")"
}

# --- Run acme.sh in a throw-away container (state comes from the volume) --------
acme() {
  cred_env
  mkdir -p "$OUT_BASE"; chmod 700 "$OUT_BASE"
  $DOCKER run --rm \
    -v "${VOLUME}:/acme.sh" \
    -v "${OUT_BASE}:/out" \
    "${CRED_ENV[@]}" \
    "$IMAGE" "$@"
}

# --- Install: no packages, no host cron - just an image, a volume and a container ---
cmd_install() {
  check_docker
  cred_env

  log "Pulling ${IMAGE}..."
  $DOCKER pull "$IMAGE"

  $DOCKER volume inspect "$VOLUME" >/dev/null 2>&1 || $DOCKER volume create "$VOLUME" >/dev/null
  mkdir -p "$OUT_BASE"; chmod 700 "$OUT_BASE"

  # The image ships busybox crond; 'daemon' runs acme.sh's daily renewal check inside
  # the container, so the host needs no cron package at all.
  $DOCKER rm -f "$CONTAINER" >/dev/null 2>&1 || true
  $DOCKER run -d --name "$CONTAINER" --restart unless-stopped \
    -v "${VOLUME}:/acme.sh" \
    -v "${OUT_BASE}:/out" \
    "${CRED_ENV[@]}" \
    "$IMAGE" daemon >/dev/null

  log "Done. State lives in volume '${VOLUME}', renewals run in container '${CONTAINER}'."
  log "Next: $0 issue"
}

# --- Issue the certificate for one domain --------------------------------
cmd_issue() {
  local domain="$1"
  check_docker

  local args=(-d "$domain")
  # Append any extra SANs configured for this domain
  local extra="${EXTRA_SANS[$domain]:-}"
  for d in $extra; do [[ -n "$d" ]] && args+=(-d "$d"); done

  log "Requesting certificate for: ${domain} ${extra}"
  acme --issue --dns "$DNS_API" "${args[@]}" --keylength "$KEY_LENGTH" --server letsencrypt -m "$EMAIL"

  cmd_export "$domain"   # export the files AND arm the after-renewal hook
}

# --- Export the files for the WAF + arm the renewal hook -----------------
cmd_export() {
  local domain="$1"
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
  local out_dir="${OUT_BASE}/${domain}"
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
  check_docker
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

usage() { sed -n '3,22p' "$SELF" | sed 's/^# \?//'; exit "${1:-0}"; }

case "${1:-}" in
  install)     cmd_install ;;
  issue)       [[ -n "${2:-}" ]] && cmd_issue "$2"  || run_all cmd_issue ;;
  renew)       [[ -n "${2:-}" ]] && cmd_renew "$2"  || run_all cmd_renew ;;
  export)      [[ -n "${2:-}" ]] && cmd_export "$2" || run_all cmd_export ;;
  show)        [[ -n "${2:-}" ]] && cmd_show "$2"   || run_all cmd_show ;;
  list)        printf '%s\n' "${DOMAINS[@]}" ;;
  status)      cmd_status ;;
  uninstall)   cmd_uninstall ;;
  --)          shift; acme "$@" ;;   # escape hatch: pass any acme.sh args straight through
  -h|--help)   usage 0 ;;
  *)           usage 1 ;;
esac
