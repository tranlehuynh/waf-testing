#!/bin/bash
#
# waf_cert.sh - Issue / renew Let's Encrypt certs via DNS-01 and export them for a WAF
#
#   ./waf_cert.sh install                 Install acme.sh + the auto-renew cron job
#   ./waf_cert.sh issue  [domain]         Issue cert(s) for the first time (all, or one)
#   ./waf_cert.sh show   [domain]         Print private key + fullchain (paste into WAF UI)
#   ./waf_cert.sh renew  [domain]         Force a renewal now (normally the cron handles this)
#   ./waf_cert.sh list                    List configured HTTPS domains
#   ./waf_cert.sh deploy-hook <domain>    Runs automatically after each renewal - do not call by hand
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
                                     # see: acme.sh --dnshelp

# DNS provider credentials (fill in only the lines matching DNS_API above)
export CF_Token=""                   # Cloudflare API token (Zone:DNS:Edit)
export CF_Account_ID=""
# export AWS_ACCESS_KEY_ID=""
# export AWS_SECRET_ACCESS_KEY=""

OUT_BASE="/etc/waf-certs"            # per-domain files live in ${OUT_BASE}/<domain>
P12_PASS=""                          # password for the .p12 file, empty = no password
PUSH_SCRIPT=""                       # (optional) script that uploads the cert via WAF API
# =======================================================

ACME="${HOME}/.acme.sh/acme.sh"
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"

log() { echo "[$(date '+%F %T')] $*"; }
die() { echo "[$(date '+%F %T')] ERROR: $*" >&2; exit 1; }

# --- Detect the OS package manager (apt / dnf / yum) ---------------------
pkg_install() {
  # Install packages using whichever manager is available.
  if command -v apt-get >/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null; then
    sudo dnf install -y "$@"
  elif command -v yum >/dev/null; then
    sudo yum install -y "$@"
  else
    die "No supported package manager found (need apt-get, dnf, or yum)."
  fi
}

# --- Fail early if the DNS provider credentials are not set --------------
check_dns_creds() {
  case "$DNS_API" in
    dns_cf)
      [[ -n "${CF_Token:-}" ]] || die "CF_Token is empty - set your Cloudflare API token in the config block."
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

# --- Install acme.sh -----------------------------------------------------
cmd_install() {
  command -v curl    >/dev/null || pkg_install curl
  command -v openssl >/dev/null || pkg_install openssl
  command -v socat   >/dev/null || pkg_install socat || true

  if [[ ! -x "$ACME" ]]; then
    log "Installing acme.sh..."
    curl -fsS https://get.acme.sh | sh -s email="$EMAIL"
  else
    log "acme.sh is already installed."
  fi

  # acme.sh installs its own daily cron and renews when under 30 days remain
  "$ACME" --upgrade --auto-upgrade
  log "Done. Auto-renew cron installed (check with: crontab -l)."
}

# --- Issue the certificate for one domain --------------------------------
cmd_issue() {
  local domain="$1"
  [[ -x "$ACME" ]] || die "acme.sh not installed yet, run: $0 install"
  check_dns_creds

  local args=(-d "$domain")
  # Append any extra SANs configured for this domain
  local extra="${EXTRA_SANS[$domain]:-}"
  for d in $extra; do [[ -n "$d" ]] && args+=(-d "$d"); done

  log "Requesting certificate for: ${domain} ${extra}"
  "$ACME" --issue --dns "$DNS_API" "${args[@]}" --server letsencrypt

  cmd_register_hook "$domain"   # wire up the hook AND export the files for the first time
}

# --- Register the deploy hook with acme.sh (per domain) ------------------
cmd_register_hook() {
  local domain="$1"
  local out_dir="${OUT_BASE}/${domain}"
  mkdir -p "$out_dir"; chmod 700 "$out_dir"

  # --install-cert copies the PEMs into out_dir and registers the reloadcmd,
  # so each domain's renewal re-exports ONLY its own files.
  "$ACME" --install-cert -d "$domain" \
    --key-file       "${out_dir}/privkey.pem" \
    --fullchain-file "${out_dir}/fullchain.pem" \
    --cert-file      "${out_dir}/cert.pem" \
    --ca-file        "${out_dir}/chain.pem" \
    --reloadcmd      "${SELF} deploy-hook ${domain}"
  log "[${domain}] Hook registered: every renewal re-exports the files and pushes to the WAF."
}

# --- Export the files for the WAF (runs automatically after renewal) -----
cmd_deploy_hook() {
  local domain="$1"
  local out_dir="${OUT_BASE}/${domain}"
  mkdir -p "$out_dir"; chmod 700 "$out_dir"

  # acme.sh writes the PEMs into out_dir via --install-cert; on the first run
  # (before the hook exists) copy them straight from acme.sh's live directory.
  local live="${HOME}/.acme.sh/${domain}_ecc"
  [[ -d "$live" ]] || live="${HOME}/.acme.sh/${domain}"
  if [[ ! -s "${out_dir}/fullchain.pem" && -d "$live" ]]; then
    cp "${live}/fullchain.cer"  "${out_dir}/fullchain.pem"
    cp "${live}/${domain}.key"  "${out_dir}/privkey.pem"
    cp "${live}/${domain}.cer"  "${out_dir}/cert.pem"
    cp "${live}/ca.cer"         "${out_dir}/chain.pem"
  fi

  # Guard: the openssl step below fails cryptically if these are missing.
  [[ -s "${out_dir}/fullchain.pem" ]] || die "[${domain}] fullchain.pem missing/empty in ${out_dir} - did --issue succeed?"
  [[ -s "${out_dir}/privkey.pem"   ]] || die "[${domain}] privkey.pem missing/empty in ${out_dir} - did --issue succeed?"

  chmod 600 "${out_dir}"/*.pem

  # Build a PKCS#12 bundle for WAFs like F5 / Imperva / Barracuda.
  # OpenSSL 3.x defaults to algorithms some appliances reject; retry with -legacy.
  local p12="${out_dir}/${domain}.p12"
  if ! openssl pkcs12 -export \
        -in "${out_dir}/fullchain.pem" \
        -inkey "${out_dir}/privkey.pem" \
        -out "$p12" -name "$domain" -passout "pass:${P12_PASS}" 2>/dev/null; then
    log "[${domain}] PKCS#12 export failed with defaults, retrying with -legacy..."
    openssl pkcs12 -export -legacy \
      -in "${out_dir}/fullchain.pem" \
      -inkey "${out_dir}/privkey.pem" \
      -out "$p12" -name "$domain" -passout "pass:${P12_PASS}"
  fi
  chmod 600 "$p12"

  log "[${domain}] Files ready in ${out_dir}:"
  log "  privkey.pem      -> Private Key"
  log "  fullchain.pem    -> Certificate (leaf + intermediate)"
  log "  chain.pem        -> CA Bundle (if the WAF asks for it separately)"
  log "  ${domain}.p12    -> for WAFs that only accept PKCS#12"

  # If the WAF exposes an API, upload the new cert right away
  if [[ -n "$PUSH_SCRIPT" && -x "$PUSH_SCRIPT" ]]; then
    log "[${domain}] Pushing cert to the WAF via ${PUSH_SCRIPT}..."
    "$PUSH_SCRIPT" "$domain" "${out_dir}/fullchain.pem" "${out_dir}/privkey.pem" \
      && log "[${domain}] Push succeeded." \
      || log "[${domain}] WARNING: push to the WAF FAILED - upload manually!"
  else
    log "[${domain}] PUSH_SCRIPT not configured -> upload to the WAF manually."
  fi
}

# --- Print to stdout for copy-pasting into the WAF UI --------------------
cmd_show() {
  local domain="$1"
  local out_dir="${OUT_BASE}/${domain}"
  echo "########## ${domain} ##########"
  echo "===== PRIVATE KEY (${out_dir}/privkey.pem) ====="
  cat "${out_dir}/privkey.pem"
  echo
  echo "===== CERTIFICATE + CHAIN (${out_dir}/fullchain.pem) ====="
  cat "${out_dir}/fullchain.pem"
  echo
  echo "===== VALIDITY ====="
  openssl x509 -in "${out_dir}/cert.pem" -noout -subject -dates
  echo
}

cmd_renew() {
  local domain="$1"
  "$ACME" --renew -d "$domain" --force
}

# --- Run a per-domain command over all DOMAINS, or a single given one ----
run_all() {
  local fn="$1"
  [[ ${#DOMAINS[@]} -gt 0 ]] || die "DOMAINS is empty - add at least one HTTPS domain to the config block."
  for d in "${DOMAINS[@]}"; do "$fn" "$d"; done
}

usage() { sed -n '2,16p' "$SELF" | sed 's/^# \?//'; exit "${1:-0}"; }

case "${1:-}" in
  install)     cmd_install ;;
  issue)       [[ -n "${2:-}" ]] && cmd_issue "$2"  || run_all cmd_issue ;;
  renew)       [[ -n "${2:-}" ]] && cmd_renew "$2"  || run_all cmd_renew ;;
  show)        [[ -n "${2:-}" ]] && cmd_show "$2"   || run_all cmd_show ;;
  list)        printf '%s\n' "${DOMAINS[@]}" ;;
  deploy-hook) cmd_deploy_hook "${2:?deploy-hook needs a domain}" ;;
  -h|--help)   usage 0 ;;
  *)           usage 1 ;;
esac
