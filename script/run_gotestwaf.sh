#!/bin/bash
#
# run-gotestwaf.sh - Run a Wallarm GoTestWAF scan against a target (Ubuntu)
#
set -euo pipefail

IMAGE="wallarm/gotestwaf"
TARGET_URL=""
WAF_NAME="unknown-waf"
BLOCK_CODES="403"
PASS_CODES="200,404"
WORKERS="5"
IDLE_CONNS="5"
STRICT=0
CONN_RESET_BLOCKED=0
DO_PRECHECK=1
DO_PULL=1
DRY_RUN=0

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; NC=$'\033[0m'
info() { echo "${GRN}[+]${NC} $*"; }
warn() { echo "${YEL}[!]${NC} $*"; }
err()  { echo "${RED}[x]${NC} $*" >&2; }
hr()   { printf '%.0s=' {1..64}; echo; }

usage() {
cat <<'EOF'
run-gotestwaf.sh - Run a Wallarm GoTestWAF scan against a target

Usage:
  ./run-gotestwaf.sh http://example.com
  ./run-gotestwaf.sh --url http://example.com --waf-name "my-waf" --block-codes 403,468

Options:
  --url URL              Target URL. Include the scheme (http:// or https://).
                         Without one, the script probes http then https.
  --waf-name NAME        Label shown in the report            (default: unknown-waf)
  --block-codes LIST     Status codes that mean "blocked"     (default: 403)
  --pass-codes LIST      Status codes that mean "not blocked" (default: 200,404)
  --workers N            Parallel workers                     (default: 5)
  --idle-conns N         Max idle connections                 (default: 5)
  --strict               Count anything that is neither a pass nor a block code
                         as BLOCKED (GoTestWAF's own default). Omitting this
                         passes --nonBlockedAsPassed instead.
  --conn-reset-blocked   Treat a dropped connection as BLOCKED. OFF by default:
                         resets are usually a body-size or timeout limit, not a
                         WAF rule, and enabling this inflates the score.
  --skip-precheck        Skip the benign-request sanity check
  --no-pull              Do not pull a fresh image
  --dry-run              Print the docker command and exit
  -h, --help             Show this help
EOF
exit "${1:-0}"
}

# ---------- 1. Parse arguments -------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)                 TARGET_URL="${2:-}";  shift 2 ;;
    --waf-name)            WAF_NAME="${2:-}";    shift 2 ;;
    --block-codes)         BLOCK_CODES="${2:-}"; shift 2 ;;
    --pass-codes)          PASS_CODES="${2:-}";  shift 2 ;;
    --workers)             WORKERS="${2:-}";     shift 2 ;;
    --idle-conns)          IDLE_CONNS="${2:-}";  shift 2 ;;
    --strict)              STRICT=1; shift ;;
    --conn-reset-blocked)  CONN_RESET_BLOCKED=1; shift ;;
    --skip-precheck)       DO_PRECHECK=0; shift ;;
    --no-pull)             DO_PULL=0; shift ;;
    --dry-run)             DRY_RUN=1; shift ;;
    -h|--help)             usage 0 ;;
    -*)                    err "Unknown option: $1"; usage 1 ;;
    *)                     TARGET_URL="$1"; shift ;;
  esac
done

if [[ -z "$TARGET_URL" ]]; then
  read -rp "Enter the target URL (e.g. http://superman.chubbyduck.org): " TARGET_URL
fi
[[ -n "$TARGET_URL" ]] || { err "Target URL cannot be empty."; exit 1; }

command -v curl &>/dev/null || { err "curl is required."; exit 1; }

# Probe rather than assume a scheme: guessing https on an http-only app
# silently tests a different listener (or nothing at all).
if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
  warn "No scheme given - probing http:// then https:// for ${TARGET_URL}"
  for scheme in http https; do
    if curl -sk -o /dev/null --max-time 8 "${scheme}://${TARGET_URL}" 2>/dev/null; then
      TARGET_URL="${scheme}://${TARGET_URL}"
      info "Reachable over ${scheme} - using ${TARGET_URL}"
      # Falling back to http when https refused the connection is exactly what an
      # origin behind a TLS-terminating WAF looks like from the inside.
      if [[ "$scheme" == "http" ]]; then
        warn "https did not answer, so this scan will run over plain HTTP."
        warn "If the WAF terminates TLS, plain HTTP usually reaches the ORIGIN, not the WAF."
      fi
      break
    fi
  done
  [[ "$TARGET_URL" =~ ^https?:// ]] || { err "Neither http nor https answered. Pass --url with an explicit scheme."; exit 1; }
fi
TARGET_URL="${TARGET_URL%/}"

# ---------- 1b. Make the address being scanned explicit -------------------
# A target that resolves to this machine means the traffic never traverses the
# WAF - it lands on the permissive origin nginx and scores a meaningless ~0%.
check_target_address() {
  local host="${TARGET_URL#*://}"
  host="${host%%/*}"          # drop any path
  host="${host%%:*}"          # drop any :port

  local addrs
  addrs="$(getent hosts "$host" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
  addrs="${addrs%% }"
  if [[ -z "$addrs" ]]; then
    err "${host} does not resolve from this machine - GoTestWAF cannot reach it."
    exit 1
  fi
  info "Target resolves to: ${addrs}"

  local local_addrs="127.0.0.1 ::1"
  if command -v ip &>/dev/null; then
    local_addrs+=" $(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
  fi

  local a b
  for a in $addrs; do
    for b in $local_addrs; do
      [[ "$a" == "$b" ]] || continue
      echo
      warn "${host} resolves to ${a}, which is an address of THIS machine."
      warn "The scan would hit the origin nginx directly and never traverse the WAF,"
      warn "so the score would describe the origin - which is deliberately permissive -"
      warn "and not your WAF. Point the scan at the WAF, or fix DNS on this host."
      echo
      read -rp "Continue anyway? [y/N] " ans
      [[ "${ans:-N}" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
      return 0
    done
  done
}
check_target_address

# ---------- 2. Install Docker if missing (Ubuntu) ------------------------
hr; info "[1/6] Checking the Docker environment"; hr

install_docker() {
  info "Docker not found - installing Docker CE from the official repo"
  sudo apt-get update -qq
  sudo apt-get install -y -qq ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo systemctl enable --now docker
  sudo usermod -aG docker "${SUDO_USER:-$USER}" || true
  warn "Added ${SUDO_USER:-$USER} to the 'docker' group - log out and back in for it to apply."
}

command -v docker &>/dev/null || install_docker
info "Docker: $(docker --version 2>/dev/null || echo 'version unavailable')"

DOCKER="docker"
if ! docker info &>/dev/null; then
  if sudo -n true 2>/dev/null || sudo docker info &>/dev/null; then
    DOCKER="sudo docker"
    warn "Using 'sudo docker' (group membership not active in this session)"
  else
    err "Cannot reach the Docker daemon. Is it running? (sudo systemctl start docker)"
    exit 1
  fi
fi

# ---------- 3. Pull the image -------------------------------------------
if [[ "$DO_PULL" -eq 1 ]]; then
  hr; info "[2/6] Pulling the GoTestWAF image"; hr
  $DOCKER pull "$IMAGE" || warn "Pull failed - using the local image if present"
else
  info "[2/6] Skipping pull (--no-pull)"
fi

# ---------- 4. Validate optional flags against this image version --------
hr; info "[3/6] Checking which optional flags this image supports"; hr

HELP_TEXT="$($DOCKER run --rm "$IMAGE" --help 2>&1 || true)"
OPTIONAL_FLAGS=()
add_if_supported() {
  local flag="$1"
  if [[ -z "$HELP_TEXT" ]]; then
    OPTIONAL_FLAGS+=("$flag")            # could not read help; try anyway
  elif grep -q -- "${flag%%=*}" <<<"$HELP_TEXT"; then
    OPTIONAL_FLAGS+=("$flag")
  else
    warn "Image does not support ${flag%%=*} - dropping it"
  fi
}

for f in --followCookies --renewSession --includePayloads --addDebugHeader --noEmailReport; do
  add_if_supported "$f"
done
[[ "$CONN_RESET_BLOCKED" -eq 1 ]] && add_if_supported --blockConnReset
[[ "$STRICT" -eq 0 ]] && add_if_supported --nonBlockedAsPassed

# ---------- 5. Sanity-check the target ----------------------------------
if [[ "$DO_PRECHECK" -eq 1 ]]; then
  hr; info "[4/6] Pre-flight check on benign requests"; hr
  echo "A clean request must NOT return a block code, and ideally should return"
  echo "a pass code - otherwise the false-positive score is meaningless."
  echo
  UNLISTED=0; REDIRECTS=0; FALSE_POS=0
  for path in "/" "/index.html" "/?q=hello%20world" "/?name=Nguyen%20Van%20A" "/no-such-path-9f3a2b"; do
    # No -L: a redirect must stay visible instead of being followed away.
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${TARGET_URL}${path}" || echo "ERR")
    printf '    %-30s -> %s' "$path" "$code"
    if [[ ",${BLOCK_CODES}," == *",${code},"* ]]; then
      echo "  ${RED}<- counted as BLOCKED (false positive)${NC}"; FALSE_POS=1
    elif [[ ",${PASS_CODES}," == *",${code},"* ]]; then
      echo "  ${GRN}<- pass${NC}"
    elif [[ "$code" =~ ^3[0-9][0-9]$ ]]; then
      echo "  ${YEL}<- redirect${NC}"; REDIRECTS=1; UNLISTED=1
    else
      echo "  ${YEL}<- not in either list${NC}"; UNLISTED=1
    fi
  done
  echo
  echo "Block codes: ${BLOCK_CODES}   |   Pass codes: ${PASS_CODES}"
  echo

  # Large bodies are the usual cause of "unexpected EOF" during a scan.
  info "Probing the request body limit (~70 KB POST)"
  BIG=$(head -c 70000 /dev/zero | tr '\0' 'A')
  big_code=$(printf '%s' "$BIG" \
    | curl -sk -o /dev/null -w '%{http_code}' --max-time 15 \
        -X POST -H 'Content-Type: text/plain' --data-binary @- "${TARGET_URL}/" \
    || echo "ERR")
  if [[ "$big_code" == "ERR" || -z "$big_code" || "$big_code" == "000" ]]; then
    warn "Large POST dropped the connection. The 8kb-128kb test cases will fail"
    warn "the same way. Raise client_max_body_size / SecRequestBodyLimit first."
  elif [[ "$big_code" =~ ^(404|405|501)$ ]]; then
    # A method/path rejection happens BEFORE the body is read, so this proves
    # nothing about the body limit - reporting it as "fine" is a false all-clear.
    warn "Large POST returned ${big_code}: the endpoint rejected the METHOD or PATH, so"
    warn "the body limit was never exercised. The 8kb-128kb cases may still fail with"
    warn "'unexpected EOF'. Re-probe against a path that accepts POST (e.g. /api/)."
  else
    info "Large POST returned ${big_code} - body size looks fine"
  fi
  echo

  if [[ "$REDIRECTS" -eq 1 ]]; then
    warn "The target redirects. Every attack payload will be scored as BYPASSED"
    warn "because a 3xx is neither a block nor a pass code. Scan the final"
    warn "scheme/host directly, or add the code to --pass-codes deliberately."
  fi
  if [[ "$FALSE_POS" -eq 1 ]]; then
    warn "Clean traffic is already being blocked. Fix that before reading any"
    warn "true-positive number - the WAF is rejecting real users right now."
  fi
  if [[ "$UNLISTED" -eq 1 && "$STRICT" -eq 1 ]]; then
    warn "Codes outside both lists with --strict on are scored as BLOCKED."
  fi

  read -rp "Continue with the scan? [Y/n] " ans
  [[ "${ans:-Y}" =~ ^[Yy]?$ ]] || { info "Aborted."; exit 0; }
fi

# ---------- 6. Prepare the report directory ------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="$(pwd)/reports/${STAMP}"
mkdir -p "$REPORT_DIR"
# The image runs as a non-root user, so a dir created by root/sudo is not
# writable inside the container.
chmod 0777 "$REPORT_DIR"

# ---------- 7. Run the scan ---------------------------------------------
hr
info "[5/6] Scanning ${TARGET_URL}"
info "      WAF name: ${WAF_NAME}   Reports: ${REPORT_DIR}"
[[ "$CONN_RESET_BLOCKED" -eq 0 ]] && info "      Connection resets count as FAILED, not blocked"
hr

TTY_FLAG=()
[[ -t 0 && -t 1 ]] && TTY_FLAG=(-it)

DOCKER_ARGS=(
  run --rm "${TTY_FLAG[@]}"
  -v "${REPORT_DIR}":/app/reports:z
  "$IMAGE"
  --url="$TARGET_URL"
  --wafName="$WAF_NAME"
  --blockStatusCodes="$BLOCK_CODES"
  --passStatusCodes="$PASS_CODES"
  --workers="$WORKERS"
  --maxIdleConns="$IDLE_CONNS"
  "${OPTIONAL_FLAGS[@]}"
  --reportFormat=html,json
  --reportPath=/app/reports
)

if [[ "$DRY_RUN" -eq 1 ]]; then
  info "Dry run - command that would execute:"
  printf '    %s' "$DOCKER"; printf ' %q' "${DOCKER_ARGS[@]}"; echo
  exit 0
fi

set +e
$DOCKER "${DOCKER_ARGS[@]}"
SCAN_RC=$?
set -e

# ---------- 8. Wrap up ---------------------------------------------------
OWNER="${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}"
sudo chown -R "$OWNER" "$REPORT_DIR" 2>/dev/null \
  || chown -R "$OWNER" "$REPORT_DIR" 2>/dev/null || true

hr
if [[ "$SCAN_RC" -eq 0 ]]; then
  info "[6/6] Scan finished"
else
  warn "[6/6] GoTestWAF exited with code ${SCAN_RC} - check the output above"
fi

if [[ -n "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]]; then
  info "Reports in ${REPORT_DIR}:"
  find "$REPORT_DIR" -type f -printf '    %-10s %p\n' 2>/dev/null | sort \
    || ls -la "$REPORT_DIR"
else
  err "No report files were produced."
  err "Common causes: an invalid flag, the report dir is not writable by the"
  err "container user, or the scan aborted early. Scroll up for the real error."
fi
hr
exit "$SCAN_RC"