#!/bin/bash
#
# run-gotestwaf.sh - Run a Wallarm GoTestWAF scan against a target (Ubuntu)
#
set -euo pipefail

IMAGE="wallarm/gotestwaf"
TARGET_URL=""
WAF_NAME="unknown-waf"
BLOCK_CODES="403"
# 200 only. The origin website answers 200 for every path and method, so a 404 can now
# only come from the WAF or an intermediary - counting it as "not blocked" would score a
# payload as a bypass when it never reached the application at all.
PASS_CODES="200"
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
  --pass-codes LIST      Status codes that mean "not blocked" (default: 200)
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
  hr; info "[4/6] Pre-flight check on the target"; hr
  echo "Every probe must return a code in --block-codes or --pass-codes. Anything else"
  echo "is 'unresolved', and --nonBlockedAsPassed then silently files it as a bypass"
  echo "(or, for benign input, as a false positive) that the WAF never actually produced."
  echo
  UNLISTED=0; REDIRECTS=0; FALSE_POS=0; UNSCOREABLE=()

  # probe <pass|scoreable> <label> <curl args...>
  #   pass      - benign traffic; a block code here is a false positive
  #   scoreable - a payload shape; blocked or passed are both legitimate outcomes,
  #               anything else means GoTestWAF cannot score that whole placeholder
  probe() {
    local mode="$1" label="$2"; shift 2
    local code
    # No -L: a redirect must stay visible instead of being followed away.
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$@" || echo "ERR")
    printf '    %-34s -> %s' "$label" "$code"
    if [[ ",${BLOCK_CODES}," == *",${code},"* ]]; then
      if [[ "$mode" == "pass" ]]; then
        echo "  ${RED}<- counted as BLOCKED (false positive)${NC}"; FALSE_POS=1
      else
        echo "  ${GRN}<- blocked${NC}"
      fi
    elif [[ ",${PASS_CODES}," == *",${code},"* ]]; then
      echo "  ${GRN}<- pass${NC}"
    elif [[ "$code" =~ ^3[0-9][0-9]$ ]]; then
      echo "  ${YEL}<- redirect${NC}"; REDIRECTS=1; UNLISTED=1
    else
      echo "  ${YEL}<- UNSCOREABLE${NC}"; UNLISTED=1; UNSCOREABLE+=("${label} -> ${code}")
    fi
  }

  echo "Block codes: ${BLOCK_CODES}   |   Pass codes: ${PASS_CODES}"
  echo
  info "Benign requests - a block code here is a false positive"
  probe pass "GET /"                    "${TARGET_URL}/"
  probe pass "GET /?q=hello world"      "${TARGET_URL}/?q=hello%20world"
  probe pass "GET /?name=Nguyen Van A"  "${TARGET_URL}/?name=Nguyen%20Van%20A"
  probe pass "GET /no-such-path-9f3a2b" "${TARGET_URL}/no-such-path-9f3a2b"
  echo

  # One probe per placeholder GoTestWAF uses. It sends body payloads to the base URL, so
  # these mirror the real requests. A 405 or 404 here is the failure that cost two
  # earlier scans ~40% of their test cases without a single warning in the report.
  info "Payload shapes - each must be scoreable"
  probe scoreable "POST / urlencoded (HTMLForm)" -X POST -d 'q=hello' "${TARGET_URL}/"
  probe scoreable "POST / json (JSONRequest)"    -X POST -H 'Content-Type: application/json' \
                                                 -d '{"q":"hello"}' "${TARGET_URL}/"
  probe scoreable "POST / xml (XMLBody/SOAPBody)" -X POST -H 'Content-Type: text/xml' \
                                                 -d '<q>hello</q>' "${TARGET_URL}/"
  probe scoreable "POST / multipart"             -X POST -F 'q=hello' "${TARGET_URL}/"
  probe scoreable "PUT /"                        -X PUT -d 'q=hello' "${TARGET_URL}/"
  probe scoreable "PATCH /"                      -X PATCH -d 'q=hello' "${TARGET_URL}/"
  probe scoreable "DELETE /"                     -X DELETE "${TARGET_URL}/"
  probe scoreable "OPTIONS /"                    -X OPTIONS "${TARGET_URL}/"
  probe scoreable "GET /payload-in-url-path"     "${TARGET_URL}/payload-in-url-path"
  echo

  # Prove the request reached the instrumented origin. Without this the scan can still
  # produce a score, but no finding can show that a payload arrived at the application.
  info "Checking which origin build answers"
  ORIGIN_BUILD=$(curl -sk -D - -o /dev/null --max-time 10 "${TARGET_URL}/?fnp_canary=1" 2>/dev/null \
    | tr -d '\r' | awk 'tolower($1)=="x-origin-build:"{print $2}' | tail -1)
  if [[ -z "$ORIGIN_BUILD" ]]; then
    # Some WAFs strip unknown response headers, so try the body instead.
    ORIGIN_BUILD=$(curl -sk --max-time 10 "${TARGET_URL}/api/health" 2>/dev/null \
      | sed -n 's/.*"build"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  fi
  if [[ -n "$ORIGIN_BUILD" ]]; then
    info "Origin build: ${ORIGIN_BUILD}"
  else
    warn "No X-Origin-Build header and no build in /api/health. Either the origin is not"
    warn "running the instrumented app, or the WAF strips both. Findings will then lack"
    warn "the per-request evidence that proves a payload reached the application."
  fi
  echo

  # Large bodies are the usual cause of "unexpected EOF" during a scan. A status code
  # alone cannot tell "accepted" from "read": the origin echoes how many bytes it
  # actually received, so assert on that instead of trusting a 200.
  info "Probing the request body limit (~70 KB POST)"
  BIG=$(head -c 70000 /dev/zero | tr '\0' 'A')
  BIG_RESPONSE=$(printf '%s' "$BIG" \
    | curl -sk -w '\n%{http_code}' --max-time 15 \
        -X POST -H 'Content-Type: text/plain' --data-binary @- "${TARGET_URL}/" \
    || printf '\nERR')
  big_code="${BIG_RESPONSE##*$'\n'}"
  big_body="${BIG_RESPONSE%$'\n'*}"
  if [[ "$big_code" == "ERR" || -z "$big_code" || "$big_code" == "000" ]]; then
    warn "Large POST dropped the connection. The 8kb-128kb test cases will fail the same"
    warn "way and be recorded as 'failed' - neither blocked nor passed. Raise the WAF's"
    warn "request-body inspection limit (and client_max_body_size / SecRequestBodyLimit)."
  elif [[ ",${BLOCK_CODES}," == *",${big_code},"* ]]; then
    info "Large POST returned ${big_code} - the WAF blocked it, which is a real result"
  elif grep -q '"body_len":70000' <<<"$big_body"; then
    info "Large POST returned ${big_code} and the origin read all 70000 bytes"
  else
    warn "Large POST returned ${big_code}, but the origin did not report reading 70000"
    warn "bytes. Something between here and the application truncates or discards the"
    warn "body, so the 8kb-128kb rows will describe that rather than the WAF."
  fi
  echo

  if ((${#UNSCOREABLE[@]})); then
    warn "UNSCOREABLE shapes - no payload GoTestWAF sends this way can be scored:"
    for shape in "${UNSCOREABLE[@]}"; do warn "    ${shape}"; done
    warn "Two causes, needing different fixes:"
    warn "  1. The origin is stale or misconfigured. On server A run ./setup.sh restart"
    warn "     (a full rebuild), then re-run this. Its nginx must hand every method and"
    warn "     every unknown path to the app instead of answering 404/405 itself."
    warn "  2. The WAF enforces an HTTP-method policy. Send the same request straight to"
    warn "     the origin IP with a Host: header - if the origin answers 200 and the WAF"
    warn "     answers 405, fix it in the WAF or add 405 to --block-codes deliberately."
  fi
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
  --reportFormat=html,json,csv
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