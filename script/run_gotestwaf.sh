#!/bin/bash
#
# run-gotestwaf.sh - Run a Wallarm GoTestWAF scan against a target (Ubuntu)
#
# Usage:
#   ./run-gotestwaf.sh https://example.com
#   ./run-gotestwaf.sh --url https://example.com --waf-name "my-waf" --block-codes 403,468
#   ./run-gotestwaf.sh --url https://example.com --strict --skip-precheck
#
# Options:
#   --url URL            Target URL (prompted for if omitted)
#   --waf-name NAME      Label shown in the report            (default: unknown-waf)
#   --block-codes LIST   Status codes that mean "blocked"     (default: 403)
#   --pass-codes LIST    Status codes that mean "not blocked" (default: 200,404)
#   --workers N          Parallel workers                     (default: 5)
#   --strict             Count anything that is neither a pass code nor a
#                        block code as BLOCKED (GoTestWAF's own default).
#                        Omit this and such responses count as passed.
#   --skip-precheck      Skip the benign-request sanity check
#   --no-pull            Do not pull a fresh image
#   -h, --help           Show this help
#
set -euo pipefail

IMAGE="wallarm/gotestwaf"
TARGET_URL=""
WAF_NAME="unknown-waf"
BLOCK_CODES="403"
PASS_CODES="200,404"
WORKERS="5"
STRICT=0
DO_PRECHECK=1
DO_PULL=1

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; NC=$'\033[0m'
info() { echo "${GRN}[+]${NC} $*"; }
warn() { echo "${YEL}[!]${NC} $*"; }
err()  { echo "${RED}[x]${NC} $*" >&2; }
hr()   { printf '%.0s=' {1..60}; echo; }

usage() { sed -n '2,22p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

# ---------- 1. Parse arguments -------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)           TARGET_URL="${2:-}";  shift 2 ;;
    --waf-name)      WAF_NAME="${2:-}";    shift 2 ;;
    --block-codes)   BLOCK_CODES="${2:-}"; shift 2 ;;
    --pass-codes)    PASS_CODES="${2:-}";  shift 2 ;;
    --workers)       WORKERS="${2:-}";     shift 2 ;;
    --strict)        STRICT=1; shift ;;
    --skip-precheck) DO_PRECHECK=0; shift ;;
    --no-pull)       DO_PULL=0; shift ;;
    -h|--help)       usage 0 ;;
    -*)              err "Unknown option: $1"; usage 1 ;;
    *)               TARGET_URL="$1"; shift ;;
  esac
done

if [[ -z "$TARGET_URL" ]]; then
  read -rp "Enter the target URL (e.g. https://superman.chubbyduck.org): " TARGET_URL
fi
[[ -n "$TARGET_URL" ]] || { err "Target URL cannot be empty."; exit 1; }

# Normalise: add a scheme if the user forgot one, strip any trailing slash
[[ "$TARGET_URL" =~ ^https?:// ]] || { TARGET_URL="https://${TARGET_URL}"; warn "No scheme given, using ${TARGET_URL}"; }
TARGET_URL="${TARGET_URL%/}"

# ---------- 2. Install Docker if missing (Ubuntu) ------------------------
hr; info "[1/5] Checking the Docker environment"; hr

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

# Fall back to sudo if the current session cannot reach the daemon
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

# ---------- 3. Sanity-check the target ----------------------------------
if [[ "$DO_PRECHECK" -eq 1 ]]; then
  command -v curl &>/dev/null || { err "curl is required for the pre-check (or use --skip-precheck)."; exit 1; }
  hr; info "[2/5] Pre-flight check on benign requests"; hr
  echo "A clean request must NOT return a block code, and ideally should return"
  echo "a pass code - otherwise the false-positive score is meaningless."
  echo
  UNLISTED=0
  for path in "/" "/index.html" "/?q=hello%20world" "/no-such-path-9f3a2b"; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${TARGET_URL}${path}" || echo "ERR")
    printf '    %-28s -> %s' "$path" "$code"
    if [[ ",${BLOCK_CODES}," == *",${code},"* ]]; then
      echo "  ${RED}<- counted as BLOCKED${NC}"
    elif [[ ",${PASS_CODES}," == *",${code},"* ]]; then
      echo "  ${GRN}<- pass${NC}"
    else
      echo "  ${YEL}<- not in either list${NC}"; UNLISTED=1
    fi
  done
  echo
  echo "Block codes: ${BLOCK_CODES}   |   Pass codes: ${PASS_CODES}"
  if [[ "$UNLISTED" -eq 1 && "$STRICT" -eq 1 ]]; then
    warn "Some codes are in neither list and --strict is on: they will be"
    warn "scored as BLOCKED. Add them to --pass-codes or drop --strict."
  fi
  read -rp "Continue with the scan? [Y/n] " ans
  [[ "${ans:-Y}" =~ ^[Yy]?$ ]] || { info "Aborted."; exit 0; }
fi

# ---------- 4. Prepare the report directory ------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="$(pwd)/reports/${STAMP}"
mkdir -p "$REPORT_DIR"
# The GoTestWAF image runs as a non-root user, so a dir created by root/sudo
# is not writable inside the container. World-writable is fine for reports.
chmod 0777 "$REPORT_DIR"

# ---------- 5. Run the scan ---------------------------------------------
if [[ "$DO_PULL" -eq 1 ]]; then
  hr; info "[3/5] Pulling the GoTestWAF image"; hr
  $DOCKER pull "$IMAGE" || warn "Pull failed - using the local image if present"
else
  info "[3/5] Skipping pull (--no-pull)"
fi

hr
info "[4/5] Scanning ${TARGET_URL}"
info "      WAF name: ${WAF_NAME}   Reports: ${REPORT_DIR}"
hr

# Only allocate a TTY when one exists, so cron and CI runs do not fail
TTY_FLAG=()
[[ -t 0 && -t 1 ]] && TTY_FLAG=(-it)

# Without --nonBlockedAsPassed, any response that matches neither list is
# scored as blocked - which silently drives the false-positive score to 0%.
SCORE_FLAG=(--nonBlockedAsPassed)
[[ "$STRICT" -eq 1 ]] && SCORE_FLAG=()

# :z relabels the volume for SELinux; harmless on Ubuntu, required on RHEL
set +e
$DOCKER run --rm "${TTY_FLAG[@]}" \
  -v "${REPORT_DIR}":/app/reports:z \
  "$IMAGE" \
  --url="$TARGET_URL" \
  --wafName="$WAF_NAME" \
  --blockStatusCodes="$BLOCK_CODES" \
  --passStatusCodes="$PASS_CODES" \
  "${SCORE_FLAG[@]}" \
  --workers="$WORKERS" \
  --maxIdleConns=1 \
  --followCookies \
  --renewSession \
  --includePayloads \
  --addDebugHeader \
  --blockConnReset \
  --noEmailReport \
  --reportFormat=html,json \
  --reportPath=/app/reports
SCAN_RC=$?
set -e

# ---------- 6. Wrap up ---------------------------------------------------
# The report files may end up owned by a container user id; reclaim them for
# the invoking (or original sudo) user so they are readable/deletable.
OWNER="${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}"
sudo chown -R "$OWNER" "$REPORT_DIR" 2>/dev/null || chown -R "$OWNER" "$REPORT_DIR" 2>/dev/null || true

hr
if [[ "$SCAN_RC" -eq 0 ]]; then
  info "[5/5] Scan finished"
else
  warn "[5/5] GoTestWAF exited with code ${SCAN_RC} - check the output above"
fi
if [[ -n "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]]; then
  info "Reports in ${REPORT_DIR}:"
  # -printf is GNU-only; fall back to ls where it is unsupported (BSD/macOS)
  find "$REPORT_DIR" -type f -printf '    %-10s %p\n' 2>/dev/null | sort \
    || ls -la "$REPORT_DIR"
else
  err "No report files were produced."
  err "Common causes: an invalid flag, the report dir is not writable by the"
  err "container user, or the scan aborted early. Scroll up for the real error."
fi
hr
exit "$SCAN_RC"