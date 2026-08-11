#!/bin/bash
#
# setup.sh - Install prerequisites and run the Friday Night Poker origin website
#
#   ./setup.sh            Install Docker (if missing), then build + start (default)
#   ./setup.sh up         Build + start in the background
#   ./setup.sh down       Stop and remove the containers
#   ./setup.sh restart    Rebuild + restart (picks up edited web/ or nginx/)
#   ./setup.sh logs       Follow the container logs
#   ./setup.sh status     Show container status
#
# The site listens on http://<this-server>:80 and is the ORIGIN behind your WAF.
# Point your domain's DNS at the WAF, cert it with ../script/waf_cert.sh, have the
# WAF forward to this server's IP:80, then scan with ../script/run_gotestwaf.sh.
#
set -euo pipefail

cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; NC=$'\033[0m'
info() { echo "${GRN}[+]${NC} $*"; }
warn() { echo "${YEL}[!]${NC} $*"; }
err()  { echo "${RED}[x]${NC} $*" >&2; }

# ---------- Install Docker if missing (auto-detect the package manager) ----
install_docker() {
  info "Docker not found - installing Docker Engine + compose plugin"
  sudo -v   # prompt for the password now, not from inside a pipe later
  if command -v apt-get >/dev/null; then
    info "Installing prerequisites (ca-certificates curl gnupg)..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq ca-certificates curl gnupg
    info "Fetching Docker's signing key from download.docker.com..."
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL --connect-timeout 10 --max-time 60 --retry 2 \
      -o /tmp/docker-key.asc https://download.docker.com/linux/ubuntu/gpg \
      || { err "Cannot reach download.docker.com - blocked egress or a proxy is required."
           err "Alternative: sudo apt-get install -y docker.io docker-compose-v2"; exit 1; }
    sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg < /tmp/docker-key.asc
    rm -f /tmp/docker-key.asc
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    info "Adding the Docker apt repository and installing..."
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif command -v dnf >/dev/null; then
    sudo dnf -y install dnf-plugins-core
    sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null \
      || sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif command -v yum >/dev/null; then
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  else
    err "No supported package manager (apt-get/dnf/yum). Install Docker manually: https://docs.docker.com/engine/install/"
    exit 1
  fi
  sudo systemctl enable --now docker
  sudo usermod -aG docker "${SUDO_USER:-$USER}" || true
  warn "Added ${SUDO_USER:-$USER} to the 'docker' group - log out and back in for it to apply."
}

command -v docker &>/dev/null || install_docker

# Fall back to sudo if the current session cannot reach the daemon
DOCKER="docker"
if ! docker info &>/dev/null; then
  if sudo -n true 2>/dev/null || sudo docker info &>/dev/null; then
    DOCKER="sudo docker"
    warn "Using 'sudo docker' (docker group membership not active in this session)"
  else
    err "Cannot reach the Docker daemon. Is it running? (sudo systemctl start docker)"
    exit 1
  fi
fi

# docker compose (v2 plugin) vs legacy docker-compose
if $DOCKER compose version &>/dev/null; then
  COMPOSE="$DOCKER compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE="docker-compose"
else
  err "Docker Compose not found. Install the docker-compose-plugin."
  exit 1
fi

# ---------- Commands -----------------------------------------------------
show_urls() {
  info "Site is up. Local check:  http://localhost/"
  info "House rules (API page):  http://localhost/rules"
  info "API health:              http://localhost/api/health"
  echo
  warn "Reminder: run GoTestWAF against your WAF domain (https://<domain>), not"
  warn "the origin directly - otherwise you are only testing this permissive origin."
}

case "${1:-up}" in
  up)
    info "Building and starting containers..."
    $COMPOSE up -d --build
    $COMPOSE ps
    show_urls
    ;;
  down)
    info "Stopping containers..."
    $COMPOSE down
    ;;
  restart)
    # The React app is baked into the web image, so edits need a rebuild -
    # a plain 'compose restart' would serve the previous build.
    info "Rebuilding and restarting containers..."
    $COMPOSE up -d --build
    $COMPOSE ps
    ;;
  logs)
    $COMPOSE logs -f
    ;;
  status)
    $COMPOSE ps
    ;;
  -h|--help)
    sed -n '2,15p' "$0" | sed 's/^# \?//'
    ;;
  *)
    err "Unknown command: $1"
    sed -n '2,15p' "$0" | sed 's/^# \?//'
    exit 1
    ;;
esac
