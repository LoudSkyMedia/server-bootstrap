#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

PROJECT_NAME="lsm-vps-init"
DEFAULT_REF="stable"
DEFAULT_REPO="https://github.com/LoudSkyMedia/server-bootstrap"
INSTALL_ROOT="/usr/local/lib/lsm-vps-init"
BIN_PATH="/usr/local/sbin/lsm-vps-init"
STATE_DIR="/var/lib/lsm-vps-init"
LOG_DIR="/var/log/lsm-vps-init"

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run this bootstrap with sudo or as root."
  fi
}

source_os_release() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release."
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
    die "Unsupported OS: ${PRETTY_NAME:-unknown}. This release supports Ubuntu 24.04 LTS."
  fi
}

apt_install_prereqs() {
  export DEBIAN_FRONTEND=noninteractive
  local packages=(ca-certificates curl tar gzip python3 tmux)
  wait_for_apt_locks
  log "Installing bootstrap prerequisites: ${packages[*]}"
  apt-get update
  apt-get install -y "${packages[@]}"
}

wait_for_apt_locks() {
  local locks=(
    /var/lib/dpkg/lock
    /var/lib/dpkg/lock-frontend
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  local waited=0
  while true; do
    local busy=0
    for lock in "${locks[@]}"; do
      if [[ -e "$lock" ]] && command -v fuser >/dev/null 2>&1 && fuser "$lock" >/dev/null 2>&1; then
        busy=1
      fi
    done
    if [[ "$busy" -eq 0 ]]; then
      return 0
    fi
    if [[ "$waited" -ge 900 ]]; then
      die "Timed out waiting for apt/dpkg locks."
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

download_release() {
  local workdir="$1"
  local ref="${LSM_VPS_INIT_REF:-$DEFAULT_REF}"
  local archive_url="${LSM_VPS_INIT_ARCHIVE_URL:-$DEFAULT_REPO/archive/refs/heads/$ref.tar.gz}"
  if [[ "$ref" == v* || "$ref" =~ ^[0-9]+\.[0-9]+ ]]; then
    archive_url="${LSM_VPS_INIT_ARCHIVE_URL:-$DEFAULT_REPO/archive/refs/tags/$ref.tar.gz}"
  fi

  local archive="$workdir/$PROJECT_NAME.tar.gz"
  log "Downloading $archive_url"
  curl -fsSL "$archive_url" -o "$archive"

  if [[ -n "${LSM_VPS_INIT_SHA256:-}" ]]; then
    printf '%s  %s\n' "$LSM_VPS_INIT_SHA256" "$archive" | sha256sum -c -
  else
    log "No LSM_VPS_INIT_SHA256 supplied; continuing without checksum verification."
  fi

  tar -xzf "$archive" -C "$workdir"
  find "$workdir" -mindepth 1 -maxdepth 1 -type d | head -n 1
}

cleanup_tmpdir() {
  if [[ -n "${tmpdir:-}" && "$tmpdir" == /tmp/lsm-vps-init.* && -d "$tmpdir" ]]; then
    rm -rf -- "$tmpdir"
  fi
}

install_from_source() {
  local source_dir="$1"
  [[ -x "$source_dir/bin/lsm-vps-init" || -f "$source_dir/bin/lsm-vps-init" ]] \
    || die "Source directory does not look like $PROJECT_NAME: $source_dir"

  install -d -o root -g root -m 0755 "$INSTALL_ROOT"
  rsync -a --delete \
    --exclude '.git' \
    --exclude '.env' \
    --exclude '__pycache__' \
    "$source_dir/" "$INSTALL_ROOT/"
  chown -R root:root "$INSTALL_ROOT"
  chmod 0755 "$INSTALL_ROOT/bin/lsm-vps-init"
  ln -sfn "$INSTALL_ROOT/bin/lsm-vps-init" "$BIN_PATH"
}

main() {
  need_root
  source_os_release
  apt_install_prereqs
  install -d -o root -g root -m 0700 "$STATE_DIR"
  install -d -o root -g root -m 0700 "$LOG_DIR"

  local source_dir="${LSM_VPS_INIT_SOURCE_DIR:-}"
  local tmpdir=""
  if [[ -z "$source_dir" ]]; then
    tmpdir="$(mktemp -d -t lsm-vps-init.XXXXXXXXXX)"
    trap cleanup_tmpdir EXIT
    source_dir="$(download_release "$tmpdir")"
  fi

  if ! command -v rsync >/dev/null 2>&1; then
    wait_for_apt_locks
    apt-get install -y rsync
  fi

  install_from_source "$source_dir"
  log "Installed $BIN_PATH"
  exec "$BIN_PATH" resume
}

main "$@"
