#!/usr/bin/env bash
# Shared helpers for setup-*.sh. Sourced, not executed.
set -Eeuo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive

# The variables below are used by the scripts that source this file
# shellcheck disable=SC2034
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATA_MOUNT="${DATA_MOUNT:-/data}"
SCRIPT_NAME="$(basename "$0")"

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$SCRIPT_NAME" "$*"; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$SCRIPT_NAME" "$*" >&2; }
die()  { printf '\033[1;31m[%s] ERROR:\033[0m %s\n' "$SCRIPT_NAME" "$*" >&2; exit 1; }

trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

require_root() {
  [[ $EUID -eq 0 ]] || die "run as root: sudo $0"
}

require_data_mount() {
  mountpoint -q "$DATA_MOUNT" || die "$DATA_MOUNT is not mounted. Run setup-disk.sh first."
}

# Write stdin to dest, leaving the file untouched when the content is identical.
# Returns 0 = changed, 1 = unchanged (callers use it to decide whether to reload a service)
write_if_changed() {
  local dest="$1" mode="${2:-0644}" tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    return 1
  fi
  install -D -m "$mode" "$tmp" "$dest"
  rm -f "$tmp"
  log "updated: $dest"
  return 0
}

# Install only missing packages; apt-get update runs only when something needs installing.
apt_install() {
  local pkg missing=()
  for pkg in "$@"; do
    dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null | grep -qx installed || missing+=("$pkg")
  done
  ((${#missing[@]})) || return 0
  log "installing packages: ${missing[*]}"
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${missing[@]}"
}

# Print the primary (v4) key fingerprint of an ASCII-armored OpenPGP public key as uppercase hex.
# Debian 13 ships without gpg (apt uses sqv), so it is computed in Python.
pgp_primary_fingerprint() {
  python3 - "$1" <<'PY'
import base64, hashlib, sys
b64 = []
inside = False
for line in open(sys.argv[1]).read().splitlines():
    if line.startswith("-----BEGIN"):
        inside = True
    elif line.startswith("-----END"):
        break
    elif inside and line and not line.startswith("=") and ":" not in line:
        b64.append(line)
data = base64.b64decode("".join(b64))
tag = data[0]
if tag & 0x40:  # new-format packet header
    ptype, l1 = tag & 0x3F, data[1]
    if l1 < 192:
        length, off = l1, 2
    elif l1 < 224:
        length, off = ((l1 - 192) << 8) + data[2] + 192, 3
    else:
        length, off = int.from_bytes(data[2:6], "big"), 6
else:  # old-format packet header
    ptype, n = (tag >> 2) & 0x0F, {0: 1, 1: 2, 2: 4}[tag & 0x03]
    length, off = int.from_bytes(data[1:1 + n], "big"), 1 + n
body = data[off:off + length]
if ptype != 6 or body[0] != 4:
    sys.exit("not a v4 public key packet")
print(hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper())
PY
}

# Ensure one fstab line keyed by mountpoint. Stops if the mountpoint already has a different entry.
ensure_fstab_line() {
  local line="$1" mnt
  mnt="$(awk '{print $2}' <<<"$line")"
  if grep -qxF "$line" /etc/fstab; then
    return 1
  fi
  if awk -v m="$mnt" '$1 !~ /^#/ && $2 == m {found=1} END {exit !found}' /etc/fstab; then
    die "/etc/fstab already has a different entry for $mnt. Check it manually."
  fi
  [[ -f /etc/fstab.nsm.bak ]] || cp -a /etc/fstab /etc/fstab.nsm.bak
  printf '%s\n' "$line" >>/etc/fstab
  systemctl daemon-reload
  log "added to fstab: $line"
  return 0
}
