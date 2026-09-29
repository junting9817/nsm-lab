#!/usr/bin/env bash
# Honeypot VM startup script (instance metadata "startup-script", runs as root on every boot). Idempotent.
#
#   1. move the real sshd to 22222 (reachable only from IAP) before Cowrie takes 22
#   2. cap journald, install Docker (only possible in the bootstrap stage, while egress is open)
#   3. write the stack files from instance metadata and create Cowrie's state directories
#   4. install a daily cleanup timer for shipped logs, TTY logs and uploads
#   5. start Cowrie + Vector (images are pulled only if missing, so the live stage works without egress)
#
# Output goes to the journal (journalctl -u google-startup-scripts) and, on exit, to the bucket as
# startup/<hostname>-<UTC time>-<exit code>.log, so a run can be inspected from the dashboard VM without GCP credentials:
#   gcloud storage ls gs://<bucket>/startup/ && gcloud storage cat gs://<bucket>/startup/<object>
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log() { printf '[nsm-honeypot] %s\n' "$*"; }
die() { printf '[nsm-honeypot] ERROR: %s\n' "$*" >&2; exit 1; }

MD=http://169.254.169.254/computeMetadata/v1
metadata() { curl -fsS --retry 5 --retry-connrefused -H 'Metadata-Flavor: Google' "$MD/$1"; }

RUN_LOG="$(mktemp /var/log/nsm-honeypot-startup.XXXXXX)"
exec 3>&1
exec >"$RUN_LOG" 2>&1

# Upload this run's log with the VM's own token. objectCreator can create new objects, which is all this needs.
# --resolve pins the API hostname to private.googleapis.com, the only egress the live stage allows.
report() {
  local code="$1" bucket token name
  cat "$RUN_LOG" >&3
  bucket="$(metadata instance/attributes/nsm-bucket 2>/dev/null)" || return 0
  token="$(metadata instance/service-accounts/default/token 2>/dev/null | sed -E 's/.*"access_token":"([^"]+)".*/\1/')" || return 0
  name="startup/$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)-exit$code.log"
  curl -fsS --max-time 20 --resolve storage.googleapis.com:443:199.36.153.8 \
    -H "Authorization: Bearer $token" -H 'Content-Type: text/plain' --data-binary "@$RUN_LOG" \
    "https://storage.googleapis.com/upload/storage/v1/b/$bucket/o?uploadType=media&name=$name" >/dev/null \
    || printf '[nsm-honeypot] could not upload the startup log\n' >&3
}
trap 'report $?' EXIT

# fetch_stack_file <metadata key> <path>: refuses empty or failed fetches so a good file is never overwritten
fetch_stack_file() {
  local content
  content="$(metadata "instance/attributes/$1")" || die "metadata attribute $1 could not be read"
  [[ -n "$content" ]] || die "metadata attribute $1 is empty"
  printf '%s\n' "$content" | write_if_changed "$2" 0644
}

# write_if_changed <path> <mode>: stdin → path, atomically; returns 0 only if the content changed
write_if_changed() {
  local path="$1" mode="$2" tmp
  tmp="$(mktemp "$path.XXXXXX")"
  cat >"$tmp"
  chmod "$mode" "$tmp"
  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$path"
  return 0
}

COWRIE_UID=999 # user inside the cowrie/cowrie image
STACK_DIR=/opt/nsm-honeypot
STATE_DIR=/var/lib/nsm-honeypot

# --- 1) real sshd on 22222 --------------------------------------------------------------------------------
if write_if_changed /etc/ssh/sshd_config.d/10-nsm-honeypot.conf 0644 <<'EOF'
# managed by honeypot/startup.sh — 22/tcp belongs to Cowrie; admin SSH is 22222 via IAP only
Port 22222
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
EOF
then
  sshd -t || die "sshd config test failed"
  systemctl restart ssh
  log "sshd moved to 22222"
fi

# --- 2) journald cap, Docker -------------------------------------------------------------------------------
mkdir -p /etc/systemd/journald.conf.d
if write_if_changed /etc/systemd/journald.conf.d/99-nsm.conf 0644 <<'EOF'
[Journal]
SystemMaxUse=200M
EOF
then
  systemctl restart systemd-journald
fi

if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  log "installing Docker (needs the bootstrap stage: egress open)"
  apt-get update -q || die "apt-get update failed — is honeypot_stage = \"bootstrap\"?"
  # Debian 13 ships the docker CLI as docker-cli, only a Recommends of docker.io and docker-compose, so name it
  # (and apparmor, which Docker needs when the kernel has AppArmor enabled) instead of pulling every recommendation.
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends docker.io docker-cli docker-compose apparmor
fi
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  die "docker CLI or compose plugin missing after install"
fi
systemctl enable --now docker >/dev/null

# --- 3) stack files and state directories ------------------------------------------------------------------
install -d -m 0755 "$STACK_DIR"
changed=0
fetch_stack_file nsm-compose "$STACK_DIR/docker-compose.yml" && changed=1
fetch_stack_file nsm-cowrie-cfg "$STACK_DIR/cowrie.cfg" && changed=1
fetch_stack_file nsm-vector-yaml "$STACK_DIR/vector.yaml" && changed=1

# An empty bind mount hides the image's var/ tree, so Cowrie's log and state directories must exist.
# 0755 on the log directory lets the Vector container (root without CAP_DAC_OVERRIDE) read it.
install -d -o "$COWRIE_UID" -g "$COWRIE_UID" -m 0755 \
  "$STATE_DIR/cowrie" "$STATE_DIR/cowrie/log" "$STATE_DIR/cowrie/log/cowrie"
install -d -o "$COWRIE_UID" -g "$COWRIE_UID" -m 0750 \
  "$STATE_DIR/cowrie/lib" "$STATE_DIR/cowrie/lib/cowrie" "$STATE_DIR/cowrie/lib/cowrie/downloads" "$STATE_DIR/cowrie/lib/cowrie/tty"
install -d -m 0700 "$STATE_DIR/vector"

# --- 4) daily cleanup (the boot disk is 10 GB) -------------------------------------------------------------
write_if_changed /etc/systemd/system/nsm-honeypot-cleanup.service 0644 <<EOF || true
[Unit]
Description=Delete shipped Cowrie logs, TTY logs and uploads older than 7 days

[Service]
Type=oneshot
ExecStart=/usr/bin/find $STATE_DIR/cowrie/log/cowrie -maxdepth 1 -type f -name 'cowrie.json.*' -mtime +7 -delete
ExecStart=/usr/bin/find $STATE_DIR/cowrie/lib/cowrie/tty $STATE_DIR/cowrie/lib/cowrie/downloads -type f -mtime +7 -delete
EOF
write_if_changed /etc/systemd/system/nsm-honeypot-cleanup.timer 0644 <<'EOF' || true
[Unit]
Description=Daily honeypot disk cleanup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now nsm-honeypot-cleanup.timer >/dev/null

# --- 5) start the stack ------------------------------------------------------------------------------------
compose=(docker compose -f "$STACK_DIR/docker-compose.yml")
"${compose[@]}" up -d --pull missing
if ((changed)); then
  # Config files are bind-mounted; a content change alone does not recreate containers.
  "${compose[@]}" restart
  log "stack files changed: containers restarted"
fi
"${compose[@]}" ps
log "done"
