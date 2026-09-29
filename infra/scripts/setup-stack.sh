#!/usr/bin/env bash
# Bring up the NSM stack: create .env secrets → data directory ownership → start ClickHouse → apply schema → start everything.
# Idempotent: existing .env values are kept and the schema only uses IF NOT EXISTS.
source "$(dirname "$0")/lib.sh"
require_root
require_data_mount
command -v docker >/dev/null || die "docker not found — run setup-docker.sh first"

cd "$REPO_ROOT"
owner="${SUDO_USER:-root}"

# --- 1) .env: add only keys from .env.example that are missing; CHANGE_ME values become random secrets -------------
[[ -f .env ]] || install -m 0600 -o "$owner" -g "$(id -gn "$owner")" /dev/null .env
chmod 0600 .env
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  grep -q "^${key}=" .env && continue
  if [[ "$value" == CHANGE_ME ]]; then
    value="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
  fi
  printf '%s=%s\n' "$key" "$value" >>.env
  log "added $key to .env"
done <.env.example

# --- 2) data directories (owned by the UID inside each container) -------------------------------------------------
install -d -m 0750 -o 101 -g 101 "$DATA_MOUNT/clickhouse" # clickhouse user in the clickhouse image
install -d -m 0750 -o 472 -g 0 "$DATA_MOUNT/grafana"      # grafana user in the grafana image
install -d -m 0750 "$DATA_MOUNT/vector"                   # vector runs as root

# Vector's enrichment tables fail to load (and the whole pipeline stops) without the GeoIP databases.
for db in dbip-country-lite dbip-asn-lite; do
  [[ -s "$DATA_MOUNT/geoip/$db.mmdb" ]] || die "$DATA_MOUNT/geoip/$db.mmdb missing — run setup-honeypot-ingest.sh first"
done
# The responder mounts this file; without it Docker would create a directory at the mount point.
[[ -f /etc/nsm/never-block.local ]] || die "/etc/nsm/never-block.local missing — run setup-response.sh first"

# --- 3) start ClickHouse first and apply the schema ---------------------------------------------------
docker compose up -d --wait --wait-timeout 180 clickhouse

for f in ingest/clickhouse/schema/*.sql; do
  log "applying schema: $f"
  docker compose exec -T clickhouse clickhouse-client --multiquery <"$f"
done

# --- 4) start everything -----------------------------------------------------------------------------
docker compose up -d --wait --wait-timeout 300

# --- 4b) bring the stack back after every boot -------------------------------------------------------------
# restart: unless-stopped did not restart nsm-suricata after the 2026-09-14 VM stop (left at exit 255 while every other
# container came back), which would leave the sensor blind until someone noticed. This unit re-runs compose after Docker
# starts; for containers that are already running it changes nothing.
if write_if_changed /etc/systemd/system/nsm-stack-boot.service 0644 <<EOF
[Unit]
Description=Ensure the NSM compose stack is running after boot
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
RequiresMountsFor=$DATA_MOUNT

[Service]
Type=oneshot
WorkingDirectory=$REPO_ROOT
# Give Docker's own restart policy the first chance, then fill the gaps.
ExecStartPre=/bin/sleep 45
ExecStart=/usr/bin/docker compose up -d --wait --wait-timeout 300
TimeoutStartSec=420

[Install]
WantedBy=multi-user.target
EOF
then
  systemctl daemon-reload
fi
systemctl enable nsm-stack-boot.service >/dev/null 2>&1

# --- 5) detection allowlist (detections/allowlist.tsv → nsm.allowlist, validated and swapped atomically) ---
"$REPO_ROOT/detections/sync-allowlist.sh"

docker compose ps
docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}'
