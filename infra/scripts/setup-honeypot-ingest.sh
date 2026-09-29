#!/usr/bin/env bash
# Sensor VM side of the Phase 5 honeypot: GeoIP databases, one-way bucket pull, directories.
# Run before setup-stack.sh (Vector's enrichment tables need the GeoIP files). Idempotent.
#
#   sudo infra/scripts/setup-honeypot-ingest.sh [--bucket NAME]
#
# The bucket defaults to "<project id>-nsm-honeypot-logs" (infra/terraform/honeypot.tf). The pull timer is enabled only
# once the bucket is readable with the VM's own service account, so running this before `terraform apply` is safe.
source "$(dirname "$0")/lib.sh"
require_root
require_data_mount

bucket=""
while (($#)); do
  case "$1" in
    --bucket) bucket="${2:?--bucket needs a name}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

metadata() { curl -fsS -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/$1"; }
[[ -n "$bucket" ]] || bucket="$(metadata project/project-id)-nsm-honeypot-logs"
[[ "$bucket" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] || die "invalid bucket name: $bucket"

# --- 1) directories ------------------------------------------------------------------------------------------
install -d -m 0755 -o root -g root "$DATA_MOUNT/logs/honeypot" "$DATA_MOUNT/logs/honeypot/cowrie" "$DATA_MOUNT/geoip"
install -d -m 0700 -o root -g root /var/lib/nsm-honeypot-pull

# --- 2) GeoIP databases (DB-IP Lite, monthly) ----------------------------------------------------------------
install -m 0755 -o root -g root "$REPO_ROOT/infra/scripts/nsm-geoip-update.sh" /usr/local/sbin/nsm-geoip-update

units_changed=0
if write_if_changed /etc/systemd/system/nsm-geoip-update.service 0644 <<'EOF'
[Unit]
Description=Update DB-IP Lite country/ASN databases for honeypot enrichment (NSM)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nsm-geoip-update
EOF
then
  units_changed=1
fi
# DB-IP publishes each month's files during the month; the script falls back to last month's.
if write_if_changed /etc/systemd/system/nsm-geoip-update.timer 0644 <<'EOF'
[Unit]
Description=Update DB-IP Lite databases monthly

[Timer]
OnCalendar=*-*-05 04:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF
then
  units_changed=1
fi

if [[ ! -s "$DATA_MOUNT/geoip/dbip-country-lite.mmdb" || ! -s "$DATA_MOUNT/geoip/dbip-asn-lite.mmdb" ]]; then
  log "first GeoIP download"
  /usr/local/sbin/nsm-geoip-update
fi

# --- 3) one-way bucket pull (every minute) -------------------------------------------------------------------
install -m 0755 -o root -g root "$REPO_ROOT/infra/scripts/nsm-honeypot-pull.py" /usr/local/sbin/nsm-honeypot-pull
write_if_changed /etc/nsm/honeypot.env 0644 <<EOF || true
# managed by infra/scripts/setup-honeypot-ingest.sh
NSM_HONEYPOT_BUCKET=$bucket
EOF

# It parses data from a host assumed to be compromised, so the service gets a narrow sandbox.
if write_if_changed /etc/systemd/system/nsm-honeypot-pull.service 0644 <<EOF
[Unit]
Description=Pull honeypot log objects from the one-way bucket (NSM)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/nsm/honeypot.env
ExecStart=/usr/local/sbin/nsm-honeypot-pull
TimeoutStartSec=300
MemoryMax=256M
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_MOUNT/logs/honeypot /var/lib/nsm-honeypot-pull
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=
EOF
then
  units_changed=1
fi
if write_if_changed /etc/systemd/system/nsm-honeypot-pull.timer 0644 <<'EOF'
[Unit]
Description=Pull honeypot logs every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
then
  units_changed=1
fi

if ((units_changed)); then
  systemctl daemon-reload
fi
systemctl enable --now nsm-geoip-update.timer >/dev/null 2>&1

token="$(metadata instance/service-accounts/default/token | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" \
  "https://storage.googleapis.com/storage/v1/b/$bucket/o?maxResults=1&prefix=cowrie/")"
if [[ "$status" == 200 ]]; then
  systemctl enable --now nsm-honeypot-pull.timer >/dev/null 2>&1
  log "bucket gs://$bucket readable: pull timer enabled"
else
  systemctl disable --now nsm-honeypot-pull.timer >/dev/null 2>&1 || true
  warn "bucket gs://$bucket not readable yet (HTTP $status): pull timer left disabled. Re-run after terraform apply."
fi

# --- summary -------------------------------------------------------------------------------------------------
ls -l "$DATA_MOUNT/geoip"
systemctl show nsm-geoip-update.timer nsm-honeypot-pull.timer -p Id -p ActiveState -p NextElapseUSecRealtime
