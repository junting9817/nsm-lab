#!/usr/bin/env bash
# Sensor VM side of Phase 6: instance-specific never-block entries for the responder. Run before setup-stack.sh. Idempotent.
#
#   sudo infra/scripts/setup-response.sh
#
# /etc/nsm/never-block.local holds addresses that only exist in this deployment — the sensor's own external IP (hairpin
# self-tests) and the honeypot's (Terraform state) — next to the static list in response/never-block.txt.
# It must exist before the responder container starts: Docker would otherwise create a directory at the mount point.
source "$(dirname "$0")/lib.sh"
require_root

sensor_ip="$(curl -fsS -H 'Metadata-Flavor: Google' \
  http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)"
[[ "$sensor_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "could not read this VM's external IP from the metadata server"

honeypot_ip=""
if command -v terraform >/dev/null; then
  honeypot_ip="$(terraform -chdir="$REPO_ROOT/infra/terraform" output -raw honeypot_external_ip 2>/dev/null || true)"
fi

{
  echo "# managed by infra/scripts/setup-response.sh — re-run after an external IP changes"
  echo "$sensor_ip/32 sensor external IP (self-tests hairpin through it)"
  if [[ "$honeypot_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "$honeypot_ip/32 honeypot external IP (ours)"
  fi
} | write_if_changed /etc/nsm/never-block.local 0644 || true

[[ "$honeypot_ip" ]] || warn "no honeypot_external_ip in Terraform state; only the sensor IP is listed"
cat /etc/nsm/never-block.local
