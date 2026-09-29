#!/usr/bin/env bash
# ET Open rule update (nsm-rules-update.timer, daily). setup-sensor-host.sh copies it to /usr/local/sbin/nsm-rules-update
# and it runs as root.
#
# 1) Run suricata-update in a one-off container, separate from the sensor (download rules + suricata -T check)
#    — inside the sensor container the test step would share the sensor's 1.5 GiB memory limit and could OOM-kill it
# 2) Restart the sensor only when the rule file actually changed
#    — a live reload builds a second detection engine and briefly doubles memory (docs/architecture.md section 3)
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SENSOR=nsm-suricata
RULES_DIR=/data/suricata
RULES_FILE="$RULES_DIR/rules/suricata.rules"
FILTER_DIR=/etc/nsm/suricata-update

log() { printf '[nsm-rules-update] %s\n' "$*"; }
die() { printf '[nsm-rules-update] ERROR: %s\n' "$*" >&2; exit 1; }

# Validate with the same image as the sensor (same Suricata version) so rule compatibility is judged correctly.
# On a first install the sensor may not exist yet; pass SURICATA_IMAGE then.
image="${SURICATA_IMAGE:-$(docker inspect -f '{{.Config.Image}}' "$SENSOR" 2>/dev/null || true)}"
[[ -n "$image" ]] || die "no $SENSOR container. Pass SURICATA_IMAGE=<image>"

before="$(sha256sum "$RULES_FILE" 2>/dev/null | cut -d' ' -f1 || true)"

docker run --rm --name nsm-rules-update \
  --memory 1536m --memory-swap 1536m \
  -v "$RULES_DIR:/var/lib/suricata" \
  -v "$FILTER_DIR:/nsm/update:ro" \
  "$image" suricata-update --no-reload --fail \
  --disable-conf /nsm/update/disable.conf \
  --enable-conf /nsm/update/enable.conf \
  --modify-conf /nsm/update/modify.conf

after="$(sha256sum "$RULES_FILE" | cut -d' ' -f1)"
enabled="$(grep -cE '^(alert|drop|pass|reject)' "$RULES_FILE")"

if [[ "$before" == "$after" ]]; then
  log "no change ($enabled rules enabled)"
  exit 0
fi

if ! docker inspect "$SENSOR" >/dev/null 2>&1; then
  log "rules ready ($enabled rules enabled). No sensor container, so no restart"
  exit 0
fi

log "rules changed ($enabled rules enabled, sha256 ${after:0:12}) → restarting sensor"
docker restart "$SENSOR" >/dev/null
for _ in $(seq 1 60); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$SENSOR")" == healthy ]] && { log "sensor healthy"; exit 0; }
  sleep 5
done
die "sensor did not become healthy within 5 minutes: docker logs $SENSOR"
