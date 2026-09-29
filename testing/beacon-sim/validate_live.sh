#!/usr/bin/env bash
# Live validation of DET-101 with the beacon simulator, through the production pipeline
# (ens4 → Zeek → Vector → ClickHouse nsm.zeek_conn).
#
#   sudo systemd-run --unit nsm-beacon-live --collect testing/beacon-sim/validate_live.sh   # ~35 min, survives logout
#   journalctl -u nsm-beacon-live -f
#
# Runs two beacons back to back against the sensor's own external IP and checks each window separately:
#   low jitter  (±20%) → DET-101 must report the pair
#   high jitter (±90%) → DET-101 must not report the pair
# Avoid other requests from this VM to its external IP while it runs: they would join the same pair.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INTERVAL="${INTERVAL:-15}"
COUNT="${COUNT:-60}"
SETTLE_SECS="${SETTLE_SECS:-45}" # Zeek writes conn.log at connection end; Vector batches for up to 5 s

log() { printf '[beacon-live] %s\n' "$*"; }

src="$(ip -4 -o addr show dev ens4 | awk '{split($4, a, "/"); print a[1]}')"
ext="$(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)"
log "pair under test: $src -> $ext:80, interval ${INTERVAL}s, ${COUNT} check-ins per run"

failed=0
run_case() {
  local name="$1" jitter="$2" expect="$3" result summary rows
  summary="$(python3 "$REPO/testing/beacon-sim/beacon.py" --interval "$INTERVAL" --jitter "$jitter" --count "$COUNT" --seed 7)"
  log "$name: $summary"
  sleep "$SETTLE_SECS"
  local from to
  from="$(jq -r .started_at <<<"$summary" | cut -c1-19)"
  to="$(date -u -d "$(jq -r .ended_at <<<"$summary" | cut -c1-19) UTC + 1 minute" '+%Y-%m-%d %H:%M:%S')"
  rows="$("$REPO/detections/run.sh" DET-101 --from "$from" --to "$to" --format JSONEachRow |
    jq -c --arg s "$src" --arg d "$ext" 'select(.src == $s and .dst == $d and .dst_port == 80)')"
  if [[ "$expect" == flag && -n "$rows" ]] || [[ "$expect" == no_flag && -z "$rows" ]]; then
    result=PASS
  else
    result=FAIL
    failed=$((failed + 1))
  fi
  # Report the score either way (lower min_score to see a pair that was not reported)
  local detail
  detail="$("$REPO/detections/run.sh" DET-101 --from "$from" --to "$to" --set min_score=0 --format JSONEachRow |
    jq -c --arg s "$src" --arg d "$ext" 'select(.src == $s and .dst == $d and .dst_port == 80) | {score, conns, median_interval_sec, mad_interval_sec, interval_cv, ts_score, cv_score, size_score}')"
  log "$name: expect=$expect result=$result window=[$from, $to) detail=${detail:-none}"
}

run_case low-jitter 0.2 flag
run_case high-jitter 0.9 no_flag

log "$((2 - failed))/2 PASS"
((failed == 0))
