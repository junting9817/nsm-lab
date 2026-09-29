#!/usr/bin/env bash
# Validation harness for the behavior-based detections (DET-101..109).
#
#   sudo testing/detections/validate.sh
#
# 1. Build synthetic scenarios (fixtures.py) — positive and negative hosts per detection, one synthetic day
# 2. Analyze the PCAP with offline Zeek using the production site config (sensors/zeek/nsm-local.zeek)
# 3. Recreate database nsm_test from the production Zeek table DDL, without TTL
#    (the fixture day is in the past, so a 30-day TTL would delete it)
# 4. Load the Zeek logs with the same field mapping as Vector, and the test allowlist
# 5. Run every detection SQL against nsm_test and compare with the expected hosts
# Exit code 0 only when every host check passes. Production tables are never touched.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/testing/detections"
DB=nsm_test
ZEEK_IMAGE="$(awk '/^  zeek:/{f=1} f && /image:/{print $2; exit}' "$REPO/docker-compose.yml")"

die() { printf '[detections] ERROR: %s\n' "$*" >&2; exit 2; }
log() { printf '[detections] %s\n' "$*"; }
[[ $EUID -eq 0 ]] || die "run as root: sudo $0"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 0755 "$WORK"

log "1/5 building fixtures"
python3 "$HERE/fixtures.py" "$WORK"
chmod 0644 "$WORK/fixtures.pcap"

log "2/5 offline Zeek ($ZEEK_IMAGE, production site config)"
# Two test-only overrides:
#   Log::default_rotation_interval=0secs         one log file per type instead of hourly rotation on the fixture day
#   Site::private_address_space_is_local=F       Zeek's private_address_space includes the RFC 5737 documentation
#                                                ranges the fixtures use for external peers, which would otherwise make
#                                                every peer "local". The fixture hosts (10.200.0.0/16) stay local via
#                                                Site::local_nets += 10.128.0.0/9 in the site config.
mkdir -m 0777 "$WORK/zeek"
docker run --rm --memory 768m -v "$REPO/sensors/zeek:/nsm/zeek:ro" -v "$WORK:/w" -w /w/zeek "$ZEEK_IMAGE" \
  zeek -C -r /w/fixtures.pcap /nsm/zeek/nsm-local.zeek \
  'Log::default_rotation_interval=0secs' 'Site::private_address_space_is_local=F' >/dev/null

log "3/5 recreating database $DB"
ch() { docker exec -i nsm-clickhouse clickhouse-client --multiquery; }
printf 'DROP DATABASE IF EXISTS %s; CREATE DATABASE %s;\n' "$DB" "$DB" | ch
for ddl in "$REPO"/ingest/clickhouse/schema/00[2-7]_zeek_*.sql "$REPO"/ingest/clickhouse/schema/011_zeek_ssl_fingerprints.sql; do
  sed -E "s/\bnsm\./${DB}./g; /^TTL /d; s/^SETTINGS ttl_only_drop_parts = 1;/;/" "$ddl" | ch
done

log "   syncing test allowlist (active, expired and disabled entries)"
"$REPO/detections/sync-allowlist.sh" --db "$DB" --file "$HERE/allowlist.tsv" >/dev/null

log "4/5 loading Zeek logs"
python3 "$HERE/harness.py" load "$WORK/zeek" "$DB"

log "5/5 running detections"
python3 "$HERE/harness.py" check "$WORK/expectations.json" "$DB"
