#!/usr/bin/env bash
# Monthly (nsm-geoip-update.timer): download DB-IP Lite country and ASN databases for honeypot enrichment.
# setup-honeypot-ingest.sh copies it to /usr/local/sbin/nsm-geoip-update and it runs as root.
#
# Source: https://db-ip.com/db/lite.php — IP to Country Lite and IP to ASN Lite, MMDB format, CC BY 4.0
# (attribution is shown on the Honeypot dashboard). No account or license key is needed.
#
# A database is replaced only after it decompresses cleanly and carries the MMDB metadata marker, then Vector
# is restarted so its enrichment tables load the new files. Exit code 0 also when nothing changed.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

GEOIP_DIR="${GEOIP_DIR:-/data/geoip}"
RESTART_VECTOR="${RESTART_VECTOR:-1}" # 0 for test runs into another directory
MIN_BYTES=1000000

log() { printf '[nsm-geoip-update] %s\n' "$*"; }
die() { printf '[nsm-geoip-update] ERROR: %s\n' "$*" >&2; exit 1; }

install -d -m 0755 "$GEOIP_DIR"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

changed=0
for db in country asn; do
  dest="$GEOIP_DIR/dbip-$db-lite.mmdb"
  got=""
  # The new month's file is published during the month; fall back to the previous one.
  for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 day" +%Y-%m)"; do
    url="https://download.db-ip.com/free/dbip-$db-lite-$month.mmdb.gz"
    if curl -fsS --max-time 300 --retry 3 -o "$work/$db.mmdb.gz" "$url"; then
      got="$month"
      break
    fi
  done
  [[ -n "$got" ]] || die "could not download dbip-$db-lite for this or last month"

  gzip -dc "$work/$db.mmdb.gz" >"$work/$db.mmdb" || die "dbip-$db-lite-$got: corrupt gzip"
  size="$(stat -c %s "$work/$db.mmdb")"
  ((size >= MIN_BYTES)) || die "dbip-$db-lite-$got: only $size bytes"
  # Every MMDB file ends with a metadata section that starts with this marker.
  LC_ALL=C grep -aq $'\xab\xcd\xefMaxMind.com' "$work/$db.mmdb" || die "dbip-$db-lite-$got: no MMDB metadata marker"

  if [[ -f "$dest" ]] && cmp -s "$work/$db.mmdb" "$dest"; then
    log "dbip-$db-lite unchanged ($got)"
    continue
  fi
  install -m 0644 "$work/$db.mmdb" "$dest.new"
  mv -f "$dest.new" "$dest"
  printf '%s\n' "$got" >"$GEOIP_DIR/dbip-$db-lite.version"
  log "installed dbip-$db-lite-$got ($size bytes)"
  changed=1
done

if ((changed)) && [[ "$RESTART_VECTOR" == 1 ]] && [[ "$(docker inspect -f '{{.State.Running}}' nsm-vector 2>/dev/null)" == true ]]; then
  docker restart nsm-vector >/dev/null
  log "restarted nsm-vector to load the new databases"
fi
