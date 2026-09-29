#!/usr/bin/env bash
# Checks the Zeek JA3/JA4 implementation (sensors/zeek/scripts/ja3-ja4.zeek) against Suricata 8's built-in JA3/JA4 on the same PCAP.
#
#   sudo testing/fingerprints/crosscheck.sh [pcap]    # default: the newest finished file in /data/pcap
#
# How: run both engines offline (-r) with the production images → pair the same flow via Zeek ssl.log (uid) ↔ conn.log (community_id) ↔ Suricata EVE tls (community_id)
# and compare the ja3 hash and ja4 string.
# The known deviation (Suricata 8.0.6 appends "_" to JA4_c before hashing for a ClientHello without signature algorithms) is recomputed
# the Suricata way from the raw JA4 (ja4_r) Zeek logged, and counted separately only when it is exactly that case.
# Fails (exit code 1) if any mismatch is unexplained or nothing was compared.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ZEEK_IMAGE="$(awk '/^  zeek:/{f=1} f && /image:/{print $2; exit}' "$REPO/docker-compose.yml")"
SURICATA_IMAGE="$(awk '/^  suricata:/{f=1} f && /image:/{print $2; exit}' "$REPO/docker-compose.yml")"

die() { printf '[crosscheck] ERROR: %s\n' "$*" >&2; exit 2; }
[[ $EUID -eq 0 ]] || die "root required: sudo $0 [pcap]"

# Without an argument, skip the newest file Suricata may still be writing and use the one before it
pcap="${1:-$(find /data/pcap -maxdepth 1 -name 'log.pcap.*' -printf '%T@ %p\n' | sort -rn | sed -n 2p | cut -d' ' -f2)}"
[[ -f "$pcap" ]] || die "no such PCAP: $pcap"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$pcap" "$WORK/in.pcap"
mkdir -m 0777 "$WORK/zeek" "$WORK/suricata"
chmod 0755 "$WORK" && chmod 0644 "$WORK/in.pcap"

docker run --rm --memory 768m -v "$REPO/sensors/zeek:/nsm/zeek:ro" -v "$WORK:/w" -w /w/zeek "$ZEEK_IMAGE" \
  zeek -C -r /w/in.pcap tuning/json-logs policy/protocols/conn/community-id-logging /nsm/zeek/scripts/ja3-ja4.zeek \
  NSMFingerprint::log_ja4_raw=T >/dev/null

docker run --rm --memory 1536m -v "$WORK:/w" --entrypoint suricata "$SURICATA_IMAGE" \
  -c /etc/suricata.dist/suricata.yaml -S /dev/null -k none -r /w/in.pcap -l /w/suricata \
  --set app-layer.protocols.tls.ja3-fingerprints=yes --set app-layer.protocols.tls.ja4-fingerprints=yes \
  --set outputs.1.eve-log.community-id=true >/dev/null 2>&1

[[ -s "$WORK/zeek/ssl.log" ]] || die "Zeek ssl.log is empty (no TLS sessions in the PCAP?)"

exec python3 "$REPO/testing/fingerprints/compare.py" "$WORK"
