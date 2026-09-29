#!/usr/bin/env bash
# Replays a PCAP onto the dummy interface (nsm-replay0).
#
#   sudo testing/pcap/replay.sh <pcap> [tcpreplay speed option, default --mbps=10]
#
# Safety: refuses any target interface that is not of type dummy. Packets sent to a dummy go nowhere, so
# replay traffic never leaks out of the VM (internet or VPC); only the production Suricata capturing that interface sees it.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

IFACE="${REPLAY_IFACE:-nsm-replay0}"

die() { printf '[replay] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "root required: sudo $0 <pcap>"
[[ $# -ge 1 ]] || die "usage: sudo $0 <pcap> [tcpreplay speed option]"
pcap="$1"
shift
[[ -f "$pcap" ]] || die "no such file: $pcap"
rate=("$@")
((${#rate[@]})) || rate=(--mbps=10)

ip -d link show dev "$IFACE" >/dev/null 2>&1 || die "$IFACE missing — sudo infra/scripts/setup-sensor-host.sh"
ip -d link show dev "$IFACE" | grep -qw dummy || die "$IFACE is not a dummy interface. Never replay onto a real NIC."
ip link show dev "$IFACE" | grep -q '[<,]UP[,>]' || die "$IFACE is down"
[[ "$(docker inspect -f '{{.State.Running}}' nsm-suricata 2>/dev/null)" == true ]] || die "nsm-suricata is not running"

tcpreplay --intf1="$IFACE" "${rate[@]}" "$pcap" 2>&1 | grep -E 'Actual:|Failed packets:' | sed "s|^|[replay] $(basename "$pcap"): |"
