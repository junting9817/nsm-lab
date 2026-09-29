#!/usr/bin/env bash
# Analyst path for the automated response (Phase 6): block, release or list through the running responder,
# so manual actions go through the same policy (never-block list, caps) and the same audit table.
#
#   sudo response/firewall/nsm-response.sh block   <ip> <ttl: 30m|6h|2d> "<reason>"
#   sudo response/firewall/nsm-response.sh release <ip> "<reason>" [suppress: 30m|6h|2d]
#   sudo response/firewall/nsm-response.sh list
#
# The reconciler applies changes to the nsm-blocklist firewall rule within 30 s (in enforce mode).
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

usage() { sed -n '5,7p' "$0" | sed 's/^# *//' >&2; exit 2; }
actor="${SUDO_USER:-$(id -un)}"
run() { docker exec nsm-responder python3 /app/responder.py "$@"; }

case "${1:-}" in
  block)
    [[ $# -eq 4 ]] || usage
    run block "$2" --ttl "$3" --reason "$4" --actor "$actor"
    ;;
  release)
    [[ $# -eq 3 || $# -eq 4 ]] || usage
    if [[ $# -eq 4 ]]; then
      run release "$2" --reason "$3" --suppress "$4" --actor "$actor"
    else
      run release "$2" --reason "$3" --actor "$actor"
    fi
    ;;
  list)
    run list
    ;;
  *)
    usage
    ;;
esac
