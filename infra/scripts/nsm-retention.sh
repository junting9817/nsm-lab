#!/usr/bin/env bash
# Runs hourly (nsm-retention.timer): rotate Suricata EVE and delete old raw logs and PCAPs, to keep the disk from filling.
# setup-sensor-host.sh copies it to /usr/local/sbin/nsm-retention and it runs as root.
# (A root timer executing a script in a user's home directory would be a privilege-escalation path, hence the copy.)
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LOG_ROOT="${LOG_ROOT:-/data/logs}"
PCAP_DIR="${PCAP_DIR:-/data/pcap}"
LOG_KEEP_MIN="${LOG_KEEP_MIN:-2880}"   # raw logs for 48 h — headroom to reprocess after loading into ClickHouse
PCAP_KEEP_MIN="${PCAP_KEEP_MIN:-1440}" # PCAP for 24 h

log() { printf '[nsm-retention] %s\n' "$*"; }

# 1) Rotate Suricata eve.json: rename it, then SIGHUP makes Suricata open a new file.
#    Suricata keeps writing to the renamed file until the HUP, and Vector follows it to the end by file fingerprint.
eve="$LOG_ROOT/suricata/eve.json"
if [[ -s "$eve" ]] && [[ "$(docker inspect -f '{{.State.Running}}' nsm-suricata 2>/dev/null)" == true ]]; then
  rotated="$LOG_ROOT/suricata/eve.$(date -u +%Y%m%dT%H%M%SZ).json"
  mv "$eve" "$rotated"
  docker kill -s HUP nsm-suricata >/dev/null
  log "rotated: $rotated"
fi

# 2) Delete raw logs (Zeek rotates itself hourly to conn.YYYY-MM-DD-HH-MM-SS.log)
find "$LOG_ROOT/suricata" -maxdepth 1 -type f -name 'eve.*.json' -mmin "+$LOG_KEEP_MIN" -print -delete
find "$LOG_ROOT/zeek" -maxdepth 1 -type f -name '*.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-*.log' -mmin "+$LOG_KEEP_MIN" -print -delete
# Honeypot events pulled from the bucket (nsm-honeypot-pull appends to one file per UTC day)
if [[ -d "$LOG_ROOT/honeypot/cowrie" ]]; then
  find "$LOG_ROOT/honeypot/cowrie" -maxdepth 1 -type f -name 'cowrie-*.json' -mmin "+$LOG_KEEP_MIN" -print -delete
fi

# 3) Delete PCAPs (the size cap is enforced separately by Suricata's pcap-log limit × max-files)
find "$PCAP_DIR" -maxdepth 1 -type f -name 'log.pcap*' -mmin "+$PCAP_KEEP_MIN" -print -delete

df -h --output=target,pcent "$LOG_ROOT" | tail -1 | awk '{print "[nsm-retention] disk usage " $1 ": " $2}'
