#!/usr/bin/env bash
# Scheduled behavior detections (Phase 7): hourly run of every DET-*.sql into nsm.detection_hits. Idempotent.
#
#   sudo infra/scripts/setup-detections.sh
#
# The timer runs as root, so it executes a root-owned copy in /usr/local/lib/nsm/detections instead of the repository
# (same reason as nsm-retention). Re-run this script after changing detections/sql, run.sh or schedule.py.
source "$(dirname "$0")/lib.sh"
require_root

DEST=/usr/local/lib/nsm/detections
install -d -m 0755 -o root -g root "$DEST" "$DEST/sql"
install -m 0755 -o root -g root "$REPO_ROOT/detections/run.sh" "$REPO_ROOT/detections/schedule.py" "$DEST/"
# Replace the SQL set as a whole so a removed detection stops running too.
rm -f "$DEST"/sql/DET-*.sql
install -m 0644 -o root -g root "$REPO_ROOT"/detections/sql/DET-*.sql "$DEST/sql/"

units_changed=0
if write_if_changed /etc/systemd/system/nsm-detections.service 0644 <<EOF_UNIT
[Unit]
Description=Run NSM behavior detections and store the results (nsm.detection_hits)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$DEST/schedule.py
TimeoutStartSec=900
EOF_UNIT
then
  units_changed=1
fi
if write_if_changed /etc/systemd/system/nsm-detections.timer 0644 <<'EOF_UNIT'
[Unit]
Description=Run NSM behavior detections hourly

[Timer]
OnCalendar=*-*-* *:07:00
Persistent=true

[Install]
WantedBy=timers.target
EOF_UNIT
then
  units_changed=1
fi
((units_changed)) && systemctl daemon-reload
systemctl enable --now nsm-detections.timer >/dev/null 2>&1

log "installed $(find "$DEST/sql" -name 'DET-*.sql' | wc -l) detections to $DEST"
systemctl show nsm-detections.timer -p ActiveState -p NextElapseUSecRealtime | paste -sd' '
