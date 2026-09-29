#!/usr/bin/env bash
# Record an analyst verdict for alerts, the input of the FP-rate KPI (docs/kpi.md). The latest verdict per subject wins.
#
#   sudo detections/verdict.sh suricata  '<sid>|<src_ip>'  true_positive|false_positive  <TUNE-id|->  "<note>"
#   sudo detections/verdict.sh detection '<hit_key>'       true_positive|false_positive  <TUNE-id|->  "<note>"
#   sudo detections/verdict.sh --list
#
# A suricata subject covers every alert of that signature from that source; a detection subject is a hit_key
# (detection_id|src|dst|dst_port) from nsm.detection_hits. Values are passed as ClickHouse query parameters.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
die() { printf '[verdict] ERROR: %s\n' "$*" >&2; exit 2; }
ch() { docker exec nsm-clickhouse clickhouse-client "$@"; } # no -i: an INSERT would wait for data on stdin

if [[ "${1:-}" == "--list" ]]; then
  ch --format PrettyCompactMonoBlock -q "
    SELECT source, subject, argMax(verdict, created_at) AS verdict, argMax(tune_id, created_at) AS tune, argMax(analyst, created_at) AS analyst,
           max(created_at) AS decided, argMax(note, created_at) AS note
    FROM nsm.verdicts GROUP BY source, subject ORDER BY decided DESC"
  exit 0
fi

[[ $# -eq 5 ]] || die "usage: $0 suricata|detection <subject> true_positive|false_positive <TUNE-id|-> \"<note>\""
source="$1" subject="$2" verdict="$3" tune="$4" note="$5"
case "$source" in
  suricata) [[ "$subject" =~ ^[0-9]+\|[0-9A-Fa-f.:]+$ ]] || die "suricata subject must be <sid>|<src_ip>" ;;
  detection) [[ "$subject" =~ ^DET-[0-9]{3}\|[^|]*\|[^|]*\|[0-9]+$ ]] || die "detection subject must be a hit_key DET-nnn|src|dst|port" ;;
  *) die "source must be suricata or detection" ;;
esac
[[ "$verdict" == true_positive || "$verdict" == false_positive ]] || die "verdict must be true_positive or false_positive"
[[ "$tune" == - || "$tune" =~ ^TUNE-[0-9]{3}$ ]] || die "tune id must be TUNE-nnn or -"
[[ -n "$note" ]] || die "a note is required"
[[ "$tune" == - ]] && tune=""

ch --param_source="$source" --param_subject="$subject" --param_verdict="$verdict" --param_tune="$tune" \
   --param_note="$note" --param_analyst="${SUDO_USER:-$(id -un)}" -q "
  INSERT INTO nsm.verdicts (source, subject, verdict, analyst, tune_id, note)
  VALUES ({source:String}, {subject:String}, {verdict:String}, {analyst:String}, {tune:String}, {note:String})"
printf '[verdict] %s %s → %s%s\n' "$source" "$subject" "$verdict" "${tune:+ ($tune)}"
