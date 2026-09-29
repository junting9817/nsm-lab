#!/usr/bin/env bash
# PCAP validation harness: replays each PCAP in cases.json onto the dummy interface and compares the alerts
# actually loaded by the production pipeline (Suricata → Vector → ClickHouse) with the expected SIDs.
#
#   sudo testing/validate.sh              # all cases
#   sudo testing/validate.sh <case name>  # one case
#
# Verdict: PASS if every expected SID shows up in ClickHouse within the time limit. Unexpected alerts are only reported.
# Results are printed as a table and written to nsm.validation_runs (basis for MTTD, docs/kpi.md).
# Exit code: 0 if every case passes, 1 if any case fails.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASES_FILE="${CASES_FILE:-$HERE/pcap/cases.json}"
IFACE="${REPLAY_IFACE:-nsm-replay0}"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"
SETTLE_SECS="${SETTLE_SECS:-5}" # wait for late alerts after the last expected one (so they do not mix into the next case)
RULES_FILE=/data/suricata/rules/suricata.rules

die() { printf '[validate] ERROR: %s\n' "$*" >&2; exit 2; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# Queries do not use -i: reading stdin would also swallow the case loop's input
ch() { docker exec nsm-clickhouse clickhouse-client --query "$1" </dev/null; }

[[ $EUID -eq 0 ]] || die "root required: sudo $0"
command -v jq >/dev/null || die "jq required"
[[ "$(docker inspect -f '{{.State.Health.Status}}' nsm-suricata 2>/dev/null)" == healthy ]] || die "nsm-suricata is not healthy"

only="${1:-}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
ruleset_sha="$(sha256sum "$RULES_FILE" | cut -d' ' -f1)"
rules_loaded="$(docker exec nsm-suricata suricatasc -c ruleset-stats | jq -r '.message[0].rules_loaded')"

printf '[validate] run=%s  rules_loaded=%s  ruleset=%s\n\n' "$run_id" "$rules_loaded" "${ruleset_sha:0:12}"
printf '%-30s %-10s %-6s %8s %9s  %-24s %s\n' CASE ATT\&CK RESULT MTTD VISIBLE MISSING UNEXPECTED

total="$(jq '.cases | length' "$CASES_FILE")"
failed=0
ran=0
# Read the case list on fd 3 (so commands in the loop that read stdin cannot consume it)
while read -r case_json <&3; do
  name="$(jq -r .name <<<"$case_json")"
  [[ -z "$only" || "$only" == "$name" ]] || continue
  ran=$((ran + 1))

  pcap="$HERE/pcap/$(jq -r .pcap <<<"$case_json")"
  [[ -f "$pcap" ]] || die "$name: PCAP missing ($pcap) — python3 testing/pcap/generate_samples.py"
  technique="$(jq -r .attack_technique <<<"$case_json")"
  primary="$(jq -r .primary_sid <<<"$case_json")"
  expected="$(jq -c '.expect_sids | sort' <<<"$case_json")"
  expected_csv="$(jq -r 'join(",")' <<<"$expected")"

  # New client ports on every run make it a new flow (so it does not attach to the previous replay's closed session, see uniquify.py)
  replay_pcap="$WORK/$name.pcap"
  python3 "$HERE/pcap/uniquify.py" "$pcap" "$replay_pcap"

  start_us="$(date +%s%6N)"
  "$HERE/pcap/replay.sh" "$replay_pcap" >/dev/null

  # Wait until every expected SID is loaded
  detected='[]'
  visible_us=""
  deadline=$(($(date +%s) + TIMEOUT_SECS))
  while (($(date +%s) < deadline)); do
    detected="$(ch "SELECT toJSONString(arraySort(groupUniqArray(alert_signature_id))) FROM nsm.suricata_alert WHERE in_iface = '$IFACE' AND timestamp >= fromUnixTimestamp64Micro($start_us)")"
    if jq -e --argjson e "$expected" --argjson d "$detected" '($e - $d) | length == 0' <<<'null' >/dev/null; then
      visible_us="$(date +%s%6N)"
      break
    fi
    sleep 1
  done

  # Collect late alerts too, then decide
  sleep "$SETTLE_SECS"
  detected="$(ch "SELECT toJSONString(arraySort(groupUniqArray(alert_signature_id))) FROM nsm.suricata_alert WHERE in_iface = '$IFACE' AND timestamp >= fromUnixTimestamp64Micro($start_us)")"
  first_alert_us="$(ch "SELECT toUnixTimestamp64Micro(min(timestamp)) FROM nsm.suricata_alert WHERE in_iface = '$IFACE' AND timestamp >= fromUnixTimestamp64Micro($start_us) AND alert_signature_id IN ($expected_csv)")"
  missing="$(jq -c --argjson e "$expected" --argjson d "$detected" -n '$e - $d')"
  unexpected="$(jq -c --argjson e "$expected" --argjson d "$detected" -n '$d - $e')"

  if [[ "$missing" == "[]" ]]; then
    result=PASS
    mttd_ms=$(((first_alert_us - start_us) / 1000))
    visible_ms=$(((visible_us - start_us) / 1000))
  else
    result=FAIL
    failed=$((failed + 1))
    mttd_ms=null
    visible_ms=null
  fi

  printf '%-30s %-10s %-6s %8s %9s  %-24s %s\n' "$name" "$technique" "$result" \
    "$([[ $mttd_ms == null ]] && echo - || echo "${mttd_ms}ms")" \
    "$([[ $visible_ms == null ]] && echo - || echo "${visible_ms}ms")" \
    "$(jq -r 'if length == 0 then "-" else join(",") end' <<<"$missing")" \
    "$(jq -r 'if length == 0 then "-" else join(",") end' <<<"$unexpected")"

  jq -nc \
    --arg run_id "$run_id" --arg case_name "$name" --arg pcap "$(jq -r .pcap <<<"$case_json")" \
    --arg pcap_sha256 "$(sha256sum "$pcap" | cut -d' ' -f1)" --arg attack_technique "$technique" \
    --argjson primary_sid "$primary" --argjson started_us "$start_us" \
    --argjson expected "$expected" --argjson detected "$detected" --argjson missing "$missing" --argjson unexpected "$unexpected" \
    --argjson first_alert_us "$([[ $result == PASS ]] && echo "$first_alert_us" || echo null)" \
    --argjson mttd_ms "$mttd_ms" --argjson visible_ms "$visible_ms" --arg result "$result" \
    --arg ruleset_sha256 "$ruleset_sha" --argjson rules_loaded "$rules_loaded" \
    'def ts6: (. / 1000000 | floor | strftime("%Y-%m-%d %H:%M:%S")) + "." + ((. % 1000000) | tostring | if length < 6 then ("0" * (6 - length)) + . else . end);
     {run_id: $run_id, case_name: $case_name, pcap: $pcap, pcap_sha256: $pcap_sha256, attack_technique: $attack_technique,
      primary_sid: $primary_sid, started_at: ($started_us | ts6), expected_sids: $expected, detected_sids: $detected,
      missing_sids: $missing, unexpected_sids: $unexpected,
      first_alert_at: (if $first_alert_us == null then null else ($first_alert_us | ts6) end),
      mttd_ms: $mttd_ms, visible_ms: $visible_ms, result: $result, ruleset_sha256: $ruleset_sha256, rules_loaded: $rules_loaded}' |
    docker exec -i nsm-clickhouse clickhouse-client --query "INSERT INTO nsm.validation_runs FORMAT JSONEachRow"
done 3< <(jq -c '.cases[]' "$CASES_FILE")

((ran > 0)) || die "no case ran (check the name: $only)"
# A full run that did not run every defined case cannot be trusted
if [[ -z "$only" ]] && ((ran != total)); then
  printf '[validate] ERROR: %d cases defined but only %d ran\n' "$total" "$ran" >&2
  exit 1
fi
printf '\n[validate] %d/%d PASS  (results: nsm.validation_runs run_id=%s)\n' "$((ran - failed))" "$ran" "$run_id"
((failed == 0))
