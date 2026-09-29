#!/usr/bin/env bash
# End-to-end honeypot check from the sensor VM: attack our own honeypot, then prove the events arrived and the egress policy holds.
#
#   sudo testing/honeypot/validate.sh
#
# Target: only the honeypot this project created — its IP and stage are read from the local Terraform state
# (terraform output), never from arguments. Traffic: 3 SSH logins and one command against Cowrie.
#
# Checks:
#   1. 22/tcp answers with Cowrie's configured SSH banner (not a real sshd)
#   2. login.failed ×2, login.success and command.input for this run reach nsm.cowrie_events (bucket → pull → Vector)
#   3. src_ip is the sensor's external IP (Docker's port publishing kept the real source) and country/ASN are filled
#   4. egress: the accepted session runs `wget http://<sensor external IP>/nsm-honeypot-egress-<run>`, a URL on our own
#      sensor, where Zeek is the witness. bootstrap stage (egress open): the request must appear in nsm.zeek_http
#      (positive control). live stage (egress denied): it must not appear within the wait window.
# shellcheck disable=SC2015 # result() always returns 0, so "cond && result PASS || result FAIL" never runs both
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
EVENT_TIMEOUT="${EVENT_TIMEOUT:-360}"  # honeypot batch 60 s + pull timer 60 s + Vector, with margin
EGRESS_WAIT="${EGRESS_WAIT:-120}"
COWRIE_BANNER="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3" # [ssh] version default in Cowrie 3.0.14

log() { printf '[honeypot-validate] %s\n' "$*"; }
die() { printf '[honeypot-validate] ERROR: %s\n' "$*" >&2; exit 1; }
ch() { docker exec nsm-clickhouse clickhouse-client "$@"; }

[[ $EUID -eq 0 ]] || die "root required: sudo $0"

tf=(terraform -chdir="$REPO_ROOT/infra/terraform" output -raw)
honeypot_ip="$("${tf[@]}" honeypot_external_ip 2>/dev/null)" || die "no honeypot_external_ip in Terraform state — apply infra/terraform first"
stage="$("${tf[@]}" honeypot_stage 2>/dev/null)" || die "no honeypot_stage in Terraform state"
[[ "$honeypot_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "unexpected honeypot IP: $honeypot_ip"
sensor_ip="$(curl -fsS -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' ')"
marker="nsm-validate-$run_id"
egress_path="/nsm-honeypot-egress-$run_id"

log "honeypot $honeypot_ip (stage: $stage), source $sensor_ip, run $run_id"
failed=0
result() { # <PASS|FAIL> <check> <detail>
  printf '  %-4s  %-34s %s\n' "$1" "$2" "$3"
  [[ "$1" == PASS ]] || failed=1
  return 0
}

# --- 1) banner ---------------------------------------------------------------------------------------------------
banner="$(timeout 10 bash -c "exec 3<>/dev/tcp/$honeypot_ip/22 && head -n1 <&3" 2>/dev/null | tr -d '\r' || true)"
[[ "$banner" == "$COWRIE_BANNER" ]] && result PASS "Cowrie banner on 22/tcp" "$banner" || result FAIL "Cowrie banner on 22/tcp" "got '${banner:-nothing}'"

# --- 2) attack our honeypot --------------------------------------------------------------------------------------
start_epoch="$(date +%s.%N)"
start_ch="$(date -u -d "@${start_epoch%.*}" '+%Y-%m-%d %H:%M:%S')"
"$HERE/ssh_attempts.sh" "$honeypot_ip" 22 "$run_id" "wget -q -O /dev/null http://$sensor_ip$egress_path" >/dev/null 2>&1 || true
log "attempts sent; waiting up to ${EVENT_TIMEOUT}s for events"

query_events() {
  ch --param_src="$sensor_ip" --param_start="$start_ch" --param_marker="$marker" --format TSV -q "
    SELECT
      countIf(eventid = 'cowrie.login.failed' AND username = 'root' AND password IN ('root', '123456')),
      countIf(eventid = 'cowrie.login.success' AND password = {marker:String}),
      countIf(eventid = 'cowrie.command.input' AND position(input, {marker:String}) > 0),
      anyIf(src_country_code, eventid = 'cowrie.login.success' AND password = {marker:String}),
      anyIf(src_asn, eventid = 'cowrie.login.success' AND password = {marker:String}),
      maxIf(timestamp, password = {marker:String} OR position(input, {marker:String}) > 0)
    FROM nsm.cowrie_events
    WHERE timestamp >= toDateTime64({start:String}, 6, 'UTC') - INTERVAL 5 SECOND AND src_ip = {src:String}"
}

deadline=$((SECONDS + EVENT_TIMEOUT))
while :; do
  IFS=$'\t' read -r failed_n success_n command_n cc asn _ < <(query_events)
  if ((failed_n >= 2 && success_n >= 1 && command_n >= 1)) || ((SECONDS >= deadline)); then
    break
  fi
  sleep 10
done
visible_s="$(awk -v s="$start_epoch" -v e="$(date +%s.%N)" 'BEGIN { printf "%.0f", e - s }')"

((failed_n >= 2)) && result PASS "login.failed (root/root, root/123456)" "$failed_n rows" || result FAIL "login.failed (root/root, root/123456)" "$failed_n rows"
((success_n >= 1)) && result PASS "login.success ($marker)" "$success_n rows, visible after ~${visible_s}s" || result FAIL "login.success" "$success_n rows after ${EVENT_TIMEOUT}s"
((command_n >= 1)) && result PASS "command.input with marker" "$command_n rows" || result FAIL "command.input with marker" "$command_n rows"
((success_n >= 1)) && result PASS "source IP preserved" "src_ip = $sensor_ip" || result FAIL "source IP preserved" "no rows with src_ip = $sensor_ip"
[[ -n "$cc" && "${asn:-0}" != 0 ]] && result PASS "GeoIP enrichment" "country $cc, AS$asn" || result FAIL "GeoIP enrichment" "country '${cc:-}', asn '${asn:-}'"

# --- 3) egress policy, witnessed by Zeek on our own sensor ---------------------------------------------------------
query_egress() {
  ch --param_src="$honeypot_ip" --param_start="$start_ch" --param_uri="$egress_path" --format TSV -q "
    SELECT count() FROM nsm.zeek_http
    WHERE ts >= toDateTime64({start:String}, 6, 'UTC') - INTERVAL 5 SECOND AND uri = {uri:String} AND id_orig_h = {src:String}"
}
deadline=$((SECONDS + EGRESS_WAIT))
while :; do
  seen="$(query_egress)"
  if [[ "$seen" != 0 && "$stage" == bootstrap ]] || ((SECONDS >= deadline)); then
    break
  fi
  sleep 10
done
if [[ "$stage" == bootstrap ]]; then
  [[ "$seen" != 0 ]] && result PASS "egress open (bootstrap control)" "Zeek saw $egress_path from $honeypot_ip" \
                     || result FAIL "egress open (bootstrap control)" "Zeek did not see the request — the check itself would be blind"
else
  [[ "$seen" == 0 ]] && result PASS "egress blocked (live)" "no request from $honeypot_ip within ${EGRESS_WAIT}s" \
                     || result FAIL "egress blocked (live)" "Zeek saw $seen request(s) from the honeypot"
fi

if ((failed)); then
  log "FAIL"
  exit 1
fi
log "PASS"
