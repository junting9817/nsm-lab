#!/usr/bin/env bash
# Responder validation without touching the firewall: a throwaway responder in RESPONDER_MODE=test on the nsm network,
# driven through its real webhook and CLI, with every decision checked in ClickHouse. Test rows are deleted at the end.
#
#   sudo testing/response/validate.sh
#   sudo KEEP_TEST_ROWS=1 testing/response/validate.sh   # keep mode='test' rows to inspect them (delete with a normal run)
#
# Synthetic attackers come from TEST-NET-3 (203.0.113.0/24), which only test mode accepts, so no real host is ever named.
# The never-block case uses the sensor's own external IP, which must always be refused.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NAME=nsm-responder-test
log() { printf '[response-validate] %s\n' "$*"; }
die() { printf '[response-validate] ERROR: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "root required: sudo $0"

image="$(docker inspect -f '{{.Config.Image}}' nsm-responder 2>/dev/null)" || die "nsm-responder is not running (setup-stack.sh)"
network="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' nsm-responder)"
sensor_ip="$(curl -fsS -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)"

secrets="$(mktemp -d)"
delete_test_rows() {
  docker exec nsm-clickhouse clickhouse-client --mutations_sync 1 -q "ALTER TABLE nsm.response_actions DELETE WHERE mode = 'test'" || true
  docker exec nsm-clickhouse clickhouse-client --mutations_sync 1 -q "ALTER TABLE nsm.response_applies DELETE WHERE mode = 'test'" || true
}
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$secrets"
  if [[ "${KEEP_TEST_ROWS:-0}" == 1 ]]; then
    log "KEEP_TEST_ROWS=1: mode='test' rows kept"
  else
    delete_test_rows
  fi
}
trap cleanup EXIT
leftover="$(docker exec nsm-clickhouse clickhouse-client -q "SELECT count() FROM nsm.response_actions WHERE mode = 'test'")"
[[ "$leftover" == 0 ]] || { log "removing $leftover leftover test rows"; delete_test_rows; }

# Secrets for the test container: the real ClickHouse password, a one-off webhook token.
grep -m1 '^CH_RESPONDER_PASSWORD=' "$REPO_ROOT/.env" | cut -d= -f2- >"$secrets/ch_responder_password"
token="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
printf '%s\n' "$token" >"$secrets/responder_webhook_token"
chmod 0755 "$secrets"; chmod 0444 "$secrets"/*

docker run -d --name "$NAME" --network "$network" --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 128m -e RESPONDER_MODE=test -e RECONCILE_SECONDS=3 -e PYTHONDONTWRITEBYTECODE=1 \
  -e NEVER_BLOCK_FILES=/etc/nsm/never-block.txt:/etc/nsm/never-block.local \
  -v "$REPO_ROOT/response/webhook:/app:ro" -v "$REPO_ROOT/response/never-block.txt:/etc/nsm/never-block.txt:ro" \
  -v /etc/nsm/never-block.local:/etc/nsm/never-block.local:ro -v "$secrets:/run/secrets:ro" \
  -w /app "$image" python3 /app/responder.py serve >/dev/null
for _ in $(seq 1 20); do
  docker exec "$NAME" python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)" 2>/dev/null && break
  sleep 1
done

# post <token> <json alerts array> → prints "HTTP <code> <body>"
post() {
  docker exec -i "$NAME" python3 -c '
import json, sys, urllib.request, urllib.error
token, alerts = sys.argv[1], sys.stdin.read()
req = urllib.request.Request("http://127.0.0.1:8080/grafana", data=json.dumps({"alerts": json.loads(alerts)}).encode(),
                             headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
try:
    r = urllib.request.urlopen(req, timeout=30); print("HTTP", r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read().decode())
' "$1" <<<"$2"
}
alert() { printf '{"status":"%s","labels":{"src_ip":"%s","nsm_trigger":"%s","alertname":"validate"},"startsAt":"2026-09-14T00:00:00Z"}' "$3" "$1" "$2"; }
rows() { docker exec nsm-clickhouse clickhouse-client --param_ip="$1" -q "SELECT action, reason, dateDiff('minute', created_at, expires_at) FROM nsm.response_actions WHERE mode = 'test' AND ip = {ip:String} ORDER BY created_at FORMAT TSV"; }

failed=0
check() { # <name> <expected> <actual>
  if [[ "$3" == *"$2"* ]]; then printf '  PASS  %-44s %s\n' "$1" "$(head -c 110 <<<"$3" | tr '\n\t' '; ')"
  else printf '  FAIL  %-44s expected %q, got %q\n' "$1" "$2" "$3"; failed=1; fi
}

check "wrong token is refused" "HTTP 401" "$(post wrong "[$(alert 203.0.113.10 suricata firing)]")"
post "$token" "[$(alert "$sensor_ip" honeypot firing)]" >/dev/null
check "never-block: sensor external IP" "reject	never-block: sensor external IP" "$(rows "$sensor_ip")"
post "$token" "[$(alert 10.1.2.3 suricata firing)]" >/dev/null
check "private address" "reject	not a public address" "$(rows 10.1.2.3)"
post "$token" "[$(alert 198.51.100.7 suricata firing)]" >/dev/null
check "documentation range outside TEST-NET-3" "reject	not a public address" "$(rows 198.51.100.7)"
post "$token" "[$(alert 2001:db8::1 suricata firing)]" >/dev/null
check "IPv6" "reject	not IPv4" "$(rows 2001:db8::1)"

post "$token" "[$(alert 203.0.113.10 suricata firing)]" >/dev/null
check "suricata block, 6 h" "block	suricata	360" "$(rows 203.0.113.10)"
post "$token" "[$(alert 203.0.113.10 suricata firing),$(alert 203.0.113.10 suricata resolved)]" >/dev/null
check "repeat notification + resolved: no new row" "1" "$(rows 203.0.113.10 | wc -l)"
post "$token" "[$(alert 203.0.113.11 scanner firing)]" >/dev/null
check "scanner is observe-only" "observe	trigger scanner is observe-only	60" "$(rows 203.0.113.11)"
post "$token" "[$(alert 203.0.113.12 honeypot firing)]" >/dev/null
check "honeypot block, 24 h" "block	honeypot	1440" "$(rows 203.0.113.12)"

sleep 6
check "reconciler list has both blocks" "['203.0.113.10/32','203.0.113.12/32']" \
  "$(docker exec nsm-clickhouse clickhouse-client -q "SELECT ranges FROM nsm.response_applies WHERE mode = 'test' ORDER BY applied_at DESC LIMIT 1")"

docker exec "$NAME" python3 /app/responder.py release 203.0.113.10 --reason "validate: analyst release" --suppress 1h --actor validate >/dev/null
post "$token" "[$(alert 203.0.113.10 suricata firing)]" >/dev/null
check "release suppresses re-block" "suppressed by an analyst release" "$(rows 203.0.113.10 | tail -1)"
sleep 6
check "reconciler removed the released IP" "['203.0.113.12/32']	[]	['203.0.113.10/32']" \
  "$(docker exec nsm-clickhouse clickhouse-client -q "SELECT ranges, added, removed FROM nsm.response_applies WHERE mode = 'test' ORDER BY applied_at DESC LIMIT 1 FORMAT TSV")"

docker exec "$NAME" python3 /app/responder.py release 203.0.113.12 --reason "validate: release without suppression" --actor validate >/dev/null
post "$token" "[$(alert 203.0.113.12 honeypot firing)]" >/dev/null
check "repeat offender: TTL x4 (96 h)" "block	honeypot, repeat offender ×4	5760" "$(rows 203.0.113.12 | tail -1)"

out="$(docker exec "$NAME" python3 /app/responder.py block 203.0.113.13 --ttl 30m --reason "validate: manual" --actor validate)"
check "manual block via CLI, 30 min, analyst reason kept" "block	manual: validate: manual	30" "$(rows 203.0.113.13)"
check "CLI output" "block: manual" "$out"

alerts=""
for i in $(seq 100 121); do alerts+="${alerts:+,}$(alert "203.0.113.$i" suricata firing)"; done
post "$token" "[$alerts]" >/dev/null
check "rate cap: 20 new automatic blocks / 10 min" "reject	cap: 20 new blocks per 10 min" "$(rows 203.0.113.121)"

logs="$(docker logs "$NAME" 2>&1 | grep -c '"apply_error"' || true)"
check "no reconciler errors" "0" "$logs"

if ((failed)); then log "FAIL"; exit 1; fi
log "PASS"
