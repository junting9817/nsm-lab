#!/usr/bin/env bash
# Proves the responder's GCP permission is limited to the nsm-blocklist rule. Run on the sensor VM after it switched to
# the nsm-sensor service account (docs/architecture.md section 13). Uses the VM's own token; no user login.
#
#   testing/response/check-firewall-permissions.sh
#
# Every write is a no-op PATCH that sets a rule's description to its current value, so nothing changes even if a
# permission turned out broader than intended. Expected:
#   nsm-blocklist                          GET 200, PATCH 200  (the responder can do its job)
#   nsm-allow-dashboard-http               PATCH 403           (other sensor rules are out of reach)
#   nsm-honeypot-deny-egress               PATCH 403           (the honeypot's egress lock is out of reach)
set -Eeuo pipefail

md() { curl -fsS -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/$1"; }
project="$(md project/project-id)"
account="$(md instance/service-accounts/default/email)"
scopes="$(md instance/service-accounts/default/scopes | tr '\n' ' ')"
token="$(md instance/service-accounts/default/token | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
base="https://compute.googleapis.com/compute/v1/projects/$project/global/firewalls"

echo "account: $account"
echo "scopes:  $scopes"
[[ "$account" == nsm-sensor@* ]] || echo "WARNING: the VM is not on the nsm-sensor account yet; results describe $account"

# no_op_patch <rule> → HTTP status of GET, then of a PATCH that rewrites the current description
no_op_patch() {
  local rule="$1" get_status body patch_status
  body="$(mktemp)"
  get_status="$(curl -sS -o "$body" -w '%{http_code}' -H "Authorization: Bearer $token" "$base/$rule")"
  if [[ "$get_status" != 200 ]]; then
    # Without read access, send a PATCH with an empty description change the API will still authorize first.
    patch_status="$(curl -sS -o /dev/null -w '%{http_code}' -X PATCH -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' -d '{}' "$base/$rule")"
  else
    patch_status="$(python3 -c 'import json, sys; print(json.dumps({"description": json.load(open(sys.argv[1])).get("description", "")}))' "$body" |
      curl -sS -o /dev/null -w '%{http_code}' -X PATCH -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d @- "$base/$rule")"
  fi
  rm -f "$body"
  printf '%s %s' "$get_status" "$patch_status"
}

failed=0
expect() { # <rule> <expected GET> <expected PATCH>
  local got
  got="$(no_op_patch "$1")"
  if [[ "$got" == "$2 $3" || ( "$2" == any && "${got#* }" == "$3" ) ]]; then
    printf '  PASS  %-28s GET/PATCH %s\n' "$1" "$got"
  else
    printf '  FAIL  %-28s GET/PATCH %s, expected %s %s\n' "$1" "$got" "$2" "$3"
    failed=1
  fi
}

expect nsm-blocklist 200 200
expect nsm-allow-dashboard-http any 403
expect nsm-honeypot-deny-egress any 403
((failed == 0)) || { echo "FAIL"; exit 1; }
echo "PASS"
