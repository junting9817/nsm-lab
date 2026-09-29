#!/usr/bin/env bash
# Delete broad default firewall rules that the console created in the default network (one-off cleanup,
# docs/architecture.md section 5).
#
#   infra/scripts/cleanup-default-firewall.sh                 # dry run: show the current state of the target rules
#   infra/scripts/cleanup-default-firewall.sh --apply         # delete the default targets
#   infra/scripts/cleanup-default-firewall.sh --apply RULE…   # delete only the named rules
#
# Auth: needs a user ADC login; revoke it right after (D2).
# Idempotent: rules that no longer exist are skipped.
# Protected: nsm-* rules, default-allow-http (80/tcp, D3) and default-allow-ssh (22/tcp, D5) are never deleted.
source "$(dirname "$0")/lib.sh"

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
  shift
fi
RULES=("$@")
((${#RULES[@]})) || RULES=(default-allow-rdp default-allow-https)

for rule in "${RULES[@]}"; do
  case "$rule" in
    nsm-*) die "$rule is managed by Terraform, not a cleanup target." ;;
    default-allow-http) die "default-allow-http (80/tcp) is kept by user decision (D3)." ;;
    default-allow-ssh) die "default-allow-ssh (22/tcp) is kept so the console SSH button works (D5)." ;;
    default-allow-*) ;;
    *) die "$rule: only default-allow-* rules are handled." ;;
  esac
done

PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
[[ -n "$PROJECT" ]] || die "unknown project. Set PROJECT=..."

# Without a user ADC, print-access-token silently falls back to the VM's default service account, so check the file
ADC_FILE="${CLOUDSDK_CONFIG:-$HOME/.config/gcloud}/application_default_credentials.json"
[[ "$(jq -r '.type // empty' "$ADC_FILE" 2>/dev/null)" == authorized_user ]] ||
  die "user ADC login required: gcloud auth application-default login --no-launch-browser"
TOKEN="$(gcloud auth application-default print-access-token 2>/dev/null)" || die "could not get an ADC token"
API="https://compute.googleapis.com/compute/v1/projects/$PROJECT/global"
BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT

# api METHOD PATH → prints the HTTP status code; the response body goes to $BODY
api() {
  curl -sS -o "$BODY" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $TOKEN" "$API/$2"
}

describe() {
  jq -r '[.name, (.sourceRanges // [] | join(",")),
          ([.allowed[]? | .IPProtocol + ":" + ((.ports // ["all"]) | join(","))] | join(" ")),
          ((.targetTags // ["(all instances)"]) | join(",")),
          (if .disabled then "disabled" else "enabled" end)] | @tsv' "$BODY"
}

for rule in "${RULES[@]}"; do
  code="$(api GET "firewalls/$rule")"
  case "$code" in
    404)
      log "$rule: already gone (skipped)"
      continue
      ;;
    200) log "$rule: $(describe)" ;;
    *) die "failed to read $rule (HTTP $code): $(jq -r '.error.message // empty' "$BODY")" ;;
  esac

  ((APPLY)) || continue

  code="$(api DELETE "firewalls/$rule")"
  [[ "$code" == 200 ]] || die "delete request for $rule failed (HTTP $code): $(jq -r '.error.message // empty' "$BODY")"
  op="$(jq -r '.name' "$BODY")"
  code="$(api POST "operations/$op/wait")"
  [[ "$code" == 200 && "$(jq -r '.status' "$BODY")" == DONE ]] || die "waiting for $rule deletion failed (HTTP $code)"
  if jq -e '.error' "$BODY" >/dev/null; then
    die "error deleting $rule: $(jq -c '.error' "$BODY")"
  fi
  log "$rule: deleted"
done

((APPLY)) || log "dry run. Add --apply to delete."
