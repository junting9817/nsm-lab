#!/usr/bin/env bash
# Regenerate docs/screenshots/*.png from the live dashboards (README). Nothing is published or left behind.
#
#   sudo docs/screenshots/capture.sh
#
# 1. creates a Viewer service account in Grafana with a token that expires after 15 minutes
# 2. runs capture.py in a one-off Playwright container on the nsm network (1 GiB memory limit)
# 3. deletes the service account again, even when the capture fails
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE=mcr.microsoft.com/playwright/python:v1.49.1-noble
die() { printf '[screenshots] ERROR: %s\n' "$*" >&2; exit 1; }

set -a
# shellcheck disable=SC1091
. "$REPO_ROOT/.env"
set +a
# Address prefixes that must never appear in a published screenshot (e.g. the dashboard user's own networks), comma-separated.
# Kept in .env so the private ranges themselves are not committed.
DENY="${NSM_SCREENSHOT_DENY:-}"
[[ -n "$DENY" ]] || die "set NSM_SCREENSHOT_DENY in .env (address prefixes to keep out of screenshots)"

api() { curl -fsS -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" -H 'Content-Type: application/json' "$@"; }
network="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' nsm-grafana)"

sa_id="$(api -X POST http://127.0.0.1/api/serviceaccounts -d '{"name":"nsm-screenshots","role":"Viewer"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')" \
  || die "could not create the service account (a leftover nsm-screenshots account may exist)"
trap 'api -X DELETE "http://127.0.0.1/api/serviceaccounts/$sa_id" >/dev/null && echo "[screenshots] service account removed"' EXIT
token="$(api -X POST "http://127.0.0.1/api/serviceaccounts/$sa_id/tokens" -d '{"name":"capture","secondsToLive":900}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')"

install -d -m 0777 "$REPO_ROOT/docs/screenshots/out"
docker run --rm --network "$network" --memory 1g --ipc host \
  -e GRAFANA_TOKEN="$token" -e NSM_SCREENSHOT_DENY="$DENY" -e OUT_DIR=/out \
  -v "$REPO_ROOT/docs/screenshots/capture.py:/capture.py:ro" -v "$REPO_ROOT/docs/screenshots/out:/out" \
  "$IMAGE" bash -c "pip install -q --break-system-packages playwright==1.49.1 && python3 /capture.py"
mv "$REPO_ROOT"/docs/screenshots/out/*.png "$REPO_ROOT/docs/screenshots/" && rmdir "$REPO_ROOT/docs/screenshots/out"
chown -R "${SUDO_USER:-root}": "$REPO_ROOT/docs/screenshots"
ls -l "$REPO_ROOT"/docs/screenshots/*.png
