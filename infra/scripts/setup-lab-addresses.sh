#!/usr/bin/env bash
# Load this lab's own addresses into nsm.lab_addresses from .env. Idempotent: re-running replaces the rows.
#
# The addresses are the lab's, not secrets, but keeping them in .env rather than in queries means the repository can be
# published without a redaction pass over every dashboard and script. Same reason the passwords live there.
#
#   LAB_ADDRESSES="34.x.x.x=sensor:external address of the NSM sensor,34.y.y.y=honeypot:the Cowrie VM"
#
# Format: comma-separated  address=role:note  entries. Role and note are optional.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO"
CONTAINER=${NSM_CH_CONTAINER:-nsm-clickhouse}

die() { printf 'setup-lab-addresses: error: %s\n' "$*" >&2; exit 1; }

[[ -f .env ]] || die ".env not found (see .env.example)"
# shellcheck disable=SC1091
LAB_ADDRESSES=$(sed -n 's/^LAB_ADDRESSES=//p' .env | tr -d '"'"'"'"' | head -1)
[[ -n "$LAB_ADDRESSES" ]] || die "LAB_ADDRESSES is not set in .env (see .env.example)"

docker exec -i "$CONTAINER" clickhouse-client --multiquery < ingest/clickhouse/schema/010_lab_addresses.sql

rows=""
count=0
IFS=',' read -ra entries <<<"$LAB_ADDRESSES"
for entry in "${entries[@]}"; do
  entry=$(printf '%s' "$entry" | xargs)   # trim
  [[ -n "$entry" ]] || continue
  address=${entry%%=*}
  rest=${entry#*=}
  [[ "$rest" == "$entry" ]] && rest=""
  role=${rest%%:*}
  note=${rest#*:}
  [[ "$note" == "$rest" ]] && note=""
  [[ "$address" =~ ^[0-9a-fA-F.:]+$ ]] || die "'$address' does not look like an IP address"
  # printf already ends the row; adding another newline gave ClickHouse a blank final line to choke on.
  rows+=$(printf '%s\t%s\t%s' "$address" "${role:-other}" "$note")$'\n'
  count=$((count + 1))
done
((count > 0)) || die "LAB_ADDRESSES parsed to nothing"

# printf, not a here-string: <<< appends its own newline on top of the one each row already carries, and the blank
# final line makes ClickHouse reject the whole batch.
printf '%s' "$rows" | docker exec -i "$CONTAINER" clickhouse-client --query \
  "INSERT INTO nsm.lab_addresses (address, role, note, added) SELECT c1, c2, c3, now() FROM input('c1 String, c2 String, c3 String') FORMAT TSV"
docker exec -i "$CONTAINER" clickhouse-client --query "OPTIMIZE TABLE nsm.lab_addresses FINAL"

printf 'setup-lab-addresses: %d address(es) loaded. Stored rows:\n' "$count"
docker exec -i "$CONTAINER" clickhouse-client --query \
  "SELECT role, count() FROM nsm.lab_addresses GROUP BY role ORDER BY role FORMAT PrettyCompactMonoBlock"
