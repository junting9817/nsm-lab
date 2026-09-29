#!/usr/bin/env bash
# Validate detections/allowlist.tsv and replace the contents of <db>.allowlist atomically.
#
#   sudo detections/sync-allowlist.sh                                   # detections/allowlist.tsv → nsm.allowlist
#   sudo detections/sync-allowlist.sh --db nsm_test --file testing/detections/allowlist.tsv
#
# Columns (tab-separated, header required): id, detection_id, match_type, value, reason, expires_at, enabled
# The whole file is rejected if any row is invalid — a bad exception must never silently widen suppression
# (for example an empty sni_suffix would match every TLS connection).
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
db=nsm
file="$REPO/detections/allowlist.tsv"
while (($#)); do
  case "$1" in
    --db) db="$2"; shift 2 ;;
    --file) file="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ "$db" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "invalid database name: $db" >&2; exit 2; }
[[ -f "$file" ]] || { echo "no such file: $file" >&2; exit 2; }

python3 - "$file" "$REPO/detections/sql" <<'PY'
import ipaddress, re, sys
from datetime import datetime
from pathlib import Path

path, sql_dir = Path(sys.argv[1]), Path(sys.argv[2])
known = {p.name[:7] for p in sql_dir.glob("DET-*.sql")} | {"*"}
header = ["id", "detection_id", "match_type", "value", "reason", "expires_at", "enabled"]
lines = [l for l in path.read_text().splitlines() if l.strip()]
errors, ids = [], set()
if not lines or lines[0].split("\t") != header:
    sys.exit(f"{path}: header must be: {' '.join(header)}")
for n, line in enumerate(lines[1:], start=2):
    f = line.split("\t")
    if len(f) != len(header):
        errors.append(f"line {n}: expected {len(header)} columns, got {len(f)}"); continue
    rid, det, mtype, value, reason, expires, enabled = f
    if not re.fullmatch(r"TUNE-\d{3}(-TEST)?", rid): errors.append(f"line {n}: id must look like TUNE-001")
    if det not in known: errors.append(f"line {n}: unknown detection_id {det}")
    if not value.strip() or not reason.strip(): errors.append(f"line {n}: value and reason must not be empty")
    if mtype == "dst_ip":
        try: ipaddress.ip_address(value)
        except ValueError: errors.append(f"line {n}: invalid IP {value}")
    elif mtype == "dst_cidr":
        try: ipaddress.ip_network(value)
        except ValueError: errors.append(f"line {n}: invalid CIDR {value}")
    elif mtype == "sni":
        if not re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]+", value): errors.append(f"line {n}: invalid SNI {value}")
    elif mtype == "sni_suffix":
        if not re.fullmatch(r"\.[a-z0-9.-]+\.[a-z0-9-]+", value): errors.append(f"line {n}: sni_suffix must start with a dot, e.g. .example.com")
    else:
        errors.append(f"line {n}: match_type must be dst_ip, dst_cidr, sni or sni_suffix")
    try: datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
    except ValueError: errors.append(f"line {n}: expires_at must be YYYY-MM-DD HH:MM:SS (UTC)")
    if enabled not in ("true", "false"): errors.append(f"line {n}: enabled must be true or false")
    if (rid, det, mtype, value) in ids: errors.append(f"line {n}: duplicate entry")
    ids.add((rid, det, mtype, value))
if errors:
    sys.exit("allowlist rejected:\n  " + "\n  ".join(errors))
print(f"allowlist valid: {len(lines) - 1} entries")
PY

ch() { docker exec -i nsm-clickhouse clickhouse-client --multiquery; }
sed -E "s/\bnsm\.allowlist\b/${db}.allowlist/" "$REPO/ingest/clickhouse/schema/012_allowlist.sql" | ch
printf 'DROP TABLE IF EXISTS %s.allowlist_staging; CREATE TABLE %s.allowlist_staging AS %s.allowlist;\n' "$db" "$db" "$db" | ch
docker exec -i nsm-clickhouse clickhouse-client --query "INSERT INTO ${db}.allowlist_staging FORMAT TSVWithNames" <"$file"
printf 'EXCHANGE TABLES %s.allowlist AND %s.allowlist_staging; DROP TABLE %s.allowlist_staging;\n' "$db" "$db" "$db" | ch

docker exec nsm-clickhouse clickhouse-client --query "
  SELECT detection_id, match_type, count() AS entries, countIf(enabled AND expires_at > now()) AS active
  FROM ${db}.allowlist GROUP BY detection_id, match_type ORDER BY detection_id, match_type FORMAT PrettyCompactMonoBlock"
