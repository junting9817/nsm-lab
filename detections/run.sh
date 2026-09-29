#!/usr/bin/env bash
# Runner for behavior-based detection SQL (detections/sql/DET-*.sql).
#
#   sudo detections/run.sh DET-101                        # last 24 hours, database nsm
#   sudo detections/run.sh DET-101 --hours 6
#   sudo detections/run.sh DET-101 --from '2026-01-05 00:00:00' --to '2026-01-06 00:00:00' --db nsm_test
#   sudo detections/run.sh DET-101 --set min_score=0.7 --format JSONEachRow
#   sudo detections/run.sh --list                         # detections and parameter defaults
#
# Parameters are declared in the SQL header as "-- @param <name> <type> [= default]".
# The runner fills db, start and end; every other parameter uses its default unless overridden with --set.
# Values are passed as ClickHouse query parameters ({name:Type}), never spliced into the SQL text.
# String defaults are written without quotes (e.g. "= Asia/Seoul"); arrays use ClickHouse literals (e.g. "= ['a','b']").
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SQL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sql"
die() { printf '[detect] ERROR: %s\n' "$*" >&2; exit 2; }

params_of() { grep -E '^-- @param ' "$1" | sed -E 's/^-- @param //'; }

if [[ "${1:-}" == "--list" ]]; then
  for f in "$SQL_DIR"/DET-*.sql; do
    printf '%s  %s\n' "$(basename "$f" .sql)" "$(sed -n '1s/^-- //p' "$f")"
    params_of "$f" | grep ' = ' | sed 's/^/    /'
  done
  exit 0
fi

[[ $# -ge 1 ]] || die "usage: $0 <DET-ID> [--db nsm] [--hours 24 | --from T --to T] [--set name=value]... [--format F]"
det="$1"
shift
mapfile -t matches < <(find "$SQL_DIR" -maxdepth 1 -name "${det}-*.sql" | sort)
((${#matches[@]} == 1)) || die "expected exactly one SQL file for $det, found ${#matches[@]}"
sql="${matches[0]}"

db=nsm
hours=24
from=""
to=""
format=PrettyCompactMonoBlock
declare -A overrides=()
while (($#)); do
  case "$1" in
    --db) db="$2"; shift 2 ;;
    --hours) hours="$2"; shift 2 ;;
    --from) from="$2"; shift 2 ;;
    --to) to="$2"; shift 2 ;;
    --format) format="$2"; shift 2 ;;
    --set)
      [[ "$2" == *=* ]] || die "--set expects name=value: $2"
      overrides["${2%%=*}"]="${2#*=}"
      shift 2
      ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ "$db" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "invalid database name: $db"

to="${to:-$(date -u '+%Y-%m-%d %H:%M:%S')}"
from="${from:-$(date -u -d "$to UTC - $hours hours" '+%Y-%m-%d %H:%M:%S')}"

args=(--param_db="$db" --param_start="$from" --param_end="$to")
declared=()
while read -r name type rest; do
  declared+=("$name")
  case "$name" in db | start | end) continue ;; esac
  if [[ -n "${overrides[$name]+x}" ]]; then
    value="${overrides[$name]}"
  elif [[ "$rest" == "= "* ]]; then
    value="${rest#= }"
  else
    die "$name ($type) has no default — pass --set $name=value"
  fi
  args+=("--param_${name}=${value}")
done < <(params_of "$sql")

for name in "${!overrides[@]}"; do
  printf '%s\n' "${declared[@]}" | grep -qx "$name" || die "$(basename "$sql") has no parameter named $name"
done

# The query goes in on stdin (-i); results go to stdout.
docker exec -i nsm-clickhouse clickhouse-client "${args[@]}" --format "$format" <"$sql"
