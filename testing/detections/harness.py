#!/usr/bin/env python3
"""Load offline Zeek logs into a test database and check detection results against expectations.

    python3 testing/detections/harness.py load  <zeek_log_dir> <database>
    python3 testing/detections/harness.py check <expectations.json> <database>

load  : applies the same mapping as Vector's zeek_rows transform (ingest/vector/vector.yaml):
        dots in field names become underscores, epoch timestamps become DateTime64 strings.
check : runs each detection through detections/run.sh against <database> and verifies that every "flag" host
        is reported (with any listed field values) and no "no_flag" host is reported. Exit code 1 on any failure.
"""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOGS = ["conn", "dns", "http", "ssl", "x509", "notice"]
TIME_FIELDS = {"ts", "certificate_not_valid_before", "certificate_not_valid_after"}


def to_ch_time(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def load(log_dir: Path, database: str) -> None:
    for name in LOGS:
        path = log_dir / f"{name}.log"
        if not path.exists():
            print(f"  {name:7s} (no log)")
            continue
        rows = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            rec = {k.replace(".", "_"): v for k, v in json.loads(line).items()}
            for field in TIME_FIELDS & rec.keys():
                rec[field] = to_ch_time(float(rec[field]))
            rows.append(json.dumps(rec))
        subprocess.run(
            ["docker", "exec", "-i", "nsm-clickhouse", "clickhouse-client", "--input_format_skip_unknown_fields=1",
             "--query", f"INSERT INTO {database}.zeek_{name} FORMAT JSONEachRow"],
            input="\n".join(rows).encode(), check=True)
        print(f"  {name:7s} {len(rows)} rows")


def run_detection(det: str, database: str, window: dict, params: dict) -> list:
    cmd = [str(REPO / "detections/run.sh"), det, "--db", database, "--from", window["from"], "--to", window["to"],
           "--format", "JSONEachRow"]
    for key, value in params.items():
        cmd += ["--set", f"{key}={value}"]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def matches(row: dict, expected: dict) -> bool:
    for key, value in expected.items():
        actual = row.get(key)
        if isinstance(value, list):
            if sorted(actual or []) != sorted(value):
                return False
        elif str(actual) != str(value):
            return False
    return True


def check(expectations_path: Path, database: str) -> int:
    failures = 0
    print(f"{'DETECTION':10s} {'HOST':16s} {'EXPECT':8s} {'RESULT':6s} DETAIL")
    for exp in json.loads(expectations_path.read_text()):
        det = exp["detection"]
        rows = run_detection(det, database, exp["window"], exp.get("params", {}))
        notes = exp.get("notes", {})
        for want in exp["flag"]:
            hit = next((r for r in rows if matches(r, want)), None)
            same_src = [r for r in rows if r.get("src") == want["src"]]
            ok = hit is not None
            failures += not ok
            detail = hit["summary"] if ok else (
                f"reported with other values: {[{k: r.get(k) for k in want} for r in same_src]}" if same_src else "not reported")
            print(f"{det:10s} {want['src']:16s} {'flag':8s} {'PASS' if ok else 'FAIL':6s} "
                  f"{detail}  [score={hit.get('score') if hit else '-'}; {notes.get(want['src'], '')}]")
        for src in exp["no_flag"]:
            hits = [r for r in rows if r.get("src") == src]
            ok = not hits
            failures += not ok
            detail = notes.get(src, "") if ok else f"unexpectedly reported: {hits[0]['summary']} (score={hits[0].get('score')})"
            print(f"{det:10s} {src:16s} {'no_flag':8s} {'PASS' if ok else 'FAIL':6s} {detail}")
    total = sum(len(e["flag"]) + len(e["no_flag"]) for e in json.loads(expectations_path.read_text()))
    print(f"\n{total - failures}/{total} host checks passed")
    return 1 if failures else 0


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("load", "check"):
        sys.exit(__doc__)
    if sys.argv[1] == "load":
        load(Path(sys.argv[2]), sys.argv[3])
        return 0
    return check(Path(sys.argv[2]), sys.argv[3])


if __name__ == "__main__":
    sys.exit(main())
