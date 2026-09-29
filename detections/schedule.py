#!/usr/bin/env python3
"""Scheduled behavior detections: run every DET-*.sql through run.sh and store the results in ClickHouse.

    sudo detections/schedule.py                      # one run for the window ending now (nsm-detections.timer, hourly)
    sudo detections/schedule.py --backfill-hours 48  # one run per past hour, oldest first, marked backfill

Each run covers the WINDOW_HOURS before its end time, the default window the detections were designed and validated with.
Rows go to nsm.detection_hits with the common leading columns (detection_id, severity, src, dst, dst_port, first_seen,
last_seen, score, summary); every detection-specific column is kept as JSON in details. Every run, including a failed
one, is recorded in nsm.detection_runs, so a detection that silently stops working shows up on the SOC KPI dashboard.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
RUN_SH = os.path.join(HERE, "run.sh")
SQL_DIR = os.path.join(HERE, "sql")
WINDOW_HOURS = 24
COMMON = ("detection_id", "severity", "src", "dst", "dst_port", "first_seen", "last_seen", "score", "summary")


def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def detections():
    return sorted(f.split("-", 2)[0] + "-" + f.split("-", 2)[1] for f in os.listdir(SQL_DIR) if f.startswith("DET-") and f.endswith(".sql"))


def insert(table, rows):
    if not rows:
        return
    payload = "\n".join(json.dumps(r, default=str) for r in rows).encode()
    subprocess.run(["docker", "exec", "-i", "nsm-clickhouse", "clickhouse-client", "-q", f"INSERT INTO nsm.{table} FORMAT JSONEachRow"],
                   input=payload, check=True, capture_output=True)


def run_one(det, start, end, run_id, run_at, backfill):
    started = time.monotonic()
    proc = subprocess.run([RUN_SH, det, "--from", fmt(start), "--to", fmt(end), "--format", "JSONEachRow"], capture_output=True, text=True)
    duration_ms = int((time.monotonic() - started) * 1000)
    base = {"run_id": run_id, "run_at": run_at, "window_start": fmt(start), "window_end": fmt(end), "detection_id": det}
    if proc.returncode != 0:
        insert("detection_runs", [dict(base, result="error", hits=0, duration_ms=duration_ms, backfill=backfill, error=proc.stderr.strip()[-1000:])])
        return det, "error", 0, proc.stderr.strip().splitlines()[-1:] or [""]
    hits = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        details = {k: v for k, v in row.items() if k not in COMMON}
        hit = {k: row.get(k) for k in COMMON}
        hit["detection_id"] = hit["detection_id"] or det
        hit["dst_port"] = int(hit["dst_port"] or 0)
        hit["hit_key"] = f"{hit['detection_id']}|{hit['src']}|{hit['dst']}|{hit['dst_port']}"
        hits.append(dict(base, **hit, details=json.dumps(details, sort_keys=True, default=str)))
    insert("detection_hits", hits)
    insert("detection_runs", [dict(base, result="ok", hits=len(hits), duration_ms=duration_ms, backfill=backfill, error="")])
    return det, "ok", len(hits), []


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--backfill-hours", type=int, default=0, help="also run for each of the past N full hours")
    args = ap.parse_args()

    now = datetime.now(timezone.utc).replace(microsecond=0)
    if args.backfill_hours:
        top = now.replace(minute=0, second=0)
        ends = [(top - timedelta(hours=h), True) for h in range(args.backfill_hours, 0, -1)]
    else:
        ends = [(now, False)]

    failed = 0
    for end, backfill in ends:
        run_id = str(uuid.uuid4())
        run_at = fmt(end if backfill else datetime.now(timezone.utc)) + ".000"
        results = [run_one(det, end - timedelta(hours=WINDOW_HOURS), end, run_id, run_at, backfill) for det in detections()]
        failed += sum(1 for _, status, _, _ in results if status != "ok")
        summary = " ".join(f"{det}={hits if status == 'ok' else 'ERROR'}" for det, status, hits, _ in results)
        print(f"[detections] window end {fmt(end)}{' (backfill)' if backfill else ''}: {summary}", flush=True)
        for det, status, _, err in results:
            if status != "ok":
                print(f"[detections] {det} failed: {err[0] if err else ''}", file=sys.stderr, flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
