#!/usr/bin/env python3
"""NSM responder (Phase 6): Grafana alert webhook → block decision → one VPC deny rule, with TTL release.

    responder.py serve                                    # webhook on :8080 + reconciler loop
    responder.py block <ip> --ttl 2h --reason "…" --actor alice
    responder.py release <ip> [--suppress 24h] --reason "…" --actor alice
    responder.py list

Flow (docs/architecture.md section 13):
  1. POST /grafana (Bearer token) — each firing alert carries labels src_ip and nsm_trigger
  2. policy.decide() → block / observe / reject / skip; every non-skip decision is appended to nsm.response_actions
  3. the reconciler derives the active block list from ClickHouse every RECONCILE_SECONDS and, in enforce mode,
     sets it as the sourceRanges of the VPC firewall rule nsm-blocklist (deny all, priority 900). Expired blocks
     simply drop out of the list. Each change is recorded in nsm.response_applies (MTTR).

RESPONDER_MODE=dry-run (default) records decisions and the list the rule would get, without calling the Compute API.
RESPONDER_MODE=test is dry-run for the validation harness (testing/response/validate.sh): it also accepts TEST-NET-3
addresses as attackers, and its rows are deleted when the harness finishes.
Rows are separated by mode, so switching to enforce starts from a clean list.

Credentials: ClickHouse account nsm_responder (/run/secrets); GCP token from the metadata server (the VM's service
account needs compute.firewalls.get/update on nsm-blocklist only — infra/terraform/response.tf).
"""
import argparse
import hmac
import ipaddress
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import policy

MODE = os.environ.get("RESPONDER_MODE", "dry-run")
FIREWALL = os.environ.get("RESPONDER_FIREWALL", "nsm-blocklist")
CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "nsm_responder")
RECONCILE_SECONDS = int(os.environ.get("RECONCILE_SECONDS", "30"))
NEVER_BLOCK_FILES = os.environ.get("NEVER_BLOCK_FILES", "/app/never-block.txt:/etc/nsm/never-block.local").split(":")
SECRETS = os.environ.get("SECRETS_DIR", "/run/secrets")
METADATA = "http://169.254.169.254/computeMetadata/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"
PLACEHOLDER_RANGE = "192.0.2.1/32"  # TEST-NET-1: a rule needs at least one range, so an empty list disables the rule
MAX_BODY = 1024 * 1024

if MODE not in ("dry-run", "enforce", "test"):
    sys.exit(f"RESPONDER_MODE must be dry-run, enforce or test, not {MODE!r}")

decision_lock = threading.Lock()


def log(event, **fields):
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "event": event, **fields}), flush=True)


def secret(name):
    with open(os.path.join(SECRETS, name)) as f:
        return f.read().strip()


def utc(ts):
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if ts else None


def parse_duration(text):
    m = re.fullmatch(r"(\d+)([mhd])", text)
    if not m:
        raise argparse.ArgumentTypeError("duration like 30m, 6h or 2d")
    return timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[m.group(2)]: int(m.group(1))})


# --- ClickHouse (HTTP interface, query parameters only — values are never spliced into SQL) ---------------------

def ch(sql, params=None, body_suffix=b""):
    query = {"database": "nsm", **{f"param_{k}": v for k, v in (params or {}).items()}}
    req = urllib.request.Request(
        f"{CLICKHOUSE_URL}/?{urllib.parse.urlencode(query)}",
        data=sql.encode() + body_suffix,
        headers={"X-ClickHouse-User": CLICKHOUSE_USER, "X-ClickHouse-Key": secret("ch_responder_password")},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return [json.loads(line) for line in r.read().decode().splitlines() if line.strip()]


def insert(table, rows):
    payload = "\n".join(json.dumps(row) for row in rows).encode()
    ch(f"INSERT INTO nsm.{table} FORMAT JSONEachRow\n", body_suffix=payload)


# expires_at is Nullable and aggregate functions skip NULLs, so argMax(expires_at, …) would return the previous block's
# expiry after a release without suppression. Wrapping it in a tuple keeps the NULL: argMax(tuple(expires_at), …).1


def active_blocks():
    return ch("""
        SELECT ip, argMax(trigger, created_at) AS last_trigger, argMax(tuple(expires_at), created_at).1 AS last_expires
        FROM nsm.response_actions
        WHERE mode = {mode:String} AND action IN ('block', 'release')
        GROUP BY ip
        HAVING argMax(action, created_at) = 'block' AND argMax(tuple(expires_at), created_at).1 > now64(3)
        ORDER BY ip
        FORMAT JSONEachRow""", {"mode": MODE})


def history(ip):
    row = ch("""
        SELECT
            argMaxIf(action, created_at, action IN ('block', 'release')) AS last_action,
            argMaxIf(tuple(expires_at), created_at, action IN ('block', 'release')).1 AS last_expires,
            countIf(action = 'block' AND created_at > now64(3) - INTERVAL 30 DAY) AS earlier_blocks
        FROM nsm.response_actions
        WHERE mode = {mode:String} AND ip = {ip:String}
        FORMAT JSONEachRow""", {"mode": MODE, "ip": ip})[0]
    totals = ch("""
        SELECT
            (SELECT count() FROM (
                SELECT ip FROM nsm.response_actions
                WHERE mode = {mode:String} AND action IN ('block', 'release')
                GROUP BY ip
                HAVING argMax(action, created_at) = 'block' AND argMax(tuple(expires_at), created_at).1 > now64(3))) AS active_total,
            (SELECT count() FROM nsm.response_actions
             WHERE mode = {mode:String} AND action = 'block' AND trigger != 'manual'
               AND created_at > now64(3) - toIntervalSecond({window:UInt32})) AS new_blocks
        FORMAT JSONEachRow""", {"mode": MODE, "window": int(policy.NEW_BLOCK_WINDOW.total_seconds())})[0]
    expires = parse_ch_time(row["last_expires"])
    now = datetime.now(timezone.utc)
    return policy.History(
        active=row["last_action"] == "block" and expires is not None and expires > now,
        suppressed_until=expires if row["last_action"] == "release" else None,
        earlier_blocks=int(row["earlier_blocks"]),
        active_total=int(totals["active_total"]),
        new_blocks_in_window=int(totals["new_blocks"]),
    )


def parse_ch_time(value):
    if not value or value.startswith("1970-01-01"):
        return None
    return datetime.strptime(value[:23], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)


# First evidence inside the same window the Grafana rule evaluates (nsm-response.yaml), so MTTR starts at the activity that
# triggered the block, not at an older event from before the rule existed or before the source crossed the threshold.
EVIDENCE_SQL = {
    "honeypot": "SELECT min(timestamp) AS t FROM nsm.cowrie_events WHERE src_ip = {ip:String} AND timestamp > now64() - INTERVAL 15 MINUTE",
    "suricata": "SELECT min(timestamp) AS t FROM nsm.suricata_alert WHERE src_ip = {ip:String} AND alert_severity = 1 AND in_iface = 'ens4' "
                "AND NOT startsWith(http_url, '/api/ds/query') AND timestamp > now64() - INTERVAL 10 MINUTE",
    "scanner": "SELECT min(ts) AS t FROM nsm.zeek_conn WHERE id_orig_h = {ip:String} AND id_resp_p = 22 AND ts > now64() - INTERVAL 10 MINUTE",
}


def evidence_at(trigger, ip):
    sql = EVIDENCE_SQL.get(trigger)
    if not sql:
        return None
    rows = ch(sql + " FORMAT JSONEachRow", {"ip": ip})
    return parse_ch_time(rows[0]["t"]) if rows else None


def never_block():
    lines = []
    for path in NEVER_BLOCK_FILES:
        if path and os.path.exists(path):
            with open(path) as f:
                lines.extend(f.readlines())
    return policy.parse_networks(lines)


# --- decisions ------------------------------------------------------------------------------------------------------

def handle(ip, trigger, rule, actor, detail, requested_ttl=None):
    """Decides and records one alert or analyst request. Serialized so concurrent alerts cannot double-block."""
    with decision_lock:
        now = datetime.now(timezone.utc)
        hist = history(ip) if _is_ipv4(ip) else policy.History()
        d = policy.decide(ip, trigger, now, never_block(), hist, requested_ttl, test_net_ok=MODE == "test")
        # An analyst's own words belong in the audit column, next to the policy's reason.
        reason = f"{d.reason}: {detail['reason']}" if trigger == "manual" and detail.get("reason") else d.reason
        if d.action != "skip":
            insert("response_actions", [{
                "created_at": utc(now), "action": d.action, "ip": ip, "trigger": trigger, "rule": rule,
                "reason": reason, "evidence_at": utc(evidence_at(trigger, ip)) if d.action in ("block", "observe") else None,
                "expires_at": utc(d.expires_at), "mode": MODE, "actor": actor, "detail": json.dumps(detail)[:4000],
            }])
        log("decision", ip=ip, trigger=trigger, rule=rule, action=d.action, reason=d.reason, expires_at=utc(d.expires_at), mode=MODE)
        return d


def release(ip, reason, actor, suppress=None):
    ipaddress.ip_address(ip)
    now = datetime.now(timezone.utc)
    with decision_lock:
        insert("response_actions", [{
            "created_at": utc(now), "action": "release", "ip": ip, "trigger": "manual", "rule": "manual release",
            "reason": reason, "evidence_at": None, "expires_at": utc(now + suppress) if suppress else None,
            "mode": MODE, "actor": actor, "detail": "{}",
        }])
    log("release", ip=ip, actor=actor, reason=reason, suppress_until=utc(now + suppress) if suppress else None, mode=MODE)


def _is_ipv4(ip):
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


# --- firewall reconciler --------------------------------------------------------------------------------------------

def metadata(path):
    req = urllib.request.Request(f"{METADATA}/{path}", headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()


def compute(method, url, body=None):
    token = json.loads(metadata("instance/service-accounts/default/token"))["access_token"]
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def last_applied_ranges():
    rows = ch("""
        SELECT ranges FROM nsm.response_applies
        WHERE mode = {mode:String} AND result IN ('ok', 'dry-run', 'test')
        ORDER BY applied_at DESC LIMIT 1
        FORMAT JSONEachRow""", {"mode": MODE})
    return sorted(rows[0]["ranges"]) if rows else []


def reconcile_once():
    desired = sorted(f"{row['ip']}/32" for row in active_blocks())
    started = time.monotonic()
    if MODE in ("dry-run", "test"):
        previous = last_applied_ranges()
        if desired == previous:
            return
        result, error, previous_set = MODE, "", previous
    else:
        url = f"{COMPUTE}/projects/{metadata('project/project-id')}/global/firewalls/{FIREWALL}"
        rule = compute("GET", url)
        current = [] if rule.get("disabled") else sorted(rule.get("sourceRanges", []))
        if current == desired:
            return
        previous_set = current
        compute("PATCH", url, {"sourceRanges": desired or [PLACEHOLDER_RANGE], "disabled": not desired})
        # The PATCH returns an operation; the rule itself is the source of truth, so poll it until it matches.
        result, error = "error", "timed out waiting for the rule to match"
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            rule = compute("GET", url)
            now_ranges = [] if rule.get("disabled") else sorted(rule.get("sourceRanges", []))
            if now_ranges == desired:
                result, error = "ok", ""
                break
            time.sleep(2)
    added = sorted(set(desired) - set(previous_set))
    removed = sorted(set(previous_set) - set(desired))
    duration_ms = int((time.monotonic() - started) * 1000)
    insert("response_applies", [{
        "applied_at": utc(datetime.now(timezone.utc)), "firewall": FIREWALL, "mode": MODE, "result": result,
        "ranges": desired, "added": added, "removed": removed, "duration_ms": duration_ms, "error": error,
    }])
    log("apply", mode=MODE, result=result, ranges=len(desired), added=added, removed=removed, duration_ms=duration_ms, error=error)


def reconcile_loop():
    while True:
        try:
            reconcile_once()
        except Exception as e:  # keep the loop alive; the next cycle retries
            detail = e.read().decode()[:500] if isinstance(e, urllib.error.HTTPError) else ""
            log("apply_error", mode=MODE, error=f"{type(e).__name__}: {e}", detail=detail)
            try:
                insert("response_applies", [{"applied_at": utc(datetime.now(timezone.utc)), "firewall": FIREWALL, "mode": MODE,
                                              "result": "error", "ranges": [], "added": [], "removed": [], "duration_ms": 0,
                                              "error": f"{type(e).__name__}: {e} {detail}"[:1000]}])
            except Exception:
                pass
        time.sleep(RECONCILE_SECONDS)


# --- webhook --------------------------------------------------------------------------------------------------------

class Webhook(BaseHTTPRequestHandler):
    server_version = "nsm-responder"

    def log_message(self, fmt, *args):
        pass

    def _reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"status": "ok", "mode": MODE})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/grafana":
            return self._reply(404, {"error": "not found"})
        expected = f"Bearer {secret('responder_webhook_token')}"
        if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
            log("webhook_unauthorized", peer=self.client_address[0])
            return self._reply(401, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            return self._reply(413, {"error": "body size"})
        try:
            payload = json.loads(self.rfile.read(length))
            alerts = payload.get("alerts", [])
        except (ValueError, AttributeError):
            return self._reply(400, {"error": "invalid JSON"})
        results = []
        for alert in alerts:
            labels = alert.get("labels", {}) or {}
            if alert.get("status") != "firing" or "src_ip" not in labels:
                continue
            d = handle(str(labels["src_ip"]), str(labels.get("nsm_trigger", "")), str(labels.get("alertname", "")),
                       "grafana", {"startsAt": alert.get("startsAt"), "labels": labels, "annotations": alert.get("annotations", {})})
            results.append({"ip": labels["src_ip"], "action": d.action, "reason": d.reason})
        self._reply(200, {"mode": MODE, "results": results})


def serve():
    log("start", mode=MODE, firewall=FIREWALL, reconcile_seconds=RECONCILE_SECONDS, never_block=len(never_block()))
    threading.Thread(target=reconcile_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Webhook).serve_forever()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    b = sub.add_parser("block")
    b.add_argument("ip")
    b.add_argument("--ttl", type=parse_duration, required=True)
    b.add_argument("--reason", required=True)
    b.add_argument("--actor", required=True)
    r = sub.add_parser("release")
    r.add_argument("ip")
    r.add_argument("--suppress", type=parse_duration, help="refuse automatic re-blocks for this long")
    r.add_argument("--reason", required=True)
    r.add_argument("--actor", required=True)
    sub.add_parser("list")
    args = ap.parse_args()

    if args.cmd == "serve":
        serve()
    elif args.cmd == "block":
        d = handle(args.ip, "manual", "manual block", args.actor, {"reason": args.reason}, requested_ttl=args.ttl)
        print(f"{d.action}: {d.reason}" + (f" (until {utc(d.expires_at)} UTC)" if d.expires_at else ""))
        sys.exit(0 if d.action in ("block", "skip") else 1)
    elif args.cmd == "release":
        release(args.ip, args.reason, args.actor, args.suppress)
        print(f"released {args.ip}; the reconciler removes it within {RECONCILE_SECONDS} s")
    elif args.cmd == "list":
        for row in active_blocks():
            print(f"{row['ip']:<16} {row['last_trigger']:<9} until {row['last_expires']} UTC")


if __name__ == "__main__":
    main()
