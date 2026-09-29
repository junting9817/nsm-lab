#!/usr/bin/env python3
"""Pull new honeypot log objects from the one-way bucket onto the sensor VM (nsm-honeypot-pull.timer, every minute).

setup-honeypot-ingest.sh copies it to /usr/local/sbin/nsm-honeypot-pull and it runs as root.

    nsm-honeypot-pull [--bucket NAME] [--dest DIR] [--state FILE]

Credentials: the VM's own service account token from the metadata server (devstorage.read_only scope plus
roles/storage.objectViewer on the bucket). No inbound port and no network path to the honeypot are involved.

Objects are named cowrie/<upload time>-<uuid>.json.gz (honeypot/vector/vector.yaml.tftpl), so listing starts at
the newest pulled time minus an overlap window, and names already pulled inside that window are skipped.
Each object's lines are appended to <dest>/cowrie-<UTC date>.json, which Vector tails.

The honeypot is treated as hostile: object size and decompressed size are capped, and only lines that parse as
JSON objects are kept. If the process dies between the append and the state write, that object is pulled again
on the next run (at most one object's events duplicated).
"""
import argparse
import gzip
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

API = "https://storage.googleapis.com"
METADATA_TOKEN = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
PREFIX = "cowrie/"
NAME_RE = re.compile(r"^cowrie/(\d{8}T\d{6}Z)-[0-9a-f-]+\.json\.gz$")
OVERLAP = timedelta(hours=2)
MAX_OBJECT_BYTES = 50 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_OBJECTS_PER_RUN = 500


def log(msg):
    print(f"[nsm-honeypot-pull] {msg}", flush=True)


def http_json(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def get_token():
    req = urllib.request.Request(METADATA_TOKEN, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)["access_token"]


def load_state(path):
    try:
        with open(path) as f:
            state = json.load(f)
        return {"seen": dict(state.get("seen", {}))}
    except FileNotFoundError:
        return {"seen": {}}


def save_state(path, state):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".state.")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def object_time(name):
    m = NAME_RE.match(name)
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc) if m else None


def list_new(bucket, token, start_offset):
    params = {"prefix": PREFIX, "fields": "items(name,size),nextPageToken"}
    if start_offset:
        params["startOffset"] = start_offset
    items, page = [], None
    while True:
        if page:
            params["pageToken"] = page
        url = f"{API}/storage/v1/b/{urllib.parse.quote(bucket, safe='')}/o?{urllib.parse.urlencode(params)}"
        body = http_json(url, token)
        items.extend(body.get("items", []))
        page = body.get("nextPageToken")
        if not page or len(items) >= 10 * MAX_OBJECTS_PER_RUN:
            return items


def download_lines(bucket, name, token):
    """Returns the object's JSON-object lines as bytes, and the number of lines dropped."""
    url = f"{API}/storage/v1/b/{urllib.parse.quote(bucket, safe='')}/o/{urllib.parse.quote(name, safe='')}?alt=media"
    # Vector uploads with Content-Encoding: gzip. Cloud Storage would transparently decompress such objects on
    # download (decompressive transcoding) unless the client accepts gzip, so ask for the stored bytes, and still
    # accept an already-decompressed body.
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(MAX_OBJECT_BYTES + 1)
    if len(data) > MAX_OBJECT_BYTES:
        raise ValueError(f"object larger than {MAX_OBJECT_BYTES} bytes")
    # Streamed decompression with a cap (gzip bombs); wbits 16+MAX_WBITS = gzip container, multi-member handled in the loop.
    out, total = [], 0
    if not data.startswith(b"\x1f\x8b"):
        out, data = [data], b""
    while data:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        chunk = d.decompress(data, MAX_DECOMPRESSED_BYTES - total + 1)
        total += len(chunk)
        out.append(chunk)
        if total > MAX_DECOMPRESSED_BYTES or d.unconsumed_tail:
            raise ValueError(f"decompressed size over {MAX_DECOMPRESSED_BYTES} bytes")
        if not d.eof:
            raise ValueError("truncated gzip stream")
        data = d.unused_data
    kept, dropped = [], 0
    for line in b"".join(out).splitlines():
        if not line.strip():
            continue
        try:
            ok = isinstance(json.loads(line), dict)
        except ValueError:
            ok = False
        if ok:
            kept.append(line)
        else:
            dropped += 1
    return b"".join(line + b"\n" for line in kept), dropped


def append(dest_dir, payload):
    path = os.path.join(dest_dir, f"cowrie-{datetime.now(timezone.utc):%Y-%m-%d}.json")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        view = memoryview(payload)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bucket", default=os.environ.get("NSM_HONEYPOT_BUCKET"))
    ap.add_argument("--dest", default="/data/logs/honeypot/cowrie")
    ap.add_argument("--state", default="/var/lib/nsm-honeypot-pull/state.json")
    args = ap.parse_args()
    if not args.bucket:
        sys.exit("[nsm-honeypot-pull] --bucket or NSM_HONEYPOT_BUCKET is required")
    os.makedirs(args.dest, exist_ok=True)

    state = load_state(args.state)
    times = [t for t in (object_time(n) for n in state["seen"]) if t]
    start_offset = None
    if times:
        start_offset = PREFIX + (max(times) - OVERLAP).strftime("%Y%m%dT%H%M%SZ")

    token = get_token()
    listed = list_new(args.bucket, token, start_offset)
    unexpected = [i["name"] for i in listed if not NAME_RE.match(i["name"])]
    if unexpected:
        log(f"WARNING: {len(unexpected)} objects with unexpected names were ignored, e.g. {unexpected[0]!r}")
    items = sorted((i for i in listed if NAME_RE.match(i["name"])), key=lambda i: i["name"])
    todo = [i for i in items if i["name"] not in state["seen"]][:MAX_OBJECTS_PER_RUN]

    pulled = events = 0
    for item in todo:
        name = item["name"]
        try:
            payload, dropped = download_lines(args.bucket, name, token)
        except ValueError as e:
            log(f"skipped {name}: {e}")
            payload, dropped = b"", 0
        if payload:
            append(args.dest, payload)
        if dropped:
            log(f"{name}: dropped {dropped} lines that were not JSON objects")
        state["seen"][name] = int(time.time())
        pulled += 1
        events += payload.count(b"\n")
        save_state(args.state, state)

    # Objects listed but not pulled because of MAX_OBJECTS_PER_RUN; counted before pruning, which drops names that are
    # already pulled but fall outside the overlap window (counting afterwards reported them as a false backlog).
    backlog = len([i for i in items if i["name"] not in state["seen"]])

    # Forget names older than the overlap window behind the newest one.
    if state["seen"]:
        newest = max(t for t in (object_time(n) for n in state["seen"]) if t)
        state["seen"] = {n: v for n, v in state["seen"].items() if (object_time(n) or newest) >= newest - OVERLAP}
        save_state(args.state, state)

    log(f"pulled {pulled} objects, {events} events" + (f", {backlog} left for the next run" if backlog else ""))


if __name__ == "__main__":
    main()
