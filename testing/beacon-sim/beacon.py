#!/usr/bin/env python3
"""Beacon simulator for validating DET-101 (beaconing) on live traffic.

Sends an HTTP check-in on a new TCP connection every `interval` seconds, with uniform ±`jitter` randomness,
the way a simple C2 implant would.

    python3 testing/beacon-sim/beacon.py --interval 15 --jitter 0.2 --count 60

Safety: the target must resolve to this sensor's own external IP (read from the GCE metadata server),
a loopback address, or an address inside the VPC (10.128.0.0/9). Anything else is refused, so the simulator
cannot generate traffic toward hosts we do not own. Hitting the sensor's external IP hairpins through the
VPC, which makes the connections visible to Zeek on ens4.
"""
import argparse
import http.client
import ipaddress
import json
import random
import socket
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

METADATA_EXTERNAL_IP = ("http://metadata.google.internal/computeMetadata/v1/instance/"
                        "network-interfaces/0/access-configs/0/external-ip")
VPC = ipaddress.ip_network("10.128.0.0/9")


def own_external_ip() -> str:
    req = urllib.request.Request(METADATA_EXTERNAL_IP, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.read().decode().strip()


def check_target(host: str) -> str:
    ip = socket.gethostbyname(host)
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr in VPC:
        return ip
    external = own_external_ip()
    if ip == external:
        return ip
    sys.exit(f"refusing target {host} ({ip}): only this sensor's external IP {external}, loopback or {VPC} are allowed")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", help="default: http://<this sensor's external IP>/nsm-beacon")
    ap.add_argument("--interval", type=float, default=15.0, help="seconds between check-ins")
    ap.add_argument("--jitter", type=float, default=0.2, help="uniform ±fraction of the interval (0..1)")
    ap.add_argument("--count", type=int, default=60)
    ap.add_argument("--pad", type=int, default=64, help="padding bytes per request (keeps check-in size constant)")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    if not 0 <= args.jitter <= 1:
        sys.exit("--jitter must be between 0 and 1")

    url = urllib.parse.urlparse(args.url or f"http://{own_external_ip()}/nsm-beacon")
    target_ip = check_target(url.hostname)
    rng = random.Random(args.seed)

    started = now_iso()
    ok = errors = 0
    for i in range(args.count):
        try:
            conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=5)
            conn.request("GET", f"{url.path or '/'}?seq={i:05d}",
                         headers={"User-Agent": "nsm-beacon-sim/1.0", "X-Pad": "p" * args.pad, "Connection": "close"})
            conn.getresponse().read()
            conn.close()
            ok += 1
        except OSError:
            errors += 1
        if i < args.count - 1:
            time.sleep(max(0.0, args.interval * (1 + rng.uniform(-args.jitter, args.jitter))))

    print(json.dumps({"started_at": started, "ended_at": now_iso(), "target": f"{target_ip}:{url.port or 80}",
                      "interval_s": args.interval, "jitter": args.jitter, "sent": ok, "errors": errors}))


if __name__ == "__main__":
    main()
