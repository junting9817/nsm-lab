#!/usr/bin/env python3
"""Synthetic traffic scenarios and expected results for the behavior-based detections (DET-101..109).

Each detection gets positive hosts (must be flagged) and negative hosts (must not be flagged) in its own
subnet 10.200.<detection number>.0/24. External peers use RFC 5737 documentation ranges.
All traffic lives on one synthetic day starting 2026-01-05 00:00:00 UTC (Monday 09:00 in Asia/Seoul),
so business-hours logic is deterministic.

    python3 testing/detections/fixtures.py <out_dir>     # writes <out_dir>/fixtures.pcap and <out_dir>/expectations.json

The PCAP is analyzed by offline Zeek with the production site config, loaded into database nsm_test and checked
with the same SQL that runs in production (testing/detections/validate.sh).
"""
import base64
import json
import random
import string
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pcap"))
from pcaplib import (Clock, app_data, client_hello, client_key_exchange_finished, dns_exchange,  # noqa: E402
                     server_finished, server_hello_certificate, syn_probe, tcp_flow)
from scapy.all import wrpcap  # noqa: E402

BASE = datetime(2026, 1, 5, tzinfo=timezone.utc).timestamp()
HOUR = 3600.0
RNG = random.Random(20260105)
WINDOW = {"from": "2026-01-05 00:00:00", "to": "2026-01-06 00:00:00"}

_ports = {}


def cport(host: str) -> int:
    """A fresh client port per host so repeated sessions never reuse a 5-tuple."""
    _ports[host] = _ports.get(host, 40000) + 1
    return _ports[host]


def http_get(host: str, path: str = "/", pad: int = 0) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fixture/1.0\r\n"
            f"X-Pad: {'p' * pad}\r\nConnection: close\r\n\r\n").encode()


def http_ok(body: bytes = b"ok") -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


# --- DET-101 beaconing ---------------------------------------------------------------------------

def beacon(src, dst, times):
    pkts = []
    for t in times:
        pkts += tcp_flow(src, cport(src), dst, 80, [("c", http_get(dst, "/c", pad=40)), ("s", http_ok(b"noop"))], Clock(t))
    return pkts


def det101():
    n, interval = 150, 60.0

    def jittered(start, jitter):
        t, out = start, []
        for _ in range(n):
            out.append(t)
            t += interval * (1 + RNG.uniform(-jitter, jitter))
        return out

    random_times, t = [], BASE + 0.5 * HOUR
    for _ in range(n):
        random_times.append(t)
        t += RNG.expovariate(1 / interval)

    tls_beacon = []
    for t in jittered(BASE + 0.5 * HOUR, 0.05):
        hello = client_hello(COMMON_CIPHERS, COMMON_EXTS, sni="telemetry.allowed.test", alpn=["h2"], supported_versions=[0x0304])
        tls_beacon += tls_client_only("10.200.101.14", "198.51.100.105", t, hello)

    pkts = tls_beacon + (beacon("10.200.101.10", "198.51.100.101", jittered(BASE + 0.5 * HOUR, 0.10))
            + beacon("10.200.101.11", "198.51.100.102", random_times)
            + beacon("10.200.101.12", "198.51.100.103", jittered(BASE + 0.5 * HOUR, 0.0)[:10])
            + beacon("10.200.101.13", "198.51.100.104", jittered(BASE + 0.5 * HOUR, 0.90)))
    expect = {
        "detection": "DET-101", "window": WINDOW, "params": {},
        "flag": [{"src": "10.200.101.10", "dst": "198.51.100.101", "dst_port": 80}],
        "no_flag": ["10.200.101.11", "10.200.101.12", "10.200.101.13", "10.200.101.14"],
        "notes": {"10.200.101.10": "60s ±10% jitter", "10.200.101.11": "exponential gaps (random)",
                  "10.200.101.12": "regular but only 10 connections", "10.200.101.13": "60s ±90% jitter",
                  "10.200.101.14": "60s ±5% TLS beacon to *.allowed.test, suppressed by active allowlist entry TUNE-901-TEST"},
    }
    unsuppressed = {
        "detection": "DET-101", "window": WINDOW, "params": {"use_allowlist": "0"},
        "flag": [{"src": "10.200.101.14", "dst": "198.51.100.105", "dst_port": 443}], "no_flag": [],
        "notes": {"10.200.101.14": "same TLS beacon with use_allowlist=0 — proves the allowlist is what hides it"},
    }
    return pkts, [expect, unsuppressed]


# --- DET-102 long connections ---------------------------------------------------------------------

def keepalive_session(src, dst, start, duration, every=120.0):
    exchanges = []
    for _ in range(int(duration // every)):
        exchanges += [("c", b"k" * 32, every), ("s", b"a" * 32)]
    return tcp_flow(src, cport(src), dst, 8883, exchanges, Clock(start))


def det102():
    pkts = (keepalive_session("10.200.102.10", "198.51.100.120", BASE + 1 * HOUR, 2 * HOUR)
            + keepalive_session("10.200.102.11", "198.51.100.121", BASE + 1 * HOUR, 10 * 60)
            + keepalive_session("10.200.102.12", "198.51.100.122", BASE + 1 * HOUR, 2 * HOUR))
    expect = {
        "detection": "DET-102", "window": WINDOW, "params": {},
        "flag": [{"src": "10.200.102.10", "dst": "198.51.100.120"}, {"src": "10.200.102.12", "dst": "198.51.100.122"}],
        "no_flag": ["10.200.102.11"],
        "notes": {"10.200.102.10": "2 h session with keepalives", "10.200.102.11": "10 min session",
                  "10.200.102.12": "2 h session; its allowlist entry TUNE-903-TEST expired in 2020, so it must still be reported"},
    }
    return pkts, expect


# --- DET-103 rare JA4 -----------------------------------------------------------------------------

COMMON_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
COMMON_EXTS = [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27]


def tls_client_only(src, dst, start, hello):
    """ClientHello, a server record and close — enough for Zeek to log ssl.log with a JA4, without certificates."""
    return tcp_flow(src, cport(src), dst, 443, [("c", hello), ("s", app_data(80)), ("c", app_data(40))], Clock(start))


def det103():
    pkts = []
    for i in range(30):
        src = f"10.200.103.{20 + i % 3}"
        hello = client_hello(COMMON_CIPHERS, COMMON_EXTS, sni=f"app{i % 5}.common.test", alpn=["h2", "http/1.1"],
                             supported_versions=[0x0304, 0x0303])
        pkts += tls_client_only(src, "198.51.100.130", BASE + (i * 0.7) * HOUR, hello)
    rare = client_hello([0x0035, 0x002f, 0x000a], [0, 10, 11], sni="update.rare-client.test")
    pkts += tls_client_only("10.200.103.10", "203.0.113.130", BASE + 10 * HOUR, rare)
    expect = {
        "detection": "DET-103", "window": WINDOW, "params": {},
        "flag": [{"src": "10.200.103.10", "dst": "203.0.113.130"}],
        "no_flag": ["10.200.103.20", "10.200.103.21", "10.200.103.22"],
        "notes": {"10.200.103.10": "one-off TLS 1.2 ClientHello with 3 legacy ciphers",
                  "10.200.103.2x": "same browser-like ClientHello 30 times from 3 hosts"},
    }
    return pkts, expect


# --- DET-104 suspicious certificates --------------------------------------------------------------

def self_signed_der(common_name: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        cert = Path(d) / "cert.der"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", str(Path(d) / "key.pem"), "-subj", f"/CN={common_name}", "-addext", f"subjectAltName=DNS:{common_name}",
             "-not_before", "20250101000000Z", "-not_after", "20300101000000Z", "-outform", "DER", "-out", str(cert)],
            check=True, capture_output=True)
        return cert.read_bytes()


def tls12_with_cert(src, dst, start, sni, cert_der):
    hello = client_hello([0xc02f, 0xc030, 0x009c], [0, 10, 11, 13, 65281], sni=sni)
    return tcp_flow(src, cport(src), dst, 443, [
        ("c", hello), ("s", server_hello_certificate(cert_der)),
        ("c", client_key_exchange_finished()), ("s", server_finished()),
        ("c", app_data(120)), ("s", app_data(300)),
    ], Clock(start))


def det104():
    pkts = (tls12_with_cert("10.200.104.10", "198.51.100.140", BASE + 2 * HOUR, "login.bank.test", self_signed_der("evil.test"))
            + tls12_with_cert("10.200.104.11", "198.51.100.141", BASE + 2 * HOUR, "internal.app.test", self_signed_der("internal.app.test"))
            + tls_client_only("10.200.104.12", "198.51.100.142", BASE + 2 * HOUR,
                              client_hello(COMMON_CIPHERS, COMMON_EXTS, sni="modern.site.test", alpn=["h2"], supported_versions=[0x0304])))
    expect = {
        "detection": "DET-104", "window": WINDOW, "params": {},
        "flag": [{"src": "10.200.104.10", "reasons": ["self_signed", "sni_mismatch"], "severity": "high"},
                 {"src": "10.200.104.11", "reasons": ["self_signed"], "severity": "medium"}],
        "no_flag": ["10.200.104.12"],
        "notes": {"10.200.104.10": "SNI login.bank.test, self-signed cert for evil.test",
                  "10.200.104.11": "self-signed cert whose name matches SNI",
                  "10.200.104.12": "TLS 1.3-style session, no certificate visible"},
    }
    return pkts, expect


# --- DET-105 DNS tunneling -------------------------------------------------------------------------

def det105():
    pkts = []
    for i in range(120):
        label = base64.b32encode(RNG.randbytes(30)).decode().lower().rstrip("=")
        pkts += dns_exchange("10.200.105.10", cport("10.200.105.10"), "198.51.100.53", f"{label}.{i}.exfil-tunnel.test",
                             BASE + 4 * HOUR + i * 2, qtype="TXT", txid=i)
    normal = ["www.example.com", "api.example.com", "cdn.example.net", "mail.example.org", "static.example.com"]
    for i in range(120):
        pkts += dns_exchange("10.200.105.11", cport("10.200.105.11"), "198.51.100.53", normal[i % len(normal)],
                             BASE + 4 * HOUR + i * 2, answer="198.51.100.200", txid=1000 + i)
    expect = {
        "detection": "DET-105", "window": WINDOW, "params": {},
        "flag": [{"src": "10.200.105.10", "base_domain": "exfil-tunnel.test"}],
        "no_flag": ["10.200.105.11"],
        "notes": {"10.200.105.10": "120 TXT queries with 48-char base32 labels",
                  "10.200.105.11": "120 A queries to five ordinary names"},
    }
    return pkts, expect


# --- DET-106 DGA / NXDOMAIN spike -----------------------------------------------------------------

def det106():
    pkts = []
    src = "10.200.106.10"
    for h in range(13):  # quiet baseline: two lookups per hour
        for k in range(2):
            pkts += dns_exchange(src, cport(src), "198.51.100.53", "www.example.com", BASE + h * HOUR + k * 600,
                                 answer="198.51.100.200", txid=h * 10 + k)
    spike_start = BASE + 13 * HOUR + 60
    for i in range(60):  # burst of generated domains, 90 % unregistered
        name = "".join(RNG.choice(string.ascii_lowercase) for _ in range(12)) + ".com"
        nx = i % 10 != 0
        pkts += dns_exchange(src, cport(src), "198.51.100.53", name, spike_start + i * 4,
                             rcode=3 if nx else 0, answer=None if nx else "198.51.100.201", txid=5000 + i)
    other = "10.200.106.11"
    for b in range(144):  # steady resolver user: 30 lookups per 10 min, occasional typo
        for k in range(30):
            nx = (b * 30 + k) % 20 == 0
            pkts += dns_exchange(other, cport(other), "198.51.100.53", "typo.exampel.com" if nx else "www.example.org",
                                 BASE + b * 600 + k * 19, rcode=3 if nx else 0, answer=None if nx else "198.51.100.202",
                                 txid=(b * 30 + k) % 65535)
    expect = {
        "detection": "DET-106", "window": {"from": "2026-01-05 13:00:00", "to": "2026-01-05 14:00:00"},
        "params": {"baseline_hours": "13"},
        "flag": [{"src": "10.200.106.10"}],
        "no_flag": ["10.200.106.11"],
        "notes": {"10.200.106.10": "2 lookups/h for 13 h, then 54 NXDOMAIN among 60 random .com names in 4 min",
                  "10.200.106.11": "30 lookups per 10 min all day with 5 % NXDOMAIN"},
    }
    return pkts, expect


# --- DET-107 exfiltration --------------------------------------------------------------------------

def det107():
    mb = 1_000_000
    pkts = (tcp_flow("10.200.107.10", cport("10.200.107.10"), "198.51.100.170", 443,
                     [("c", b"u" * (3 * mb)), ("s", b"r" * 20_000)], Clock(BASE + 3 * HOUR), gap=0.0005)
            + tcp_flow("10.200.107.11", cport("10.200.107.11"), "198.51.100.171", 443,
                       [("c", b"u" * (1 * mb)), ("s", b"r" * 5_000)], Clock(BASE + 16 * HOUR), gap=0.0005)
            + tcp_flow("10.200.107.12", cport("10.200.107.12"), "198.51.100.172", 443,
                       [("c", b"q" * 10_000), ("s", b"d" * (3 * mb))], Clock(BASE + 3 * HOUR), gap=0.0005)
            + tcp_flow("10.200.107.13", cport("10.200.107.13"), "198.51.100.173", 443,
                       [("c", b"u" * (3 * mb)), ("s", b"r" * 20_000)], Clock(BASE + 3.5 * HOUR), gap=0.0005))
    expect = {
        "detection": "DET-107", "window": WINDOW,
        "params": {"min_upload_bytes": "2000000", "min_upload_bytes_offhours": "500000"},
        "flag": [{"src": "10.200.107.10", "reasons": ["upload_heavy"]},
                 {"src": "10.200.107.11", "reasons": ["offhours_bulk_upload"]}],
        "no_flag": ["10.200.107.12", "10.200.107.13"],
        "notes": {"10.200.107.13": "3 MB upload to 198.51.100.173, suppressed by active IP entry TUNE-902-TEST",
                  "10.200.107.10": "3 MB up / 20 KB down at 12:00 KST Monday",
                  "10.200.107.11": "1 MB up at 01:00 KST Tuesday (below the business-hours threshold)",
                  "10.200.107.12": "3 MB download"},
    }
    return pkts, expect


# --- DET-108 non-standard port --------------------------------------------------------------------

def ssh_packet(payload: bytes) -> bytes:
    """SSH binary packet (RFC 4253 §6): length, padding length, payload, padding (block size 8, at least 4 bytes)."""
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    return (len(payload) + padding + 1).to_bytes(4, "big") + bytes([padding]) + payload + b"\x00" * padding


def ssh_string(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def ssh_kexinit() -> bytes:
    """SSH_MSG_KEXINIT (RFC 4253 §7.1)."""
    lists = ["curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256",
             "none", "none", "", ""]
    payload = bytes([20]) + b"\x42" * 16 + b"".join(ssh_string(x.encode()) for x in lists) + b"\x00" + b"\x00" * 4
    return ssh_packet(payload)


def ssh_banners(src, dst, port, start):
    """Version exchange, KEXINIT, ECDH key exchange (RFC 5656) and NEWKEYS, then encrypted-looking packets.
    Zeek labels a connection service=ssh only after the key exchange, not after the banners (checked against live traffic)."""
    host_key = ssh_string(b"ssh-ed25519") + ssh_string(b"\x21" * 32)
    signature = ssh_string(b"ssh-ed25519") + ssh_string(b"\x31" * 64)
    return tcp_flow(src, cport(src), dst, port, [
        ("s", b"SSH-2.0-OpenSSH_9.6\r\n"), ("c", b"SSH-2.0-OpenSSH_9.6\r\n"),
        ("c", ssh_kexinit()), ("s", ssh_kexinit()),
        ("c", ssh_packet(bytes([30]) + ssh_string(b"\x51" * 32))),
        ("s", ssh_packet(bytes([31]) + ssh_string(host_key) + ssh_string(b"\x61" * 32) + ssh_string(signature))),
        ("c", ssh_packet(bytes([21]))), ("s", ssh_packet(bytes([21]))),
        ("c", b"\x9e" * 52), ("s", b"\x8d" * 52), ("c", b"\x7c" * 116), ("s", b"\x6b" * 244),
    ], Clock(start))


def det108():
    t = BASE + 6 * HOUR
    pkts = (tcp_flow("10.200.108.10", cport("10.200.108.10"), "198.51.100.180", 4444,
                     [("c", http_get("198.51.100.180", "/tasks")), ("s", http_ok(b"sleep 60"))], Clock(t))
            + ssh_banners("10.200.108.11", "198.51.100.181", 2222, t)
            + tcp_flow("10.200.108.12", cport("10.200.108.12"), "198.51.100.182", 80,
                       [("c", http_get("198.51.100.182", "/")), ("s", http_ok(b"hello"))], Clock(t))
            + ssh_banners("10.200.108.13", "198.51.100.183", 22, t)
            + tcp_flow("10.200.108.14", cport("10.200.108.14"), "198.51.100.184", 4444,
                       [("c", http_get("198.51.100.184", "/tasks")), ("s", http_ok(b"sleep 60"))], Clock(t + 1)))
    expect = {
        "detection": "DET-108", "window": WINDOW, "params": {},
        "flag": [{"src": "10.200.108.10", "dst_port": 4444, "protocols": "http", "severity": "high"},
                 {"src": "10.200.108.11", "dst_port": 2222, "protocols": "ssh", "severity": "medium"},
                 {"src": "10.200.108.14", "dst_port": 4444, "protocols": "http"}],
        "no_flag": ["10.200.108.12", "10.200.108.13"],
        "notes": {"10.200.108.10": "HTTP on 4444", "10.200.108.11": "SSH on 2222",
                  "10.200.108.14": "HTTP on 4444; its allowlist entry TUNE-904-TEST is disabled, so it must still be reported",
                  "10.200.108.12": "HTTP on 80", "10.200.108.13": "SSH on 22"},
    }
    return pkts, expect


# --- DET-109 scanning ------------------------------------------------------------------------------

def det109():
    t = BASE + 8 * HOUR
    pkts = []
    for i, port in enumerate(range(1, 121)):  # external vertical scan, no answers
        pkts += syn_probe("203.0.113.190", 50000, "10.200.109.10", port, t + i * 0.05, reply="none")
    for i in range(60):  # internal horizontal sweep of port 445, hosts refuse
        pkts += syn_probe("10.200.109.20", 51000 + i, f"10.200.109.{100 + i}", 445, t + 30 + i * 0.05, reply="rst")
    for i in range(5):  # ordinary client
        pkts += tcp_flow("10.200.109.30", cport("10.200.109.30"), "198.51.100.190", 80 if i % 2 == 0 else 443,
                         [("c", http_get("198.51.100.190")), ("s", http_ok())], Clock(t + 60 + i))
    expect = {
        "detection": "DET-109", "window": WINDOW, "params": {},
        "flag": [{"src": "203.0.113.190", "scan_type": "vertical", "attack_technique": "T1595.001"},
                 {"src": "10.200.109.20", "scan_type": "horizontal", "attack_technique": "T1046", "severity": "high"}],
        "no_flag": ["10.200.109.30"],
        "notes": {"203.0.113.190": "SYN to 120 ports of one host, no answers",
                  "10.200.109.20": "SYN to port 445 on 60 local hosts, RST back",
                  "10.200.109.30": "5 normal web connections"},
    }
    return pkts, expect


SCENARIOS = [det101, det102, det103, det104, det105, det106, det107, det108, det109]


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    packets, expectations = [], []
    for build in SCENARIOS:
        pkts, expect = build()
        packets += pkts
        expectations += expect if isinstance(expect, list) else [expect]
    packets.sort(key=lambda p: float(p.time))  # offline Zeek needs time-ordered packets
    wrpcap(str(out / "fixtures.pcap"), packets)
    (out / "expectations.json").write_text(json.dumps(expectations, indent=2))
    print(f"fixtures.pcap: {len(packets)} packets, {(out / 'fixtures.pcap').stat().st_size} bytes; "
          f"{len(expectations)} expectation sets, {sum(len(e['flag']) + len(e['no_flag']) for e in expectations)} host checks")


if __name__ == "__main__":
    main()
