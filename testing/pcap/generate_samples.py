#!/usr/bin/env python3
"""Synthetic PCAP generator for the validation harness.

Instead of real malware PCAPs from elsewhere, it builds traffic holding only the "indicators" a specific ET Open rule looks for.
    - Reproducible: fixed IPs, ports, sequence numbers and timestamps give the same bytes every time
    - Safe: no executable payloads, and small enough to commit to the repo
    - Addresses: victim hosts are 10.200.0.0/24 inside HOME_NET (10.128.0.0/9),
                         external hosts use the RFC 5737 documentation ranges (198.51.100.0/24, 203.0.113.0/24), which never overlap real internet addresses

Cases and expected SIDs are in testing/pcap/cases.json.

    python3 testing/pcap/generate_samples.py          # writes testing/pcap/samples/*.pcap
"""
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether, wrpcap

from pcaplib import CLIENT_MAC, SERVER_MAC, Clock, tcp_session

OUT = Path(__file__).resolve().parent / "samples"
BASE_TS = 1_767_225_600.0  # 2026-01-01T00:00:00Z — replay rewrites it to capture time, so the value itself does not matter


def http_response(status: str, body: bytes, content_type: str = "text/html") -> bytes:
    head = (
        f"HTTP/1.1 {status}\r\n"
        "Server: Apache\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    )
    return head.encode() + body


def scan_nmap_nse_http():
    """T1595.002 vulnerability scanning: sweeps a web server with the default Nmap NSE User-Agent."""
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 10.200.0.10\r\n"
        b"User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\r\n"
        b"Connection: close\r\n\r\n"
    )
    response = http_response("404 Not Found", b"<html><body>Not Found</body></html>")
    return tcp_session("198.51.100.23", 51234, "10.200.0.10", 80, request, response, Clock(BASE_TS))


def attack_response_id_root():
    """T1059.004 Unix shell: a command injection succeeds and the `id` output (root) comes back in the HTTP response."""
    request = (
        b"GET /cgi-bin/status.cgi?host=127.0.0.1 HTTP/1.1\r\n"
        b"Host: 10.200.0.11\r\n"
        b"User-Agent: curl/8.5.0\r\n"
        b"Connection: close\r\n\r\n"
    )
    response = http_response("200 OK", b"uid=0(root) gid=0(root) groups=0(root)\n", "text/plain")
    return tcp_session("203.0.113.50", 44321, "10.200.0.11", 80, request, response, Clock(BASE_TS))


def c2_dns_nxransomware():
    """T1071.004 DNS C2: an infected host looks up a known ransomware C2 domain."""
    clock = Clock(BASE_TS)
    qname = "0cf5ff34.ngrok.io"
    query = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.200.0.20", dst="198.51.100.53")
        / UDP(sport=53001, dport=53)
        / DNS(id=0x4E53, rd=1, qd=DNSQR(qname=qname, qtype="A"))
    )
    answer = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="198.51.100.53", dst="10.200.0.20")
        / UDP(sport=53, dport=53001)
        / DNS(id=0x4E53, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=qname, qtype="A"),
              an=DNSRR(rrname=qname, type="A", ttl=60, rdata="198.51.100.99"))
    )
    query.time = clock.tick()
    answer.time = clock.tick()
    return [query, answer]


def exploit_apache_path_traversal():
    """T1190 exploit public-facing application: Apache 2.4.49 path traversal to /bin/sh (CVE-2021-41773).

    Modeled on the RedTail botnet requests seen against this sensor on 2026-09-14 (user agent libredtail-http, same URL);
    the body is a harmless `id` instead of the real downloader.
    """
    body = b"echo Content-Type: text/plain; echo; id"
    request = (
        b"POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1\r\n"
        b"Host: 10.200.0.12\r\n"
        b"User-Agent: libredtail-http\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )
    # 302 as the sensor actually answered (Grafana redirects unknown paths to /login)
    response = http_response("302 Found", b"<a href=\"/login\">Found</a>.")
    return tcp_session("198.51.100.77", 47811, "10.200.0.12", 80, request, response, Clock(BASE_TS))


CASES = {
    "scan-nmap-nse-http": scan_nmap_nse_http,
    "attack-response-id-root": attack_response_id_root,
    "c2-dns-nxransomware": c2_dns_nxransomware,
    "exploit-apache-path-traversal": exploit_apache_path_traversal,
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in CASES.items():
        path = OUT / f"{name}.pcap"
        packets = build()
        wrpcap(str(path), packets)
        print(f"{path.relative_to(OUT.parent.parent.parent)}  packets={len(packets)}  bytes={path.stat().st_size}")


if __name__ == "__main__":
    main()
