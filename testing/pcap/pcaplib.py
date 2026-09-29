"""Shared helpers for synthetic PCAPs (used by testing/pcap/generate_samples.py and testing/detections/fixtures.py).

Every packet gets an explicit timestamp. Offline Zeek (-r) uses packet timestamps as network time,
so hours of beaconing or an off-hours transfer fit into one small PCAP.
"""
import struct

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


class Clock:
    """Monotonic timestamps with a small step per packet."""

    def __init__(self, start: float):
        self.t = start

    def tick(self, step: float = 0.01) -> float:
        self.t += step
        return self.t


def tcp_session(client, cport, server, sport, request: bytes, response: bytes, clock: Clock):
    """Complete TCP session: 3-way handshake, request, response, FIN from both sides.

    Suricata's flow:established and HTTP parser need the handshake and consistent seq/ack numbers.
    """
    return tcp_flow(client, cport, server, sport, [("c", request), ("s", response)], clock)


def tcp_flow(client, cport, server, sport, exchanges, clock: Clock, gap: float = 0.01, close: str = "fin"):
    """TCP flow: handshake, exchanges, then close.

    exchanges: [(direction 'c'|'s', payload bytes, [seconds to wait before this exchange])...]
               Long payloads are split into 1400-byte segments, each ACKed by the other side.
    close: 'fin' (FIN from both sides) | 'none' (leave the connection open)
    """
    c_isn, s_isn = 1_000_000, 2_000_000
    c2s = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=client, dst=server)
    s2c = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=server, dst=client)
    pkts = []

    def add(pkt, step=gap):
        pkt.time = clock.tick(step)
        pkts.append(pkt)

    c_seq, s_seq = c_isn, s_isn
    add(c2s / TCP(sport=cport, dport=sport, flags="S", seq=c_seq))
    add(s2c / TCP(sport=sport, dport=cport, flags="SA", seq=s_seq, ack=c_seq + 1))
    c_seq += 1
    s_seq += 1
    add(c2s / TCP(sport=cport, dport=sport, flags="A", seq=c_seq, ack=s_seq))

    for exchange in exchanges:
        direction, payload = exchange[0], exchange[1]
        wait = exchange[2] if len(exchange) > 2 else gap
        first = True
        for i in range(0, len(payload), 1400):
            chunk = payload[i:i + 1400]
            step = wait if first else gap
            first = False
            if direction == "c":
                add(c2s / TCP(sport=cport, dport=sport, flags="PA", seq=c_seq, ack=s_seq) / chunk, step)
                c_seq += len(chunk)
                add(s2c / TCP(sport=sport, dport=cport, flags="A", seq=s_seq, ack=c_seq))
            else:
                add(s2c / TCP(sport=sport, dport=cport, flags="PA", seq=s_seq, ack=c_seq) / chunk, step)
                s_seq += len(chunk)
                add(c2s / TCP(sport=cport, dport=sport, flags="A", seq=c_seq, ack=s_seq))

    if close == "fin":
        add(c2s / TCP(sport=cport, dport=sport, flags="FA", seq=c_seq, ack=s_seq))
        c_seq += 1
        add(s2c / TCP(sport=sport, dport=cport, flags="FA", seq=s_seq, ack=c_seq))
        s_seq += 1
        add(c2s / TCP(sport=cport, dport=sport, flags="A", seq=c_seq, ack=s_seq))
    return pkts


def syn_probe(src, sport, dst, dport, t: float, reply: str = "none"):
    """Single scan SYN. reply: 'none' (no answer → Zeek S0) | 'rst' (RST → REJ) | 'synack'."""
    syn = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=7000)
    syn.time = t
    pkts = [syn]
    if reply == "rst":
        rst = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=7001)
        rst.time = t + 0.001
        pkts.append(rst)
    elif reply == "synack":
        sa = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=9000, ack=7001)
        sa.time = t + 0.001
        pkts.append(sa)
    return pkts


def dns_exchange(client, cport, resolver, qname: str, t: float, qtype: str = "A", rcode: int = 0,
                 answer: str = None, txid: int = 0x1234, rtt: float = 0.02):
    """One DNS query and its response. rcode=3 means NXDOMAIN."""
    query = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=client, dst=resolver) / UDP(sport=cport, dport=53)
             / DNS(id=txid, rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
    an = None
    if rcode == 0 and answer is not None:
        an = DNSRR(rrname=qname, type=qtype, ttl=60, rdata=answer)
    resp = (Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=resolver, dst=client) / UDP(sport=53, dport=cport)
            / DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype), an=an))
    query.time = t
    resp.time = t + rtt
    return [query, resp]


# --- TLS messages (assembled byte by byte) --------------------------------------------------------

def _u16(v): return struct.pack(">H", v)
def _u24(v): return struct.pack(">I", v)[1:]


def tls_record(content_type: int, body: bytes, version: int = 0x0303) -> bytes:
    return bytes([content_type]) + _u16(version) + _u16(len(body)) + body


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + _u24(len(body)) + body


def client_hello(ciphers, extensions_order, sni=None, alpn=None, groups=(0x001d, 0x0017), point_formats=(0,),
                 sig_algs=(0x0403, 0x0804, 0x0401), supported_versions=None, legacy_version=0x0303, random=b"\x11" * 32) -> bytes:
    """ClientHello record. extensions_order lists extension codes in wire order (0=SNI, 10=groups, 11=point formats, 13=sig algs, 16=ALPN, 43=versions, anything else is sent empty)."""
    ext_bytes = b""
    for code in extensions_order:
        if code == 0 and sni:
            name = sni.encode()
            data = _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name
        elif code == 10:
            data = _u16(2 * len(groups)) + b"".join(_u16(g) for g in groups)
        elif code == 11:
            data = bytes([len(point_formats)]) + bytes(point_formats)
        elif code == 13:
            data = _u16(2 * len(sig_algs)) + b"".join(_u16(s) for s in sig_algs)
        elif code == 16 and alpn:
            protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
            data = _u16(len(protos)) + protos
        elif code == 43 and supported_versions:
            data = bytes([2 * len(supported_versions)]) + b"".join(_u16(v) for v in supported_versions)
        else:
            data = b""
        ext_bytes += _u16(code) + _u16(len(data)) + data
    body = (_u16(legacy_version) + random + b"\x00" + _u16(2 * len(ciphers)) + b"".join(_u16(c) for c in ciphers)
            + b"\x01\x00" + _u16(len(ext_bytes)) + ext_bytes)
    return tls_record(22, _handshake(1, body), version=0x0301)


def server_hello_certificate(cert_der: bytes, cipher: int = 0xc02f, random=b"\x22" * 32) -> bytes:
    """TLS 1.2 ServerHello + Certificate + ServerHelloDone in one record."""
    hello = _u16(0x0303) + random + b"\x20" + b"\x33" * 32 + _u16(cipher) + b"\x00"
    certs = _u24(len(cert_der)) + cert_der
    certificate = _u24(len(certs)) + certs
    body = _handshake(2, hello) + _handshake(11, certificate) + _handshake(14, b"")
    return tls_record(22, body)


def client_key_exchange_finished() -> bytes:
    """ClientKeyExchange + ChangeCipherSpec + (encrypted-looking) Finished."""
    cke = tls_record(22, _handshake(16, bytes([65]) + b"\x04" + b"\x44" * 64))
    return cke + tls_record(20, b"\x01") + tls_record(22, b"\x55" * 40)


def server_finished() -> bytes:
    """ChangeCipherSpec + (encrypted-looking) Finished."""
    return tls_record(20, b"\x01") + tls_record(22, b"\x66" * 40)


def app_data(n: int = 64) -> bytes:
    return tls_record(23, b"\x77" * n)
