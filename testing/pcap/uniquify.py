#!/usr/bin/env python3
"""Rewrites client ports in a PCAP so every replay becomes a distinct flow.

Why: replaying the same PCAP again shortly after leaves IPs, ports and TCP sequence numbers identical, so packets
attach to the "closed session" still in Suricata's flow table (kept 60 s by default). It is not seen as a new connection,
so no HTTP parsing or alert happens (found in the validation harness on 2026-09-14).

How: for each flow (5-tuple) the side that sent the first packet is the client, and only its port changes.
Server ports, IP addresses and payloads stay the same, so rule match conditions ($HOME_NET, service ports, content) do not change.

        python3 testing/pcap/uniquify.py <input.pcap> <output.pcap> [--seed N]
"""
import argparse
import random

from scapy.all import IP, TCP, UDP, IPv6, rdpcap, wrpcap


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("src")
    parser.add_argument("dst")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    packets = rdpcap(args.src)
    client_of = {}  # normalized flow key → (client IP, original port)
    new_port = {}  # (client IP, original port) → new port
    used = set()

    for pkt in packets:
        l3 = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if l3 is None or l4 is None:
            continue
        a, b = (l3.src, l4.sport), (l3.dst, l4.dport)
        key = (type(l4).__name__, frozenset((a, b)))
        if key not in client_of:
            client_of[key] = a
        client = client_of[key]
        if client not in new_port:
            port = rng.randint(20000, 60999)
            while port in used:
                port = rng.randint(20000, 60999)
            used.add(port)
            new_port[client] = port

        if (l3.src, l4.sport) == client:
            l4.sport = new_port[client]
        elif (l3.dst, l4.dport) == client:
            l4.dport = new_port[client]
        # Delete checksums so scapy recomputes them
        del l4.chksum
        if isinstance(l3, IP):
            del l3.chksum

    wrpcap(args.dst, packets)


if __name__ == "__main__":
    main()
