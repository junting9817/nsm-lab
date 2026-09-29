#!/usr/bin/env python3
"""Comparison step of crosscheck.sh: matches JA3/JA4 per flow between Zeek (ssl.log + conn.log) and Suricata (eve.json).

    python3 testing/fingerprints/compare.py <work dir>   # reads the zeek/ and suricata/ subdirectories

Output: a JSON summary. Exit code 1 if any mismatch is unexplained or nothing was compared.
"""
import hashlib
import json
import sys
from pathlib import Path


def read_json_lines(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def suricata_style_ja4c(raw_exts: str) -> str:
    """JA4_c as Suricata 8.0.6 computes it for a ClientHello without signature algorithms (with a trailing '_')."""
    return hashlib.sha256((raw_exts + "_").encode()).hexdigest()[:12]


def main():
    work = Path(sys.argv[1])
    cid_of = {r["uid"]: r.get("community_id") for r in read_json_lines(work / "zeek/conn.log")}
    zeek = {cid_of.get(r["uid"]): r for r in read_json_lines(work / "zeek/ssl.log") if r.get("ja4")}
    suricata = {
        r["community_id"]: r["tls"]
        for r in read_json_lines(work / "suricata/eve.json")
        if r.get("event_type") == "tls" and r.get("tls", {}).get("ja4")
    }

    both = sorted((set(zeek) & set(suricata)) - {None})
    ja3_match = ja4_match = 0
    known, unexplained = [], []

    for cid in both:
        z, s = zeek[cid], suricata[cid]
        ja3_ok = z.get("ja3") == s.get("ja3", {}).get("hash")
        ja4_ok = z["ja4"] == s["ja4"]
        ja3_match += ja3_ok
        ja4_match += ja4_ok
        if ja3_ok and ja4_ok:
            continue

        raw = z.get("ja4_r", "").split("_")  # [a, ciphers, extensions] means no signature algorithms
        z_a, z_b, _ = z["ja4"].split("_")
        s_a, s_b, s_c = s["ja4"].split("_")
        if ja3_ok and len(raw) == 3 and (z_a, z_b) == (s_a, s_b) and s_c == suricata_style_ja4c(raw[2]):
            known.append({"sni": z.get("server_name", ""), "zeek_ja4": z["ja4"], "suricata_ja4": s["ja4"]})
        else:
            unexplained.append({
                "community_id": cid, "sni": z.get("server_name", ""), "ja4_r": z.get("ja4_r"),
                "zeek": {"ja3": z.get("ja3"), "ja4": z["ja4"]},
                "suricata": {"ja3": s.get("ja3", {}).get("hash"), "ja4": s["ja4"]},
            })

    result = {
        "tls_flows_zeek": len(zeek),
        "tls_flows_suricata": len(suricata),
        "compared": len(both),
        "ja3_match": ja3_match,
        "ja4_match": ja4_match,
        "known_suricata_no_sigalg_underscore": len(known),
        "unexplained_mismatches": len(unexplained),
        "distinct_ja4": len({zeek[c]["ja4"] for c in both}),
        "known_examples": known[:3],
        "unexplained_examples": unexplained[:5],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if both and not unexplained else 1


if __name__ == "__main__":
    sys.exit(main())
