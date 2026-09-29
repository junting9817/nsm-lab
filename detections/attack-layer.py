#!/usr/bin/env python3
"""Generate the ATT&CK Navigator layer and the coverage table from the detection catalog.

    sudo detections/attack-layer.py            # write detections/attack-map.json and rebuild nsm.attack_coverage
    detections/attack-layer.py --no-db         # layer file only (no ClickHouse access needed)

Sources (the catalog stays the single source of truth for what each detection covers):
  docs/detection-catalog.md   index table: ID, ATT&CK column, Status — a row counts as validated when its status starts
                              with "Validated" or "Enforcing"
  detections/attack-targets.tsv  the techniques this sensor should be able to see (coverage denominator)
  ClickHouse (optional)       techniques observed in production: Suricata rule metadata on ens4 (last 30 days, alerts with a
                              false-positive verdict excluded) and honeypot activity (logins, commands, file transfers)

Scores in the layer: 2 validated detection, 1 observed in production only, 0 target without either (a gap).
"""
import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs" / "detection-catalog.md"
TARGETS = ROOT / "detections" / "attack-targets.tsv"
LAYER = ROOT / "detections" / "attack-map.json"
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
INDEX_ROW = re.compile(r"^\| ((?:DET|RSP)-\d{3}) \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|$")

# Honeypot event types → what they show an attacker doing (Cowrie on the isolated honeypot VM)
HONEYPOT_TECHNIQUES = {
    "T1110.001": "eventid IN ('cowrie.login.failed', 'cowrie.login.success')",
    "T1059.004": "eventid = 'cowrie.command.input'",
    "T1105": "eventid IN ('cowrie.session.file_upload', 'cowrie.session.file_download', 'cowrie.session.file_download.failed')",
}


def ch(query):
    out = subprocess.run(["docker", "exec", "nsm-clickhouse", "clickhouse-client", "-q", query],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def ch_insert(query, payload):
    subprocess.run(["docker", "exec", "-i", "nsm-clickhouse", "clickhouse-client", "-q", query],
                   input=payload.encode(), capture_output=True, check=True)


def read_catalog():
    detections = []
    for line in CATALOG.read_text().splitlines():
        m = INDEX_ROW.match(line.strip())
        if not m:
            continue
        det_id, name, _type, attack, status = (g.strip() for g in m.groups())
        detections.append({
            "id": det_id, "name": name, "techniques": sorted(set(TECHNIQUE_RE.findall(attack))),
            "validated": status.startswith(("Validated", "Enforcing")), "status": status,
        })
    if not detections:
        raise SystemExit(f"no detection rows found in {CATALOG}")
    return detections


def read_targets():
    rows = TARGETS.read_text().splitlines()
    header = rows[0].split("\t")
    return {r["technique_id"]: r for r in (dict(zip(header, line.split("\t"))) for line in rows[1:] if line.strip())}


def observed_in_production():
    observed = {}
    for technique, sources in ch("""
        SELECT t, toString(uniqExact(a.src_ip))
        FROM nsm.suricata_alert AS a ARRAY JOIN a.alert_metadata_mitre_technique_id AS t
        LEFT ANTI JOIN (SELECT subject FROM nsm.verdicts WHERE source = 'suricata'
                        GROUP BY subject HAVING argMax(verdict, created_at) = 'false_positive') AS fp
          ON fp.subject = concat(toString(a.alert_signature_id), '|', a.src_ip)
        WHERE a.in_iface = 'ens4' AND a.timestamp > now() - INTERVAL 30 DAY
        GROUP BY t"""):
        observed.setdefault(technique, []).append(f"suricata ({sources} sources)")
    for technique, condition in HONEYPOT_TECHNIQUES.items():
        sources = int(ch(f"SELECT uniqExact(src_ip) FROM nsm.cowrie_events WHERE {condition} AND timestamp > now() - INTERVAL 30 DAY")[0][0])
        if sources:
            observed.setdefault(technique, []).append(f"honeypot ({sources} sources)")
    return observed


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--no-db", action="store_true", help="skip production observations and the ClickHouse table")
    args = ap.parse_args()

    detections = read_catalog()
    targets = read_targets()
    observed = {} if args.no_db else observed_in_production()

    by_technique = {}
    for d in detections:
        for t in d["techniques"]:
            entry = by_technique.setdefault(t, {"validated": [], "catalogued": []})
            entry["catalogued"].append(d["id"])
            if d["validated"]:
                entry["validated"].append(d["id"])

    techniques = sorted(set(targets) | set(by_technique) | set(observed))
    rows, layer_techniques = [], []
    for t in techniques:
        validated = by_technique.get(t, {}).get("validated", [])
        seen = observed.get(t, [])
        status = "validated" if validated else "observed" if seen else "gap"
        target = targets.get(t, {})
        score = {"validated": 2, "observed": 1, "gap": 0}[status]
        comment = "; ".join(filter(None, [
            f"validated by {', '.join(validated)}" if validated else "",
            f"observed: {', '.join(seen)}" if seen else "",
            "in target list, no detection yet" if status == "gap" else "",
            "" if t in targets else "outside the target list",
        ]))
        layer_techniques.append({
            "techniqueID": t, "score": score, "comment": comment, "enabled": True, "showSubtechniques": False,
            "metadata": [{"name": "status", "value": status}] + [{"name": "detection", "value": d} for d in validated],
        })
        rows.append({"technique_id": t, "name": target.get("name", ""), "tactic": target.get("tactic", ""), "in_target": t in targets,
                     "status": status, "detections": validated, "observed_by": seen,
                     "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")})

    in_target = [r for r in rows if r["in_target"]]
    validated_n = sum(r["status"] == "validated" for r in in_target)
    observed_n = sum(r["status"] == "observed" for r in in_target)
    layer = {
        "name": "NSM Lab — network detection coverage",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": (f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by detections/attack-layer.py from docs/detection-catalog.md. "
                        f"Targets: {len(in_target)}; validated {validated_n} ({validated_n / len(in_target):.0%}); "
                        f"observed only {observed_n}; gaps {len(in_target) - validated_n - observed_n}."),
        "filters": {"platforms": ["Linux", "Network"]},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": layer_techniques,
        "gradient": {"colors": ["#e8716b", "#f5d76e", "#66b86a"], "minValue": 0, "maxValue": 2},
        "legendItems": [
            {"label": "Validated detection", "color": "#66b86a"},
            {"label": "Observed in production only", "color": "#f5d76e"},
            {"label": "Target without detection (gap)", "color": "#e8716b"},
        ],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }
    LAYER.write_text(json.dumps(layer, indent=2) + "\n")

    if not args.no_db:
        ch("CREATE TABLE IF NOT EXISTS nsm.attack_coverage_staging AS nsm.attack_coverage")
        ch("TRUNCATE TABLE nsm.attack_coverage_staging")
        ch_insert("INSERT INTO nsm.attack_coverage_staging FORMAT JSONEachRow", "\n".join(json.dumps(r) for r in rows))
        ch("EXCHANGE TABLES nsm.attack_coverage_staging AND nsm.attack_coverage")
        ch("DROP TABLE nsm.attack_coverage_staging")

    print(f"targets {len(in_target)}: validated {validated_n} ({validated_n / len(in_target):.0%}), observed only {observed_n}, "
          f"gaps {len(in_target) - validated_n - observed_n}; layer {LAYER.relative_to(ROOT)}")
    for r in in_target:
        if r["status"] != "validated":
            print(f"  {r['status']:<9} {r['technique_id']:<10} {r['name']}" + (f" — {', '.join(r['observed_by'])}" if r["observed_by"] else ""))
    outside = [r["technique_id"] for r in rows if not r["in_target"]]
    if outside:
        print(f"  outside the target list: {', '.join(outside)}")


if __name__ == "__main__":
    main()
