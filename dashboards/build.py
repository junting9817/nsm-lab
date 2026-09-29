#!/usr/bin/env python3
"""Build the Phase 7 Grafana dashboards as JSON (dashboards as code).

    python3 dashboards/build.py        # writes dashboards/json/nsm-{live-traffic,alerts,c2-hunt,dns,soc-kpi}.json

Grafana provisions every file in dashboards/json (dashboards/provisioning/dashboards/nsm.yaml). The Honeypot (Phase 5) and
Response (Phase 6) dashboards were generated earlier and are kept as their JSON files.

ClickHouse rules these queries follow (each one bit this project before):
  - never alias an expression with the name of a column it aggregates (ILLEGAL_AGGREGATION, DET-104 / Honeypot / responder)
  - Nullable columns inside argMax need argMax(tuple(x), t).1, or NULLs are skipped (responder release bug)
  - with the default join_use_nulls = 0, unmatched LEFT JOIN strings are '' rather than NULL
  - Suricata alerts from the PCAP harness arrive on nsm-replay0; production panels keep in_iface = 'ens4'
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "json"
DS = {"type": "grafana-clickhouse-datasource", "uid": "nsm-clickhouse"}
ENS4 = "in_iface = 'ens4'"
OUTBOUND = "local_orig AND NOT local_resp"
LATEST_RUN = "(SELECT max(run_at) FROM nsm.detection_runs WHERE NOT backfill)"
SURICATA_VERDICTS = "(SELECT subject, argMax(verdict, created_at) AS latest_verdict FROM nsm.verdicts WHERE source = 'suricata' GROUP BY subject)"
DETECTION_VERDICTS = "(SELECT subject, argMax(verdict, created_at) AS latest_verdict FROM nsm.verdicts WHERE source = 'detection' GROUP BY subject)"
TABLE_OPTS = {"showHeader": True, "cellHeight": "sm"}
# A block counts as an MTTR sample only when the Grafana alert behind it started shortly before the decision; a repeat notification
# of an alert that has fired for hours (e.g. since before enforcement) measures the notification schedule, not detection.
FRESH_ALERT = "parseDateTime64BestEffortOrNull(JSONExtractString(a.detail, 'startsAt')) >= a.created_at - INTERVAL 20 MINUTE"


class Board:
    def __init__(self):
        self.panels = []

    def _add(self, ptype, title, pos, sql, desc, fmt=1, defaults=None, **extra):
        x, y, w, h = pos
        p = {
            "id": len(self.panels) + 1, "type": ptype, "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "datasource": DS,
            "targets": [{"refId": "A", "datasource": DS, "editorType": "sql", "format": fmt,
                         "queryType": "timeseries" if fmt == 0 else "table", "rawSql": " ".join(sql.split())}],
            "fieldConfig": {"defaults": defaults or {}, "overrides": []},
            "description": desc,
        }
        p.update(extra)
        self.panels.append(p)

    def stat(self, title, pos, sql, desc, unit="short", decimals=None, no_value=None):
        defaults = {"unit": unit, "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]}}
        if decimals is not None:
            defaults["decimals"] = decimals
        if no_value is not None:
            defaults["noValue"] = no_value
        self._add("stat", title, pos, sql, desc, defaults=defaults,
                  options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                           "colorMode": "value", "graphMode": "none", "textMode": "auto", "justifyMode": "auto"})

    def table(self, title, pos, sql, desc):
        self._add("table", title, pos, sql, desc, options=TABLE_OPTS)

    def series(self, title, pos, sql, desc, unit="short", bars=False):
        defaults = {"unit": unit}
        if bars:
            defaults["custom"] = {"drawStyle": "bars", "fillOpacity": 80, "stacking": {"mode": "normal", "group": "A"}}
        self._add("timeseries", title, pos, sql, desc, fmt=0, defaults=defaults,
                  options={"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                           "tooltip": {"mode": "multi", "sort": "desc"}})

    def text(self, pos, content):
        x, y, w, h = pos
        self.panels.append({"id": len(self.panels) + 1, "type": "text", "title": "", "gridPos": {"x": x, "y": y, "w": w, "h": h},
                            "options": {"mode": "markdown", "content": content}})


def dashboard(uid, title, description, tags, board, time_from="now-24h", refresh="1m", variables=None):
    return {"uid": uid, "title": title, "description": description, "tags": ["nsm", "phase7"] + tags, "timezone": "browser",
            "editable": False, "refresh": refresh, "time": {"from": time_from, "to": "now"}, "schemaVersion": 41,
            "templating": {"list": variables or []}, "panels": board.panels}


FRESHNESS = """
SELECT source, latest, dateDiff('second', latest, now64(3)) AS lag_s FROM (
  SELECT 'zeek_conn' AS source, max(ts) AS latest FROM nsm.zeek_conn
  UNION ALL SELECT 'suricata_alert', max(timestamp) FROM nsm.suricata_alert WHERE in_iface = 'ens4'
  UNION ALL SELECT 'suricata_stats', max(timestamp) FROM nsm.suricata_stats
  UNION ALL SELECT 'cowrie_events (honeypot)', max(timestamp) FROM nsm.cowrie_events
  UNION ALL SELECT 'detection_runs', max(run_at) FROM nsm.detection_runs WHERE NOT backfill
  UNION ALL SELECT 'vector_internal_metrics', max(timestamp) FROM nsm.vector_internal_metrics
) ORDER BY lag_s DESC"""


# --- Traffic Overview ---------------------------------------------------------------------------------------------

def traffic_overview():
    b = Board()
    inbound = "NOT local_orig AND local_resp AND id_orig_h != '${self_ip}'"
    b.stat("Zeek connections", (0, 0, 5, 4), "SELECT count() AS connections FROM nsm.zeek_conn WHERE $__timeFilter(ts)",
           "Connections that ended in the selected range (Zeek conn.log)")
    b.stat("Inbound source IPs", (5, 0, 5, 4), f"SELECT uniqExact(id_orig_h) AS sources FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {inbound}",
           "Distinct sources of connections into the sensor, excluding its own external IP (self-test hairpin)")
    b.stat("Suricata alerts", (10, 0, 4, 4), f"SELECT count() AS alerts FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4}",
           "Signature alerts on ens4 (the validation harness replays on nsm-replay0 and is excluded)")
    b.stat("Kernel drop rate", (14, 0, 5, 4),
           "SELECT argMax(stats_capture_kernel_drops, timestamp) / greatest(argMax(stats_capture_kernel_packets, timestamp), 1) AS drop_rate FROM nsm.suricata_stats WHERE $__timeFilter(timestamp)",
           "Suricata AF_PACKET kernel drops / packets since engine start (latest value in range)", unit="percentunit", decimals=3)
    b.stat("Ingestion lag", (19, 0, 5, 4), "SELECT dateDiff('second', max(ts), now64()) AS lag FROM nsm.zeek_conn",
           "Now minus the newest loaded Zeek connection. Connections are logged when they end, so long ones can raise it", unit="s")
    b.series("Connections by direction", (0, 4, 12, 8),
             "SELECT $__timeInterval(ts) AS time, multiIf(local_orig AND local_resp, 'internal', local_orig, 'outbound', 'inbound') AS direction, count() AS connections FROM nsm.zeek_conn WHERE $__timeFilter(ts) GROUP BY time, direction ORDER BY time",
             "inbound = internet → sensor, outbound = sensor → internet (Zeek Site::local_nets)")
    b.series("Bytes by direction (IP bytes)", (12, 4, 12, 8),
             "SELECT $__timeInterval(ts) AS time, multiIf(local_orig AND local_resp, 'internal', local_orig, 'outbound', 'inbound') AS direction, sum(orig_ip_bytes + resp_ip_bytes) AS bytes FROM nsm.zeek_conn WHERE $__timeFilter(ts) GROUP BY time, direction ORDER BY time",
             "IP bytes in both directions of each connection", unit="decbytes")
    b.table("Top inbound destination ports", (0, 12, 8, 9),
            f"SELECT id_resp_p AS port, proto AS protocol, anyIf(service, service != '') AS detected_service, count() AS connections, uniqExact(id_orig_h) AS sources FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {inbound} GROUP BY port, protocol ORDER BY connections DESC LIMIT 10",
            "Only ports the VPC firewall allows reach the VM (22 and 80); everything else is dropped before capture")
    b.table("Top inbound source IPs", (8, 12, 10, 9),
            f"SELECT id_orig_h AS source, count() AS connections, uniqExact(id_resp_p) AS ports, arrayStringConcat(arrayMap(p -> toString(p), arraySort(groupUniqArray(5)(id_resp_p))), ',') AS sample_ports FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {inbound} GROUP BY source ORDER BY connections DESC LIMIT 10",
            "Top sources by connection count")
    b.table("Services seen", (18, 12, 6, 9),
            "SELECT if(service = '', '(not identified)', service) AS detected, count() AS connections FROM nsm.zeek_conn WHERE $__timeFilter(ts) GROUP BY detected ORDER BY connections DESC LIMIT 12",
            "Zeek's payload-based protocol identification")
    b.series("Alerts by severity", (0, 21, 12, 8),
             f"SELECT $__timeInterval(timestamp) AS time, concat('severity ', toString(alert_severity)) AS level, count() AS alerts FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4} GROUP BY time, level ORDER BY time",
             "Details on the Alerts dashboard")
    b.table("Data freshness", (12, 21, 12, 8), FRESHNESS,
            "Newest row per source. Honeypot events arrive in batches (~1–2 min); detection runs are hourly; Suricata stats every minute")
    b.table("Top DNS queries", (0, 29, 12, 9),
            "SELECT query AS name, count() AS queries, uniqExact(id_orig_h) AS clients FROM nsm.zeek_dns WHERE $__timeFilter(ts) GROUP BY name ORDER BY queries DESC LIMIT 10",
            "Details on the DNS dashboard")
    b.table("Top TLS server names", (12, 29, 12, 9),
            "SELECT server_name AS sni, count() AS sessions, uniqExact(id_resp_h) AS servers FROM nsm.zeek_ssl WHERE $__timeFilter(ts) AND server_name != '' GROUP BY sni ORDER BY sessions DESC LIMIT 10",
            "Details on the C2 Hunt dashboard")
    # Read from nsm.lab_addresses rather than written here: the addresses live in .env
    # (infra/scripts/setup-lab-addresses.sh), so this repository can be published without a redaction pass over
    # every dashboard and script that needs to exclude our own traffic.
    variables = [{"type": "query", "name": "self_ip", "label": "Sensor external IP to exclude",
                  "description": "Removes test requests the sensor sent to its own external IP (hairpin) from inbound statistics",
                  "datasource": DS, "refresh": 1, "hide": 0, "includeAll": False, "multi": False,
                  "query": {"refId": "self_ip", "editorType": "sql", "format": 1, "queryType": "table",
                            "rawSql": "SELECT address FROM nsm.lab_addresses WHERE role = 'sensor'"}}]
    return dashboard("nsm-live-traffic", "NSM — Traffic Overview",
                     "What reaches the sensor and leaves it: connections, bytes, ports, services, alert volume and pipeline freshness.",
                     ["traffic"], b, time_from="now-6h", refresh="30s", variables=variables)


# --- Alerts -------------------------------------------------------------------------------------------------------

def alerts():
    b = Board()
    b.stat("Suricata alerts", (0, 0, 4, 4), f"SELECT count() AS alerts FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4}",
           "Signature alerts on ens4 in the range")
    b.stat("Severity 1", (4, 0, 4, 4), f"SELECT countIf(alert_severity = 1) AS severe FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4}",
           "Highest-severity alerts; RSP-002 blocks their sources")
    b.stat("Unreviewed severity-1", (8, 0, 4, 4),
           f"""SELECT count() AS unreviewed FROM (SELECT DISTINCT concat(toString(alert_signature_id), '|', src_ip) AS pair FROM nsm.suricata_alert
               WHERE $__timeFilter(timestamp) AND {ENS4} AND alert_severity = 1) AS a
               LEFT ANTI JOIN (SELECT DISTINCT subject FROM nsm.verdicts WHERE source = 'suricata') AS rv ON rv.subject = a.pair""",
           "Signature/source pairs with no analyst verdict yet — the triage queue below")
    b.stat("Behavior findings now", (12, 0, 4, 4),
           f"SELECT count() AS findings FROM nsm.detection_hits WHERE run_at = {LATEST_RUN}",
           "Rows from the latest hourly run of DET-101..109 (24 h window)")
    b.stat("Automatic blocks", (16, 0, 4, 4),
           "SELECT count() AS blocks FROM nsm.response_actions WHERE mode = 'enforce' AND action = 'block' AND trigger != 'manual' AND $__timeFilter(created_at)",
           "Sources blocked by the responder in the range (enforce mode)")
    b.stat("Suppressed by tuning", (20, 0, 4, 4),
           "SELECT argMax(stats_detect_alerts_suppressed, timestamp) - argMin(stats_detect_alerts_suppressed, timestamp) AS suppressed FROM nsm.suricata_stats WHERE $__timeFilter(timestamp)",
           "Alerts Suricata suppressed through threshold.config (TUNE-001) in the range; resets when the engine restarts")
    b.series("Alerts by severity", (0, 4, 12, 8),
             f"SELECT $__timeInterval(timestamp) AS time, concat('severity ', toString(alert_severity)) AS level, count() AS alerts FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4} GROUP BY time, level ORDER BY time",
             "Suricata alerts on ens4", bars=True)
    b.series("New behavior findings", (12, 4, 12, 8),
             """SELECT $__timeInterval(first_reported) AS time, det AS detection, count() AS findings
                FROM (SELECT hit_key, any(detection_id) AS det, min(run_at) AS first_reported FROM nsm.detection_hits GROUP BY hit_key)
                WHERE $__timeFilter(first_reported) GROUP BY time, detection ORDER BY time""",
             "Findings (hit_key) by the run that first reported them; backfilled runs included", bars=True)
    b.table("Triage queue: severity-1 without verdict", (0, 12, 24, 8),
            f"""SELECT a.pair AS signature_source, a.sig AS signature, a.n AS alerts, a.first_at AS first_seen, a.last_at AS last_seen, a.url AS sample_url
                FROM (SELECT concat(toString(alert_signature_id), '|', src_ip) AS pair, any(alert_signature) AS sig, count() AS n, min(timestamp) AS first_at,
                             max(timestamp) AS last_at, anyIf(http_url, http_url != '') AS url
                      FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4} AND alert_severity = 1 GROUP BY pair) AS a
                LEFT ANTI JOIN (SELECT DISTINCT subject FROM nsm.verdicts WHERE source = 'suricata') AS rv ON rv.subject = a.pair
                ORDER BY last_seen DESC LIMIT 50""",
            "Record a verdict: sudo detections/verdict.sh suricata '<sid>|<ip>' true_positive|false_positive <TUNE-id|-> \"note\"")
    b.table("Top signatures", (0, 20, 12, 9),
            f"""SELECT alert_signature_id AS sid, any(alert_signature) AS signature, any(alert_severity) AS level, count() AS alerts, uniqExact(src_ip) AS sources
                FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4} GROUP BY sid ORDER BY alerts DESC LIMIT 20""",
            "Most frequent signatures in the range")
    b.table("Alert sources with verdicts and response", (12, 20, 12, 9),
            f"""SELECT a.src AS source, a.n AS alerts, a.severe AS severity_1, a.sigs AS signatures, pv.verdicts AS verdicts, ra.response AS response
                FROM (SELECT src_ip AS src, count() AS n, countIf(alert_severity = 1) AS severe, uniqExact(alert_signature_id) AS sigs
                      FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4} GROUP BY src) AS a
                LEFT JOIN (SELECT splitByChar('|', subject)[2] AS ip, arrayStringConcat(groupUniqArray(latest_verdict), ', ') AS verdicts FROM {SURICATA_VERDICTS} GROUP BY ip) AS pv ON pv.ip = a.src
                LEFT JOIN (SELECT ip, concat(argMax(action, created_at), ' (', argMax(mode, created_at), ')') AS response FROM nsm.response_actions GROUP BY ip) AS ra ON ra.ip = a.src
                ORDER BY severity_1 DESC, alerts DESC LIMIT 25""",
            "verdicts: analyst judgements for this source's signatures; response: the responder's latest decision for the IP")
    b.table("Current behavior findings", (0, 29, 24, 8),
            f"""SELECT h.detection_id AS detection, h.severity AS level, h.src AS source, h.dst AS destination, h.dst_port AS port, h.score AS finding_score,
                       h.summary AS what, if(dv.latest_verdict = '', 'unreviewed', dv.latest_verdict) AS verdict
                FROM nsm.detection_hits AS h LEFT JOIN {DETECTION_VERDICTS} AS dv ON dv.subject = h.hit_key
                WHERE h.run_at = {LATEST_RUN} ORDER BY finding_score DESC""",
            "Latest hourly run; reviewed findings carry their verdict (docs/tuning-log.md)")
    b.table("Recent alerts", (0, 37, 24, 9),
            f"""SELECT timestamp AS time, alert_severity AS level, alert_signature_id AS sid, alert_signature AS signature, src_ip, dest_port, app_proto,
                       http_url AS url, community_id FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4} ORDER BY timestamp DESC LIMIT 100""",
            "community_id finds the same flow in nsm.zeek_conn")
    return dashboard("nsm-alerts", "NSM — Alerts", "Signature alerts and behavior findings with triage state, verdicts and the automated response.",
                     ["alerts"], b)


# --- C2 Hunt ------------------------------------------------------------------------------------------------------

def c2_hunt():
    b = Board()
    c2 = "('DET-101', 'DET-102', 'DET-103', 'DET-104', 'DET-107', 'DET-108')"
    b.stat("Outbound connections", (0, 0, 6, 4), f"SELECT count() AS connections FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {OUTBOUND}",
           "Connections the sensor opened to the internet")
    b.stat("External destinations", (6, 0, 6, 4), f"SELECT uniqExact(id_resp_h) AS destinations FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {OUTBOUND}",
           "Distinct external addresses contacted")
    b.stat("Uploaded", (12, 0, 6, 4), f"SELECT sum(orig_bytes) AS uploaded FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {OUTBOUND}",
           "Payload bytes sent to the internet", unit="decbytes")
    b.stat("C2 findings now", (18, 0, 6, 4), f"SELECT count() AS findings FROM nsm.detection_hits WHERE run_at = {LATEST_RUN} AND detection_id IN {c2}",
           "Latest run of the C2 and exfiltration detections (DET-101/102/103/104/107/108)")
    b.table("C2 and exfiltration findings (latest run)", (0, 4, 24, 7),
            f"""SELECT h.detection_id AS detection, h.src AS source, h.dst AS destination, h.dst_port AS port, h.score AS finding_score, h.summary AS what,
                       if(dv.latest_verdict = '', 'unreviewed', dv.latest_verdict) AS verdict
                FROM nsm.detection_hits AS h LEFT JOIN {DETECTION_VERDICTS} AS dv ON dv.subject = h.hit_key
                WHERE h.run_at = {LATEST_RUN} AND h.detection_id IN {c2} ORDER BY finding_score DESC""",
            "Allowlisted software (docs/tuning-log.md) is already filtered out; what remains needs a verdict")
    b.table("Most regular outbound pairs", (0, 11, 12, 9),
            f"""SELECT dst AS destination, port, sni, conns AS connections, round(med) AS median_interval_s, round(mad, 1) AS mad_s, round(mad / greatest(med, 1), 3) AS irregularity
                FROM (SELECT c.id_resp_h AS dst, c.id_resp_p AS port, anyIf(s.server_name, s.server_name != '') AS sni, count() AS conns,
                             arrayPopFront(arrayDifference(arraySort(groupArray(toFloat64(c.ts))))) AS gaps,
                             arrayReduce('median', gaps) AS med, arrayReduce('median', arrayMap(g -> abs(g - med), gaps)) AS mad
                      FROM nsm.zeek_conn AS c LEFT JOIN (SELECT uid, server_name FROM nsm.zeek_ssl WHERE $__timeFilter(ts)) AS s ON s.uid = c.uid
                      WHERE $__timeFilter(c.ts) AND c.local_orig AND NOT c.local_resp GROUP BY dst, port HAVING conns >= 10)
                WHERE med >= 5 ORDER BY irregularity ASC LIMIT 20""",
            "Hunting view of DET-101's idea: low MAD relative to the median interval means clockwork check-ins. Includes allowlisted software")
    b.table("Top destinations by upload", (12, 11, 12, 9),
            f"""SELECT c.id_resp_h AS destination, anyIf(s.server_name, s.server_name != '') AS sni, count() AS connections, sum(c.orig_bytes) AS bytes_up,
                       sum(c.resp_bytes) AS bytes_down, round(sum(c.orig_bytes) / greatest(sum(c.orig_bytes) + sum(c.resp_bytes), 1), 2) AS upload_ratio
                FROM nsm.zeek_conn AS c LEFT JOIN (SELECT uid, server_name FROM nsm.zeek_ssl WHERE $__timeFilter(ts)) AS s ON s.uid = c.uid
                WHERE $__timeFilter(c.ts) AND c.local_orig AND NOT c.local_resp GROUP BY destination ORDER BY bytes_up DESC LIMIT 20""",
            "upload_ratio near 1 = mostly sending (DET-107 looks for this at volume)")
    b.table("Rarest TLS client fingerprints (JA4)", (0, 20, 12, 9),
            """SELECT ja4, count() AS sessions, uniqExact(server_name) AS server_names, arrayStringConcat(groupUniqArray(3)(server_name), ', ') AS sample_sni, min(ts) AS first_seen
               FROM nsm.zeek_ssl WHERE $__timeFilter(ts) AND ja4 != '' AND isIPAddressInRange(id_orig_h, '10.128.0.0/9') GROUP BY ja4 ORDER BY sessions ASC LIMIT 20""",
            "Clients seen least often from the sensor; DET-103 compares against a longer baseline")
    b.table("Outbound TLS without SNI", (12, 20, 12, 9),
            """SELECT id_resp_h AS destination, id_resp_p AS port, count() AS sessions, anyIf(ja4, ja4 != '') AS client_ja4, max(ts) AS last_seen
               FROM nsm.zeek_ssl WHERE $__timeFilter(ts) AND server_name = '' AND isIPAddressInRange(id_orig_h, '10.128.0.0/9') GROUP BY destination, port ORDER BY sessions DESC LIMIT 20""",
            "Tools that connect to raw IPs skip SNI; so do sessions Zeek picked up mid-stream after a restart (no handshake seen)")
    b.table("Protocols on unusual ports (outbound)", (0, 29, 12, 8),
            f"""SELECT service AS detected, id_resp_p AS port, count() AS connections, uniqExact(id_resp_h) AS destinations
                FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {OUTBOUND} AND service != ''
                  AND NOT ((service = 'ssl' AND id_resp_p = 443) OR (service = 'http' AND id_resp_p = 80) OR (service = 'dns' AND id_resp_p = 53)
                           OR (service = 'ntp' AND id_resp_p = 123) OR (service = 'ssh' AND id_resp_p = 22))
                GROUP BY detected, port ORDER BY connections DESC LIMIT 20""",
            "Payload-identified protocol on a port it does not usually use (DET-108)")
    b.table("Certificate validation problems", (12, 29, 12, 8),
            """SELECT server_name AS sni, id_resp_h AS server, validation_status AS status, anyIf(issuer, issuer != '') AS cert_issuer, count() AS sessions
               FROM nsm.zeek_ssl WHERE $__timeFilter(ts) AND validation_status NOT IN ('', 'ok') GROUP BY sni, server, status ORDER BY sessions DESC LIMIT 20""",
            "TLS 1.3 encrypts certificates, so most sessions have no validation result; TLS 1.2 ones do (DET-104)")
    b.series("Outbound bytes", (0, 37, 24, 8),
             f"SELECT $__timeInterval(ts) AS time, sum(orig_bytes) AS sent, sum(resp_bytes) AS received FROM nsm.zeek_conn WHERE $__timeFilter(ts) AND {OUTBOUND} GROUP BY time ORDER BY time",
             "Payload bytes to and from the internet", unit="decbytes")
    return dashboard("nsm-c2-hunt", "NSM — C2 Hunt", "Outbound behavior of the sensor: beaconing, rare clients, uploads, TLS anomalies and the C2 detections.",
                     ["c2", "hunt"], b)


# --- DNS ----------------------------------------------------------------------------------------------------------

def dns():
    b = Board()
    b.stat("Queries", (0, 0, 6, 4), "SELECT count() AS queries FROM nsm.zeek_dns WHERE $__timeFilter(ts)", "DNS transactions seen by Zeek")
    b.stat("Registered domains", (6, 0, 6, 4),
           "SELECT uniqExact(cutToFirstSignificantSubdomain(query)) AS domains FROM nsm.zeek_dns WHERE $__timeFilter(ts) AND query != ''",
           "Distinct registered domains (eTLD+1)")
    b.stat("NXDOMAIN share", (12, 0, 6, 4), "SELECT countIf(rcode_name = 'NXDOMAIN') / greatest(count(), 1) AS nx FROM nsm.zeek_dns WHERE $__timeFilter(ts)",
           "Share of answers that were NXDOMAIN (DET-106 watches for spikes)", unit="percentunit", decimals=1)
    b.stat("DNS findings now", (18, 0, 6, 4),
           f"SELECT count() AS findings FROM nsm.detection_hits WHERE run_at = {LATEST_RUN} AND detection_id IN ('DET-105', 'DET-106')",
           "Latest run of DNS tunneling (DET-105) and DGA (DET-106)")
    b.series("Queries by response code", (0, 4, 12, 8),
             "SELECT $__timeInterval(ts) AS time, if(rcode_name = '', '(no answer)', rcode_name) AS answer, count() AS queries FROM nsm.zeek_dns WHERE $__timeFilter(ts) GROUP BY time, answer ORDER BY time",
             "NOERROR, NXDOMAIN, SERVFAIL, … per interval")
    b.series("NXDOMAIN share over time", (12, 4, 12, 8),
             "SELECT $__timeInterval(ts) AS time, countIf(rcode_name = 'NXDOMAIN') / greatest(count(), 1) AS nxdomain_share FROM nsm.zeek_dns WHERE $__timeFilter(ts) GROUP BY time ORDER BY time",
             "A DGA-infected host drives this up with many failing lookups", unit="percentunit")
    b.table("Top registered domains", (0, 12, 12, 9),
            """SELECT cutToFirstSignificantSubdomain(query) AS domain, count() AS queries, uniqExact(query) AS names, uniqExact(id_orig_h) AS clients
               FROM nsm.zeek_dns WHERE $__timeFilter(ts) AND query != '' GROUP BY domain ORDER BY queries DESC LIMIT 20""",
            "Many distinct names under one domain is what DNS tunneling looks like (DET-105)")
    b.table("Top NXDOMAIN names", (12, 12, 12, 9),
            """SELECT query AS name, qtype_name AS record_type, count() AS failures, uniqExact(id_orig_h) AS clients
               FROM nsm.zeek_dns WHERE $__timeFilter(ts) AND rcode_name = 'NXDOMAIN' GROUP BY name, record_type ORDER BY failures DESC LIMIT 20""",
            "Search-domain expansion and SRV lookups are normal here; random-looking names are not")
    b.table("Longest query names", (0, 21, 12, 9),
            """SELECT query AS name, length(query) AS chars, qtype_name AS record_type, id_orig_h AS client, count() AS times
               FROM nsm.zeek_dns WHERE $__timeFilter(ts) GROUP BY name, record_type, client ORDER BY chars DESC LIMIT 20""",
            "Encoded data in labels makes names long")
    b.table("Record types and resolvers", (12, 21, 12, 9),
            """SELECT qtype_name AS record_type, id_resp_h AS resolver, count() AS queries, countIf(rcode_name = 'NXDOMAIN') AS nxdomain
               FROM nsm.zeek_dns WHERE $__timeFilter(ts) GROUP BY record_type, resolver ORDER BY queries DESC LIMIT 20""",
            "A host that suddenly uses another resolver, or lots of TXT/NULL records, deserves a look")
    b.table("DNS findings (last 7 days)", (0, 30, 24, 8),
            f"""SELECT h.detection_id AS detection, h.src AS source, h.dst AS domain_or_resolver, max(h.score) AS finding_score, any(h.summary) AS what,
                       min(h.run_at) AS first_reported, max(h.run_at) AS last_reported, if(any(dv.latest_verdict) = '', 'unreviewed', any(dv.latest_verdict)) AS verdict
                FROM nsm.detection_hits AS h LEFT JOIN {DETECTION_VERDICTS} AS dv ON dv.subject = h.hit_key
                WHERE h.detection_id IN ('DET-105', 'DET-106') AND h.run_at > now() - INTERVAL 7 DAY
                GROUP BY detection, source, domain_or_resolver ORDER BY last_reported DESC LIMIT 50""",
            "No production findings so far means the thresholds held; the fixtures prove they fire (testing/detections)")
    return dashboard("nsm-dns", "NSM — DNS", "DNS activity from Zeek: volume, NXDOMAIN, domains, long names, resolvers and the tunneling/DGA detections.",
                     ["dns"], b)


# --- SOC KPI ------------------------------------------------------------------------------------------------------

def soc_kpi():
    b = Board()
    b.stat("MTTD (engine, median)", (0, 0, 4, 4),
           "SELECT quantileExact(0.5)(mttd_ms) AS mttd FROM nsm.validation_runs WHERE result = 'PASS' AND started_at > now() - INTERVAL 30 DAY",
           "Replay start → Suricata alert, median of PASS rows in 30 days (testing/validate.sh, docs/kpi.md)", unit="ms")
    b.stat("Alert visible after (median)", (4, 0, 4, 4),
           "SELECT quantileExact(0.5)(visible_ms) / 1000 AS visible FROM nsm.validation_runs WHERE result = 'PASS' AND started_at > now() - INTERVAL 30 DAY",
           "Replay start → queryable in ClickHouse (pipeline included)", unit="s", decimals=1)
    b.stat("MTTR (evidence → block, median)", (8, 0, 4, 4),
           f"""SELECT median(dateDiff('millisecond', a.evidence_at, p.applied_at)) / 1000 AS mttr FROM nsm.response_actions AS a
              INNER JOIN (SELECT applied_at, arrayJoin(added) AS range FROM nsm.response_applies WHERE mode = 'enforce' AND result = 'ok') AS p ON p.range = concat(a.ip, '/32')
              WHERE a.mode = 'enforce' AND a.action = 'block' AND a.trigger != 'manual' AND a.evidence_at IS NOT NULL AND p.applied_at >= a.created_at
                AND a.created_at > now() - INTERVAL 30 DAY AND {FRESH_ALERT}""",
           "First evidence → firewall rule confirmed, automatic blocks in 30 days whose Grafana alert started within 20 min of the decision. "
           "Blocks decided from a repeat notification of an older alert are not detection latency (docs/kpi.md)", unit="s", decimals=0,
           no_value="no clean sample yet")
    b.stat("Daily alert volume", (12, 0, 4, 4),
           f"SELECT round(avg(n)) AS per_day FROM (SELECT toDate(timestamp) AS d, count() AS n FROM nsm.suricata_alert WHERE {ENS4} AND timestamp > now() - INTERVAL 7 DAY AND toDate(timestamp) < today() GROUP BY d)",
           "Average Suricata alerts per complete day over the last 7 days")
    b.stat("FP rate (reviewed pairs)", (16, 0, 4, 4),
           f"""SELECT countIf(sv.latest_verdict = 'false_positive') / count() AS fp_rate FROM {SURICATA_VERDICTS} AS sv
               WHERE sv.subject IN (SELECT DISTINCT concat(toString(alert_signature_id), '|', src_ip) FROM nsm.suricata_alert WHERE {ENS4})""",
           "False-positive signature/source pairs ÷ reviewed pairs (the unit of triage). Counted per alert, the noise already suppressed "
           "by tuning dominates — see the table below. Verdicts cover reviewed severity-1 pairs and tuned noise, not a random sample",
           unit="percentunit", decimals=1)
    b.stat("ATT&CK coverage", (20, 0, 4, 4),
           "SELECT countIf(status = 'validated') / count() AS coverage FROM nsm.attack_coverage WHERE in_target",
           "Target techniques with a validated detection (detections/attack-targets.tsv; detections/attack-layer.py)", unit="percentunit", decimals=0)
    b.series("Daily alert volume", (0, 4, 12, 8),
             f"SELECT toStartOfDay(timestamp) AS time, concat('severity ', toString(alert_severity)) AS level, count() AS alerts FROM nsm.suricata_alert WHERE $__timeFilter(timestamp) AND {ENS4} GROUP BY time, level ORDER BY time",
             "Suricata alerts per day by severity", bars=True)
    b.series("Daily response decisions", (12, 4, 12, 8),
             "SELECT toStartOfDay(created_at) AS time, concat(action, ' · ', mode) AS decision, count() AS decisions FROM nsm.response_actions WHERE $__timeFilter(created_at) AND mode != 'test' GROUP BY time, decision ORDER BY time",
             "Blocks, observations, rejections and releases per day (dry-run until 2026-09-15 04:14 UTC)", bars=True)
    b.table("False-positive rate by source", (0, 12, 12, 7),
            f"""SELECT 'Suricata (by reviewed pair)' AS source, countIf(sv.latest_verdict = 'true_positive') AS true_positives,
                       countIf(sv.latest_verdict = 'false_positive') AS false_positives, round(100 * countIf(sv.latest_verdict = 'false_positive') / count(), 1) AS fp_rate_pct
                FROM {SURICATA_VERDICTS} AS sv WHERE sv.subject IN (SELECT DISTINCT concat(toString(alert_signature_id), '|', src_ip) FROM nsm.suricata_alert WHERE {ENS4})
                UNION ALL
                SELECT 'Suricata (by alert, incl. tuned noise)' AS source, countIf(sv.latest_verdict = 'true_positive') AS true_positives, countIf(sv.latest_verdict = 'false_positive') AS false_positives,
                       round(100 * countIf(sv.latest_verdict = 'false_positive') / count(), 1) AS fp_rate_pct
                FROM nsm.suricata_alert AS a INNER JOIN {SURICATA_VERDICTS} AS sv ON sv.subject = concat(toString(a.alert_signature_id), '|', a.src_ip) WHERE a.{ENS4}
                UNION ALL
                SELECT 'Behavior detections (by finding)', countIf(dv.latest_verdict = 'true_positive'), countIf(dv.latest_verdict = 'false_positive'),
                       round(100 * countIf(dv.latest_verdict = 'false_positive') / count(), 1)
                FROM (SELECT DISTINCT hit_key FROM nsm.detection_hits) AS f INNER JOIN {DETECTION_VERDICTS} AS dv ON dv.subject = f.hit_key""",
            "Behavior detections on a server with no compromise have only produced benign findings so far — each tuned in docs/tuning-log.md")
    b.table("Detection health (latest run)", (12, 12, 12, 7),
            """SELECT detection_id AS detection, argMax(result, run_at) AS last_result, argMax(hits, run_at) AS last_hits, argMax(duration_ms, run_at) AS last_duration_ms,
                      max(run_at) AS last_run, dateDiff('minute', max(run_at), now64(3)) AS minutes_ago, countIf(result = 'error' AND run_at > now() - INTERVAL 1 DAY) AS errors_24h
               FROM nsm.detection_runs WHERE NOT backfill GROUP BY detection ORDER BY detection""",
            "A detection that stops running shows up here before anyone misses its findings (hourly at :07)")
    b.table("ATT&CK coverage", (0, 19, 12, 12),
            """SELECT technique_id AS technique, name AS technique_name, tactic, status AS coverage, arrayStringConcat(detections, ', ') AS validated_by,
                      arrayStringConcat(observed_by, ', ') AS observed
               FROM nsm.attack_coverage WHERE in_target ORDER BY indexOf(['gap', 'observed', 'validated'], coverage), technique""",
            "Layer for ATT&CK Navigator: detections/attack-map.json. gap = in scope but nothing detects it yet")
    b.table("Validation runs (PCAP harness)", (12, 19, 12, 12),
            """SELECT started_at, case_name AS test_case, attack_technique AS technique, result AS outcome, mttd_ms, visible_ms, rules_loaded
               FROM nsm.validation_runs ORDER BY started_at DESC LIMIT 40""",
            "Each row is one replayed attack through the production pipeline")
    b.table("Data freshness", (0, 31, 24, 7), FRESHNESS, "Newest row per source")
    return dashboard("nsm-soc-kpi", "NSM — SOC KPI", "MTTD, MTTR, daily alert volume, false-positive rate, ATT&CK coverage and the health of detections and data.",
                     ["kpi"], b, time_from="now-7d", refresh="5m")


def main():
    OUT.mkdir(exist_ok=True)
    for name, build in [("nsm-live-traffic", traffic_overview), ("nsm-alerts", alerts), ("nsm-c2-hunt", c2_hunt), ("nsm-dns", dns), ("nsm-soc-kpi", soc_kpi)]:
        d = build()
        (OUT / f"{name}.json").write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n")
        print(f"{name}.json  {len(d['panels'])} panels")


if __name__ == "__main__":
    main()
