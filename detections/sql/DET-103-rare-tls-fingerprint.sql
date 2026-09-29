-- DET-103 Rare TLS client fingerprint (JA4)
-- ATT&CK: T1071.001 Application Layer Protocol: Web Protocols, T1573.002 Encrypted Channel: Asymmetric Cryptography
--
-- Logic: find local hosts that opened outbound TLS with a JA4 that was almost never seen across the whole network
-- during the baseline (baseline_hours back from the end of the window).
--   Conditions: times seen in baseline ≤ max_seen and number of hosts using it ≤ max_hosts
--   score = 1 - (times seen - 1) / max_seen   → 1 for a fingerprint seen exactly once
-- Why: browsers and runtimes in use converge on a handful of fingerprints; malware and offensive tools with their own
-- TLS stacks stand out.
-- JA4 comes from sensors/zeek/scripts/ja3-ja4.zeek (cross-checked against Suricata's built-in implementation).
-- Direction: zeek_ssl has no local flags, so local_nets decides it (source local, destination not local).
-- Exceptions: rows in the allowlist table for this detection (by destination IP/CIDR or the connection's TLS SNI) are excluded.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param baseline_hours UInt32 = 168
-- @param max_seen UInt32 = 3
-- @param max_hosts UInt32 = 1
-- @param local_nets Array(String) = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','127.0.0.0/8','fc00::/7','fe80::/10']
-- @param use_allowlist UInt8 = 1
WITH
allow AS
(
    -- Reviewed exceptions (detections/allowlist.tsv → allowlist table). use_allowlist=0 shows what they suppress.
    SELECT match_type, value
    FROM {db:Identifier}.allowlist
    WHERE {use_allowlist:UInt8} = 1 AND enabled AND expires_at > now() AND detection_id IN ('DET-103', '*')
),
prevalence AS
(
    SELECT ja4, count() AS seen, uniqExact(id_orig_h) AS hosts
    FROM {db:Identifier}.zeek_ssl
    WHERE ts >= {end:DateTime64(6)} - toIntervalHour({baseline_hours:UInt32})
      AND ts < {end:DateTime64(6)}
      AND ja4 != ''
    GROUP BY ja4
)
SELECT
    'DET-103' AS detection_id,
    if(any(p.seen) = 1, 'medium', 'low') AS severity,
    s.id_orig_h AS src,
    s.id_resp_h AS dst,
    s.id_resp_p AS dst_port,
    min(s.ts) AS first_seen,
    max(s.ts) AS last_seen,
    round(1 - (any(p.seen) - 1) / {max_seen:UInt32}, 3) AS score,
    concat(s.id_orig_h, ' connected to ', arrayStringConcat(groupUniqArray(3)(if(s.server_name = '', s.id_resp_h, s.server_name)), ','),
           ' with JA4 ', s.ja4, ' (seen ', toString(any(p.seen)), 'x in baseline)') AS summary,
    s.ja4 AS ja4,
    any(s.ja3) AS ja3,
    groupUniqArray(5)(s.server_name) AS server_names,
    count() AS sessions,
    any(p.seen) AS seen_in_baseline,
    any(p.hosts) AS hosts_in_baseline
FROM {db:Identifier}.zeek_ssl AS s
INNER JOIN prevalence AS p ON s.ja4 = p.ja4
WHERE s.ts >= {start:DateTime64(6)} AND s.ts < {end:DateTime64(6)}
  AND s.ja4 != ''
  AND arrayExists(n -> isIPAddressInRange(s.id_orig_h, n), {local_nets:Array(String)})
  AND NOT arrayExists(n -> isIPAddressInRange(s.id_resp_h, n), {local_nets:Array(String)})
  AND p.seen <= {max_seen:UInt32}
  AND p.hosts <= {max_hosts:UInt32}
  AND NOT (
        has((SELECT groupArray(value) FROM allow WHERE match_type = 'dst_ip'), s.id_resp_h)
     OR arrayExists(n -> isIPAddressInRange(s.id_resp_h, n), (SELECT groupArray(value) FROM allow WHERE match_type = 'dst_cidr'))
     OR has((SELECT groupArray(value) FROM allow WHERE match_type = 'sni'), s.server_name)
     OR arrayExists(x -> endsWith(s.server_name, x), (SELECT groupArray(value) FROM allow WHERE match_type = 'sni_suffix'))
  )
GROUP BY src, dst, dst_port, ja4
ORDER BY score DESC, first_seen
