-- DET-109 Port and host scanning
-- ATT&CK: T1046 Network Service Discovery (local source), T1595.001 Active Scanning: Scanning IP Blocks (external source)
--
-- Logic: per source, look for two shapes.
--   vertical   : distinct ports on one destination host ≥ min_ports
--   horizontal : one destination port tried on distinct hosts ≥ min_hosts
--   Both require many unanswered SYNs — SYN:SYN-ACK ratio ≥ min_syn_ratio
--   (in Zeek history, uppercase S = originator SYN, lowercase h = responder SYN+ACK)
--   score = 0.6·min(1, distinct targets / (4 × threshold)) + 0.4·failed-connection ratio (S0/REJ/RSTO/RSTR/RSTOS0/SH/OTH)
--   A local source is reported as T1046 with higher severity (internet scans of an exposed server are constant noise).
-- Limitation: ports blocked by the VPC firewall never reach the VM, so they are invisible (inbound ports seen: 22, 80).
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param min_ports UInt32 = 50
-- @param min_hosts UInt32 = 30
-- @param min_syn_ratio Float64 = 3
WITH
flows AS
(
    SELECT
        ts, id_orig_h, id_resp_h, id_resp_p, proto, local_orig,
        startsWith(history, 'S') AS syn,
        position(history, 'h') > 0 AS synack,
        conn_state IN ('S0', 'REJ', 'RSTO', 'RSTR', 'RSTOS0', 'SH', 'OTH') AS failed
    FROM {db:Identifier}.zeek_conn
    WHERE ts >= {start:DateTime64(6)} AND ts < {end:DateTime64(6)}
      AND proto = 'tcp'
),
vertical AS
(
    SELECT
        'vertical' AS scan_type, id_orig_h AS src, id_resp_h AS dst, toUInt16(0) AS dst_port,
        uniqExact(id_resp_p) AS targets, count() AS attempts,
        countIf(syn AND NOT synack) / greatest(countIf(synack), 1) AS syn_ratio,
        countIf(failed) / count() AS failed_ratio,
        arraySort(groupUniqArray(10)(id_resp_p)) AS sample_ports,
        any(local_orig) AS internal_src, min(ts) AS first_seen, max(ts) AS last_seen
    FROM flows
    GROUP BY src, dst
    HAVING targets >= {min_ports:UInt32} AND syn_ratio >= {min_syn_ratio:Float64}
),
horizontal AS
(
    SELECT
        'horizontal' AS scan_type, id_orig_h AS src, '' AS dst, id_resp_p AS dst_port,
        uniqExact(id_resp_h) AS targets, count() AS attempts,
        countIf(syn AND NOT synack) / greatest(countIf(synack), 1) AS syn_ratio,
        countIf(failed) / count() AS failed_ratio,
        [id_resp_p] AS sample_ports,
        any(local_orig) AS internal_src, min(ts) AS first_seen, max(ts) AS last_seen
    FROM flows
    GROUP BY src, dst_port
    HAVING targets >= {min_hosts:UInt32} AND syn_ratio >= {min_syn_ratio:Float64}
)
SELECT
    'DET-109' AS detection_id,
    if(internal_src, 'high', 'low') AS severity,
    src,
    dst,
    dst_port,
    first_seen,
    last_seen,
    round(0.6 * least(1, targets / (4 * if(scan_type = 'vertical', {min_ports:UInt32}, {min_hosts:UInt32})))
          + 0.4 * failed_ratio, 3) AS score,
    concat(src, if(internal_src, ' (local)', ' (external)'), ' ', scan_type, ' scan: ',
           if(scan_type = 'vertical', concat(toString(targets), ' ports on ', dst),
                                      concat('port ', toString(dst_port), ' on ', toString(targets), ' hosts')),
           ', SYN:SYN-ACK ', toString(round(syn_ratio, 1)), ', failed ', toString(round(100 * failed_ratio)), '%') AS summary,
    scan_type,
    if(internal_src, 'T1046', 'T1595.001') AS attack_technique,
    targets,
    attempts,
    round(syn_ratio, 2) AS syn_synack_ratio,
    round(failed_ratio, 3) AS failed_ratio,
    sample_ports
FROM (SELECT * FROM vertical UNION ALL SELECT * FROM horizontal)
ORDER BY score DESC
