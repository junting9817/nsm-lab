-- DET-101 Beaconing (periodic C2 check-ins)
-- ATT&CK: T1071.001 Application Layer Protocol: Web Protocols (TA0011 Command and Control)
--
-- Logic: group outbound connections started by local hosts by (src, dst, port, proto) and score how regular
-- the gaps between connection start times are.
--   ts_score    = 1 - MAD(interval) / median(interval)   jitter-robust regularity; about 1 - J/2 for uniform ±J jitter
--   cv_score    = 1 - stddev(interval) / mean(interval)  coefficient of variation; about 1 - J/√3 for uniform ±J jitter
--   size_score  = 1 - MAD(bytes sent) / median           check-ins tend to be the same size
--   count_score = min(1, connections / target_conns)     enough samples to trust the pattern
--   score = 0.45·ts + 0.25·cv + 0.15·size + 0.15·count   (each term in 0..1)
-- Median and MAD instead of mean and stddev: a beacon that pauses (a few long gaps) or retries in a burst
-- barely moves them.
-- Exceptions: rows in the allowlist table for this detection (by destination IP/CIDR or the connection's TLS SNI) are excluded.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param min_conns UInt32 = 20
-- @param target_conns UInt32 = 50
-- @param min_median_interval_s Float64 = 5
-- @param min_score Float64 = 0.8
-- @param exclude_dst Array(String) = []
-- @param use_allowlist UInt8 = 1
WITH
allow AS
(
    -- Reviewed exceptions (detections/allowlist.tsv → allowlist table). use_allowlist=0 shows what they suppress.
    SELECT match_type, value
    FROM {db:Identifier}.allowlist
    WHERE {use_allowlist:UInt8} = 1 AND enabled AND expires_at > now() AND detection_id IN ('DET-101', '*')
),
tls_names AS
(
    -- TLS server name per connection, so exceptions match what each connection asked for, not a shared CDN IP
    SELECT uid, server_name
    FROM {db:Identifier}.zeek_ssl
    WHERE ts >= {start:DateTime64(6)} - toIntervalHour(1) AND ts < {end:DateTime64(6)} AND server_name != ''
),
pairs AS
(
    SELECT
        id_orig_h AS src,
        id_resp_h AS dst,
        id_resp_p AS dst_port,
        proto,
        arraySort(groupArray(toUnixTimestamp64Micro(ts))) AS t_us,
        groupArray(toFloat64(orig_bytes)) AS sizes,
        count() AS conns,
        min(ts) AS first_seen,
        max(ts) AS last_seen
    FROM {db:Identifier}.zeek_conn AS c
    ANY LEFT JOIN tls_names AS t ON c.uid = t.uid
    WHERE ts >= {start:DateTime64(6)} AND ts < {end:DateTime64(6)}
      AND local_orig AND NOT local_resp
      AND NOT has({exclude_dst:Array(String)}, id_resp_h)
      AND NOT (
            has((SELECT groupArray(value) FROM allow WHERE match_type = 'dst_ip'), id_resp_h)
         OR arrayExists(n -> isIPAddressInRange(id_resp_h, n), (SELECT groupArray(value) FROM allow WHERE match_type = 'dst_cidr'))
         OR has((SELECT groupArray(value) FROM allow WHERE match_type = 'sni'), t.server_name)
         OR arrayExists(x -> endsWith(t.server_name, x), (SELECT groupArray(value) FROM allow WHERE match_type = 'sni_suffix'))
      )
    GROUP BY src, dst, dst_port, proto
    HAVING conns >= {min_conns:UInt32}
),
scored AS
(
    SELECT
        *,
        arrayMap(x -> x / 1000000, arraySlice(arrayDifference(t_us), 2)) AS intervals,
        arrayReduce('medianExact', intervals) AS med_i,
        arrayReduce('medianExact', arrayMap(x -> abs(x - med_i), intervals)) AS mad_i,
        arrayReduce('stddevPop', intervals) / greatest(arrayReduce('avg', intervals), 1e-9) AS cv,
        arrayReduce('medianExact', sizes) AS med_b,
        arrayReduce('medianExact', arrayMap(x -> abs(x - med_b), sizes)) AS mad_b,
        greatest(0, 1 - mad_i / greatest(med_i, 1e-9)) AS ts_score,
        greatest(0, 1 - cv) AS cv_score,
        if(med_b = 0, if(mad_b = 0, 1, 0), greatest(0, 1 - mad_b / med_b)) AS size_score,
        least(1, conns / {target_conns:UInt32}) AS count_score,
        0.45 * ts_score + 0.25 * cv_score + 0.15 * size_score + 0.15 * count_score AS raw_score
    FROM pairs
)
SELECT
    'DET-101' AS detection_id,
    if(raw_score >= 0.9, 'high', 'medium') AS severity,
    src,
    dst,
    dst_port,
    first_seen,
    last_seen,
    round(raw_score, 3) AS score,
    concat(src, ' -> ', dst, ':', toString(dst_port), ' ', toString(conns), ' connections, median interval ',
           toString(round(med_i, 1)), 's (MAD ', toString(round(mad_i, 1)), 's)') AS summary,
    proto,
    conns,
    round(med_i, 2) AS median_interval_sec,
    round(mad_i, 2) AS mad_interval_sec,
    round(cv, 3) AS interval_cv,
    round(ts_score, 3) AS ts_score,
    round(cv_score, 3) AS cv_score,
    round(size_score, 3) AS size_score,
    round(count_score, 3) AS count_score
FROM scored
WHERE med_i >= {min_median_interval_s:Float64}
  AND raw_score >= {min_score:Float64}
ORDER BY score DESC
