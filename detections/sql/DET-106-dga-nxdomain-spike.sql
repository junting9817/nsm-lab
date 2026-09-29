-- DET-106 Suspected DGA (NXDOMAIN spike)
-- ATT&CK: T1568.002 Dynamic Resolution: Domain Generation Algorithms (TA0011)
--
-- Logic: per source, split time into bucket_minutes buckets and find buckets where NXDOMAIN answers suddenly pile up.
--   Conditions: NXDOMAIN in bucket ≥ min_nx, NXDOMAIN ratio ≥ min_nx_ratio, distinct base domains among them
--               ≥ min_unique_nx_domains, and NXDOMAIN count ≥ spike_factor × usual level
--               (average per bucket over the baseline_hours before the window, floor 1)
--   The usual level is a time-based average: buckets with no queries count as 0
--   (averaging only buckets that have rows would overstate it).
--   score = 0.5·min(1, NXDOMAIN ratio) + 0.5·min(1, spike multiple / (2 × spike_factor))
-- Why: DGA malware resolves many generated domains in a short burst to find its C2, and most are unregistered.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param bucket_minutes UInt32 = 10
-- @param baseline_hours UInt32 = 24
-- @param min_nx UInt32 = 20
-- @param min_nx_ratio Float64 = 0.5
-- @param min_unique_nx_domains UInt32 = 15
-- @param spike_factor Float64 = 5
WITH
buckets AS
(
    SELECT
        id_orig_h AS src,
        toStartOfInterval(ts, toIntervalMinute({bucket_minutes:UInt32})) AS bucket,
        count() AS total,
        countIf(rcode_name = 'NXDOMAIN') AS nx,
        uniqExactIf(cutToFirstSignificantSubdomain(query), rcode_name = 'NXDOMAIN') AS nx_domains,
        groupUniqArrayIf(5)(query, rcode_name = 'NXDOMAIN') AS sample_nx_queries,
        any(id_resp_h) AS resolver
    FROM {db:Identifier}.zeek_dns
    WHERE ts >= {start:DateTime64(6)} - toIntervalHour({baseline_hours:UInt32})
      AND ts < {end:DateTime64(6)}
      AND query != ''
    GROUP BY src, bucket
),
baseline AS
(
    SELECT
        src,
        sumIf(nx, bucket < toStartOfInterval({start:DateTime64(6)}, toIntervalMinute({bucket_minutes:UInt32})))
            / ({baseline_hours:UInt32} * 60 / {bucket_minutes:UInt32}) AS baseline_nx_per_bucket
    FROM buckets
    GROUP BY src
)
SELECT
    'DET-106' AS detection_id,
    if(nx / total >= 0.8, 'high', 'medium') AS severity,
    b.src AS src,
    b.resolver AS dst,
    toUInt16(53) AS dst_port,
    b.bucket AS first_seen,
    b.bucket + toIntervalMinute({bucket_minutes:UInt32}) AS last_seen,
    round(0.5 * least(1, nx / total) + 0.5 * least(1, (nx / greatest(bl.baseline_nx_per_bucket, 1)) / (2 * {spike_factor:Float64})), 3) AS score,
    concat(b.src, ' got ', toString(nx), ' NXDOMAIN in ', toString({bucket_minutes:UInt32}), ' min (',
           toString(round(100 * nx / total)), '% of ', toString(total), ' queries, ', toString(nx_domains),
           ' base domains, usual ', toString(round(bl.baseline_nx_per_bucket, 2)), ' per bucket)') AS summary,
    total AS queries,
    nx AS nxdomain,
    nx_domains AS nxdomain_base_domains,
    round(bl.baseline_nx_per_bucket, 3) AS baseline_nxdomain_per_bucket,
    sample_nx_queries
FROM buckets AS b
LEFT JOIN baseline AS bl ON b.src = bl.src
WHERE b.bucket >= toStartOfInterval({start:DateTime64(6)}, toIntervalMinute({bucket_minutes:UInt32}))
  AND nx >= {min_nx:UInt32}
  AND nx / total >= {min_nx_ratio:Float64}
  AND nx_domains >= {min_unique_nx_domains:UInt32}
  AND nx >= {spike_factor:Float64} * greatest(bl.baseline_nx_per_bucket, 1)
ORDER BY score DESC, first_seen
