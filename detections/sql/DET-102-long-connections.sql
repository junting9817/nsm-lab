-- DET-102 Long connections (outbound sessions held open for a long time)
-- ATT&CK: T1071 Application Layer Protocol (TA0011 Command and Control) — interactive C2 and tunnels keep sessions open
--
-- Logic: outbound connections started by local hosts that lasted at least min_duration_s, grouped by destination.
--   Sessions that overlap the window count: one that started before the window (up to lookback_hours earlier)
--   but ended inside it is included.
--   score = min(1, longest duration / (4 × min_duration_s))   → 1 when a session lasts 4× the threshold
-- Limitation: Zeek writes conn.log when a connection ends, so a session that is still open is caught when it closes.
-- Exceptions: rows in the allowlist table for this detection (by destination IP/CIDR or the connection's TLS SNI) are excluded.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param min_duration_s Float64 = 3600
-- @param lookback_hours UInt32 = 72
-- @param exclude_dst Array(String) = []
-- @param use_allowlist UInt8 = 1
WITH
allow AS
(
    -- Reviewed exceptions (detections/allowlist.tsv → allowlist table). use_allowlist=0 shows what they suppress.
    SELECT match_type, value
    FROM {db:Identifier}.allowlist
    WHERE {use_allowlist:UInt8} = 1 AND enabled AND expires_at > now() AND detection_id IN ('DET-102', '*')
),
tls_names AS
(
    -- TLS server name per connection, so exceptions match what each connection asked for, not a shared CDN IP
    SELECT uid, server_name
    FROM {db:Identifier}.zeek_ssl
    WHERE ts >= {start:DateTime64(6)} - toIntervalHour({lookback_hours:UInt32}) AND ts < {end:DateTime64(6)} AND server_name != ''
)
SELECT
    'DET-102' AS detection_id,
    if(max(duration) >= 4 * {min_duration_s:Float64}, 'high', 'medium') AS severity,
    id_orig_h AS src,
    id_resp_h AS dst,
    id_resp_p AS dst_port,
    min(ts) AS first_seen,
    max(ts + toIntervalMicrosecond(toInt64(duration * 1000000))) AS last_seen,
    round(least(1, max(duration) / (4 * {min_duration_s:Float64})), 3) AS score,
    concat(id_orig_h, ' -> ', id_resp_h, ':', toString(id_resp_p), ' ', toString(count()), ' sessions, longest ',
           toString(round(max(duration) / 60)), ' min') AS summary,
    proto,
    arrayStringConcat(groupUniqArrayIf(service, service != ''), ',') AS services,
    count() AS sessions,
    round(max(duration)) AS max_duration_sec,
    round(sum(duration)) AS total_duration_sec,
    sum(orig_bytes) AS orig_bytes,
    sum(resp_bytes) AS resp_bytes
FROM {db:Identifier}.zeek_conn AS c
ANY LEFT JOIN tls_names AS t ON c.uid = t.uid
WHERE ts >= {start:DateTime64(6)} - toIntervalHour({lookback_hours:UInt32})
  AND ts < {end:DateTime64(6)}
  AND ts + toIntervalMicrosecond(toInt64(duration * 1000000)) >= {start:DateTime64(6)}
  AND local_orig AND NOT local_resp
  AND duration >= {min_duration_s:Float64}
  AND NOT has({exclude_dst:Array(String)}, id_resp_h)
  AND NOT (
        has((SELECT groupArray(value) FROM allow WHERE match_type = 'dst_ip'), id_resp_h)
     OR arrayExists(n -> isIPAddressInRange(id_resp_h, n), (SELECT groupArray(value) FROM allow WHERE match_type = 'dst_cidr'))
     OR has((SELECT groupArray(value) FROM allow WHERE match_type = 'sni'), t.server_name)
     OR arrayExists(x -> endsWith(t.server_name, x), (SELECT groupArray(value) FROM allow WHERE match_type = 'sni_suffix'))
  )
GROUP BY src, dst, dst_port, proto
ORDER BY max_duration_sec DESC
