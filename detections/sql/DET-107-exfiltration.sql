-- DET-107 Suspected exfiltration (upload-heavy / off-hours bulk upload)
-- ATT&CK: T1048 Exfiltration Over Alternative Protocol, T1041 Exfiltration Over C2 Channel (TA0010)
--
-- Logic: group outbound connections started by local hosts by (src, dst, port) and compare bytes sent vs received.
--   PCR (producer-consumer ratio) = (sent - received) / (sent + received)   → close to 1 means upload only
--   upload_heavy         : sent ≥ min_upload_bytes and PCR ≥ min_pcr   (normal clients receive more than they send)
--   offhours_bulk_upload : bytes sent outside business hours (in tz: weekend, before work_start_hour or from
--                          work_end_hour) ≥ min_upload_bytes_offhours and PCR ≥ min_pcr
--   score = 0.5·min(1, PCR) + 0.3·min(1, sent / (4 × min_upload_bytes)) + 0.2·(off-hours reason present)
-- TLS SNI for the same destination (zeek_ssl, same window) is attached to help triage.
-- False positives: log/metric shipping agents, backups, large API requests → exclude_dst, or judge by SNI.
-- Exceptions: rows in the allowlist table for this detection (by destination IP/CIDR or the connection's TLS SNI) are excluded.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param min_upload_bytes UInt64 = 52428800
-- @param min_upload_bytes_offhours UInt64 = 10485760
-- @param min_pcr Float64 = 0.6
-- @param tz String = Asia/Seoul
-- @param work_start_hour UInt8 = 9
-- @param work_end_hour UInt8 = 18
-- @param exclude_dst Array(String) = []
-- @param use_allowlist UInt8 = 1
WITH
allow AS
(
    -- Reviewed exceptions (detections/allowlist.tsv → allowlist table). use_allowlist=0 shows what they suppress.
    SELECT match_type, value
    FROM {db:Identifier}.allowlist
    WHERE {use_allowlist:UInt8} = 1 AND enabled AND expires_at > now() AND detection_id IN ('DET-107', '*')
),
tls_names AS
(
    -- TLS server name per connection, so exceptions match what each connection asked for, not a shared CDN IP
    SELECT uid, server_name
    FROM {db:Identifier}.zeek_ssl
    WHERE ts >= {start:DateTime64(6)} - toIntervalHour(1) AND ts < {end:DateTime64(6)} AND server_name != ''
),
flows AS
(
    SELECT
        id_orig_h AS src,
        id_resp_h AS dst,
        id_resp_p AS dst_port,
        ts,
        orig_bytes,
        resp_bytes,
        toTimeZone(ts, {tz:String}) AS local_ts,
        toDayOfWeek(local_ts) >= 6
            OR toHour(local_ts) < {work_start_hour:UInt8}
            OR toHour(local_ts) >= {work_end_hour:UInt8} AS offhours
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
),
agg AS
(
    SELECT
        src, dst, dst_port,
        sum(orig_bytes) AS up,
        sum(resp_bytes) AS down,
        sumIf(orig_bytes, offhours) AS up_offhours,
        count() AS conns,
        min(ts) AS first_seen,
        max(ts) AS last_seen,
        (toFloat64(sum(orig_bytes)) - sum(resp_bytes)) / greatest(toFloat64(sum(orig_bytes)) + sum(resp_bytes), 1) AS pcr
    FROM flows
    GROUP BY src, dst, dst_port
),
sni AS
(
    SELECT id_orig_h AS src, id_resp_h AS dst, id_resp_p AS dst_port, groupUniqArrayIf(3)(server_name, server_name != '') AS server_names
    FROM {db:Identifier}.zeek_ssl
    WHERE ts >= {start:DateTime64(6)} AND ts < {end:DateTime64(6)}
    GROUP BY src, dst, dst_port
)
SELECT
    'DET-107' AS detection_id,
    if(has(reasons, 'offhours_bulk_upload') AND pcr >= 0.9, 'high', 'medium') AS severity,
    a.src AS src,
    a.dst AS dst,
    a.dst_port AS dst_port,
    a.first_seen AS first_seen,
    a.last_seen AS last_seen,
    round(0.5 * least(1, greatest(pcr, 0)) + 0.3 * least(1, up / (4 * {min_upload_bytes:UInt64}))
          + 0.2 * has(reasons, 'offhours_bulk_upload'), 3) AS score,
    concat(a.src, ' -> ', if(length(s.server_names) > 0, s.server_names[1], a.dst), ':', toString(a.dst_port),
           ' sent ', formatReadableSize(up), ' / received ', formatReadableSize(down), ' (PCR ', toString(round(pcr, 2)), ', ',
           arrayStringConcat(reasons, ','), ')') AS summary,
    up AS bytes_sent,
    down AS bytes_received,
    up_offhours AS bytes_sent_offhours,
    round(pcr, 3) AS pcr,
    conns,
    s.server_names AS server_names,
    reasons
FROM
(
    SELECT
        *,
        arrayFilter(x -> x != '', [
            if(up >= {min_upload_bytes:UInt64} AND pcr >= {min_pcr:Float64}, 'upload_heavy', ''),
            if(up_offhours >= {min_upload_bytes_offhours:UInt64} AND pcr >= {min_pcr:Float64}, 'offhours_bulk_upload', '')
        ]) AS reasons
    FROM agg
) AS a
LEFT JOIN sni AS s ON a.src = s.src AND a.dst = s.dst AND a.dst_port = s.dst_port
WHERE length(reasons) > 0
ORDER BY score DESC
