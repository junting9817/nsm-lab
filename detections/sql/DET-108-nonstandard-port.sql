-- DET-108 Standard protocol on a non-standard port
-- ATT&CK: T1571 Non-Standard Port (TA0011)
--
-- Logic: compare the service Zeek identified from the payload (conn.service) with the actual destination port.
--   A service outside its standard port list is a hit; services not in the list are not judged.
--   service can hold several values such as "ssl,http", and each one is checked.
--   By default only outbound connections started by local hosts are considered (include_inbound=1 adds inbound).
--   score: 1 when the port is a well-known C2/backdoor port (4444, 1337, 31337, ...), otherwise 0.7
-- Why: C2 often runs HTTP/TLS/SSH on unusual ports to slip past firewalls and proxies.
-- Exceptions: rows in the allowlist table for this detection (by destination IP/CIDR or the connection's TLS SNI) are excluded.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param include_inbound UInt8 = 0
-- @param suspicious_ports Array(UInt16) = [4444,4445,1337,31337,6666,6667,8081,9001,9002,50050]
-- @param use_allowlist UInt8 = 1
WITH
allow AS
(
    -- Reviewed exceptions (detections/allowlist.tsv → allowlist table). use_allowlist=0 shows what they suppress.
    SELECT match_type, value
    FROM {db:Identifier}.allowlist
    WHERE {use_allowlist:UInt8} = 1 AND enabled AND expires_at > now() AND detection_id IN ('DET-108', '*')
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
        ts,
        id_orig_h,
        id_resp_h,
        id_resp_p,
        local_orig,
        local_resp,
        arrayFilter(x -> x != '' AND NOT startsWith(x, '-'), splitByChar(',', service)) AS services,
        arrayFilter(svc -> NOT multiIf(
            svc = 'http', id_resp_p IN (80, 8080, 8000, 8008, 8888, 3128),
            svc = 'ssl', id_resp_p IN (443, 8443, 993, 995, 465, 636, 853, 989, 990, 5061, 5986, 6443),
            svc = 'ssh', id_resp_p = 22,
            svc = 'dns', id_resp_p IN (53, 5353, 5355),
            svc = 'smtp', id_resp_p IN (25, 465, 587, 2525),
            svc = 'ftp', id_resp_p = 21,
            svc = 'rdp', id_resp_p = 3389,
            svc = 'dhcp', id_resp_p IN (67, 68),
            svc = 'ntp', id_resp_p = 123,
            svc = 'sip', id_resp_p IN (5060, 5061),
            svc = 'irc', id_resp_p IN (6667, 6697),
            svc = 'mysql', id_resp_p = 3306,
            svc = 'socks', id_resp_p = 1080,
            1), services) AS nonstandard
    FROM {db:Identifier}.zeek_conn AS c
    ANY LEFT JOIN tls_names AS t ON c.uid = t.uid
    WHERE ts >= {start:DateTime64(6)} AND ts < {end:DateTime64(6)}
      AND service != ''
      AND ((local_orig AND NOT local_resp) OR {include_inbound:UInt8} = 1)
      AND NOT (
            has((SELECT groupArray(value) FROM allow WHERE match_type = 'dst_ip'), id_resp_h)
         OR arrayExists(n -> isIPAddressInRange(id_resp_h, n), (SELECT groupArray(value) FROM allow WHERE match_type = 'dst_cidr'))
         OR has((SELECT groupArray(value) FROM allow WHERE match_type = 'sni'), t.server_name)
         OR arrayExists(x -> endsWith(t.server_name, x), (SELECT groupArray(value) FROM allow WHERE match_type = 'sni_suffix'))
      )
)
SELECT
    'DET-108' AS detection_id,
    if(has({suspicious_ports:Array(UInt16)}, id_resp_p), 'high', 'medium') AS severity,
    id_orig_h AS src,
    id_resp_h AS dst,
    id_resp_p AS dst_port,
    min(ts) AS first_seen,
    max(ts) AS last_seen,
    if(has({suspicious_ports:Array(UInt16)}, id_resp_p), 1.0, 0.7) AS score,
    concat(id_orig_h, ' -> ', id_resp_h, ':', toString(id_resp_p), ' speaks ', arrayStringConcat(groupUniqArrayArray(nonstandard), ','),
           ' (', if(any(local_orig), 'outbound', 'inbound'), ', ', toString(count()), ' connections)') AS summary,
    arrayStringConcat(groupUniqArrayArray(nonstandard), ',') AS protocols,
    if(any(local_orig), 'outbound', 'inbound') AS direction,
    count() AS conns
FROM flows
WHERE length(nonstandard) > 0
GROUP BY src, dst, dst_port
ORDER BY score DESC, conns DESC
