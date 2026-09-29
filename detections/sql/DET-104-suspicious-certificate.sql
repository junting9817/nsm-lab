-- DET-104 Suspicious server certificate (self-signed / SNI does not match the certificate)
-- ATT&CK: T1573.002 Encrypted Channel: Asymmetric Cryptography, T1587.003 Develop Capabilities: Digital Certificates
--
-- Logic: collect certificate problems on outbound TLS sessions, one reason per problem.
--   self_signed  : Zeek's certificate validation says self-signed (matches OpenSSL 1.x "self signed" and 3.x "self-signed")
--   sni_mismatch : a certificate was visible and SNI was sent, but the certificate names do not cover the SNI
--   untrusted    : issuer chain cannot be trusted, or the certificate is outside its validity period
--   score = number of reasons / 3; severity is high when self_signed and sni_mismatch occur together
-- Limitation: TLS 1.3 encrypts certificates, so most sessions cannot be validated at all (cert_chain_fps is empty).
--   The sni_matches_cert column stores false when Zeek had no value, so a mismatch only counts when a certificate was seen.
-- Exceptions: rows in the allowlist table for this detection (by destination IP/CIDR or the connection's TLS SNI) are excluded.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param local_nets Array(String) = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','127.0.0.0/8','fc00::/7','fe80::/10']
-- @param use_allowlist UInt8 = 1
WITH
allow AS
(
    -- Reviewed exceptions (detections/allowlist.tsv → allowlist table). use_allowlist=0 shows what they suppress.
    SELECT match_type, value
    FROM {db:Identifier}.allowlist
    WHERE {use_allowlist:UInt8} = 1 AND enabled AND expires_at > now() AND detection_id IN ('DET-104', '*')
)
SELECT
    'DET-104' AS detection_id,
    if(has(reasons, 'self_signed') AND has(reasons, 'sni_mismatch'), 'high', 'medium') AS severity,
    src,
    dst,
    dst_port,
    first_seen,
    last_seen,
    round(length(reasons) / 3, 3) AS score,
    concat(src, ' -> ', if(server_name = '', dst, server_name), ':', toString(dst_port), ' certificate issues: ',
           arrayStringConcat(reasons, ','), ' (', cert_validation, ')') AS summary,
    server_name,
    cert_subject,
    cert_issuer,
    cert_validation,
    reasons,
    sessions
FROM
(
    SELECT
        id_orig_h AS src,
        id_resp_h AS dst,
        id_resp_p AS dst_port,
        server_name,
        anyIf(subject, subject != '') AS cert_subject,
        anyIf(issuer, issuer != '') AS cert_issuer,
        anyIf(validation_status, validation_status != '') AS cert_validation,
        arrayFilter(x -> x != '', [
            if(countIf(match(validation_status, '(?i)self[- ]signed certificate')) > 0, 'self_signed', ''),
            if(countIf(length(cert_chain_fps) > 0 AND server_name != '' AND NOT sni_matches_cert) > 0, 'sni_mismatch', ''),
            if(countIf(match(validation_status, '(?i)unable to get local issuer|certificate has expired|not yet valid')) > 0, 'untrusted', '')
        ]) AS reasons,
        count() AS sessions,
        min(ts) AS first_seen,
        max(ts) AS last_seen
    FROM {db:Identifier}.zeek_ssl
    WHERE ts >= {start:DateTime64(6)} AND ts < {end:DateTime64(6)}
      AND arrayExists(n -> isIPAddressInRange(id_orig_h, n), {local_nets:Array(String)})
      AND NOT arrayExists(n -> isIPAddressInRange(id_resp_h, n), {local_nets:Array(String)})
      AND NOT (
            has((SELECT groupArray(value) FROM allow WHERE match_type = 'dst_ip'), id_resp_h)
         OR arrayExists(n -> isIPAddressInRange(id_resp_h, n), (SELECT groupArray(value) FROM allow WHERE match_type = 'dst_cidr'))
         OR has((SELECT groupArray(value) FROM allow WHERE match_type = 'sni'), server_name)
         OR arrayExists(x -> endsWith(server_name, x), (SELECT groupArray(value) FROM allow WHERE match_type = 'sni_suffix'))
      )
    GROUP BY src, dst, dst_port, server_name
)
WHERE length(reasons) > 0
ORDER BY score DESC, first_seen
