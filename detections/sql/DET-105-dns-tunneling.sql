-- DET-105 DNS tunneling (data carried inside DNS queries)
-- ATT&CK: T1071.004 Application Layer Protocol: DNS (TA0011), T1048 Exfiltration Over Alternative Protocol
--
-- Logic: per (source, base domain), look at the shape of the subdomain part of each query.
--   base domain = cutToFirstSignificantSubdomain(query)   (e.g. a1b2.t.exfil.test → exfil.test)
--   subdomain   = the query with the base domain removed (dots stripped)
--   Conditions: queries ≥ min_queries, distinct subdomains ≥ min_unique_subdomains,
--               average subdomain length ≥ min_avg_sub_len, average Shannon entropy (bits/char) ≥ min_avg_entropy
--   score = 0.4·min(1, avg length/50) + 0.4·min(1, avg entropy/5) + 0.2·min(1, distinct subdomains/queries)
-- Why: encoded data (base32/hex) is long and random, so entropy is high and almost every query is a new subdomain.
-- False positives: some CDNs and security products use long hash-like subdomains → exclude_domains.
--
-- @param db Identifier
-- @param start DateTime64(6)
-- @param end DateTime64(6)
-- @param min_queries UInt32 = 50
-- @param min_unique_subdomains UInt32 = 30
-- @param min_avg_sub_len Float64 = 20
-- @param min_avg_entropy Float64 = 3.5
-- @param exclude_domains Array(String) = []
WITH
q AS
(
    SELECT
        ts,
        id_orig_h AS src,
        id_resp_h AS resolver,
        query,
        qtype_name,
        cutToFirstSignificantSubdomain(query) AS base_domain,
        replaceAll(substring(query, 1, greatest(length(query) - length(base_domain) - 1, 0)), '.', '') AS sub,
        splitByString('', sub) AS chars,
        length(chars) AS n,
        if(n = 0, 0, arraySum(arrayMap(c -> -(c / n) * log2(c / n),
                                       arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars))))) AS entropy
    FROM {db:Identifier}.zeek_dns
    WHERE ts >= {start:DateTime64(6)} AND ts < {end:DateTime64(6)}
      AND query != ''
),
agg AS
(
    SELECT
        src,
        base_domain,
        count() AS queries,
        uniqExact(sub) AS unique_subdomains,
        avg(n) AS avg_sub_len,
        max(n) AS max_sub_len,
        avg(entropy) AS avg_entropy,
        arrayStringConcat(groupUniqArray(3)(qtype_name), ',') AS qtypes,
        groupUniqArray(3)(query) AS sample_queries,
        any(resolver) AS resolver,
        min(ts) AS first_seen,
        max(ts) AS last_seen
    FROM q
    WHERE base_domain != '' AND n > 0 AND NOT has({exclude_domains:Array(String)}, base_domain)
    GROUP BY src, base_domain
)
SELECT
    'DET-105' AS detection_id,
    if(avg_entropy >= 4.2 AND avg_sub_len >= 40, 'high', 'medium') AS severity,
    src,
    resolver AS dst,
    toUInt16(53) AS dst_port,
    first_seen,
    last_seen,
    round(0.4 * least(1, avg_sub_len / 50) + 0.4 * least(1, avg_entropy / 5) + 0.2 * least(1, unique_subdomains / queries), 3) AS score,
    concat(src, ' sent ', toString(queries), ' queries under ', base_domain, ' (', toString(unique_subdomains),
           ' distinct subdomains, avg length ', toString(round(avg_sub_len, 1)), ', entropy ', toString(round(avg_entropy, 2)), ')') AS summary,
    base_domain,
    queries,
    unique_subdomains,
    round(avg_sub_len, 1) AS avg_subdomain_len,
    max_sub_len AS max_subdomain_len,
    round(avg_entropy, 3) AS avg_subdomain_entropy,
    qtypes,
    sample_queries
FROM agg
WHERE queries >= {min_queries:UInt32}
  AND unique_subdomains >= {min_unique_subdomains:UInt32}
  AND avg_sub_len >= {min_avg_sub_len:Float64}
  AND avg_entropy >= {min_avg_entropy:Float64}
ORDER BY score DESC
