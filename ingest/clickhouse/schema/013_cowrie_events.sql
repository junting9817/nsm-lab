-- nsm.cowrie_events — Cowrie SSH honeypot events (Phase 5), one row per event.
-- Path: honeypot Vector → bucket (one-way) → nsm-honeypot-pull → /data/logs/honeypot/cowrie → Vector cowrie_rows.
-- Columns keep Cowrie's field names except version → client_version. Events are sparse, so the original line is kept in raw.
-- src_country_* / src_asn / src_as_org come from DB-IP Lite at ingest time, i.e. who held the address when the attack happened.
-- ORDER BY: per-event-type aggregation by source (attempts per IP, credential pairs, commands) is the main pattern.
-- Retention 90 days (same as Suricata alerts).
CREATE TABLE IF NOT EXISTS nsm.cowrie_events
(
    `timestamp`        DateTime64(6, 'UTC'),
    `eventid`          LowCardinality(String),
    `sensor`           LowCardinality(String),
    `session`          String,
    `protocol`         LowCardinality(String),
    `src_ip`           String,
    `src_port`         UInt16,
    `dst_ip`           String,
    `dst_port`         UInt16,
    `username`         String CODEC(ZSTD(1)),
    `password`         String CODEC(ZSTD(1)),
    `input`            String CODEC(ZSTD(1)),
    `client_version`   LowCardinality(String),
    `hassh`            LowCardinality(String),
    `duration_ms`      UInt64,
    `url`              String CODEC(ZSTD(1)),
    `shasum`           String,
    `message`          String CODEC(ZSTD(1)),
    `src_country_code` LowCardinality(String),
    `src_country`      LowCardinality(String),
    `src_asn`          UInt32,
    `src_as_org`       LowCardinality(String),
    `raw`              String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (eventid, src_ip, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
