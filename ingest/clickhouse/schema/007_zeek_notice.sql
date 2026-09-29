-- nsm.zeek_notice — Zeek Notice::Info (notice.log)
-- Zeek notice framework events (e.g. SSH brute forcing, certificate validation failures).
-- Columns are Zeek 8.0.10's logged fields in declaration order (sensors/zeek/tools/dump-log-schema.zeek).
-- Dots in field names become underscores (id.orig_h → id_orig_h); the mapping is zeek_rows in ingest/vector/vector.yaml.
-- Retention 30 days: whole daily partitions are dropped.
CREATE TABLE IF NOT EXISTS nsm.zeek_notice
(
    `ts`             DateTime64(6, 'UTC'),
    `uid`            String CODEC(ZSTD(1)),
    `id_orig_h`      String,
    `id_orig_p`      UInt16,
    `id_resp_h`      String,
    `id_resp_p`      UInt16,
    `fuid`           String CODEC(ZSTD(1)),
    `file_mime_type` LowCardinality(String),
    `file_desc`      String CODEC(ZSTD(1)),
    `proto`          LowCardinality(String),
    `note`           LowCardinality(String),
    `msg`            String CODEC(ZSTD(1)),
    `sub`            String CODEC(ZSTD(1)),
    `src`            String,
    `dst`            String,
    `p`              UInt16,
    `n`              UInt64,
    `peer_descr`     String CODEC(ZSTD(1)),
    `actions`        Array(String) CODEC(ZSTD(1)),
    `suppress_for`   Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (note, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
