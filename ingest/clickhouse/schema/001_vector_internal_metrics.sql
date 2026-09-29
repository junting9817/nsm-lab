-- Vector's own health metrics (events received and sent, errors, buffer usage).
-- Used in Phase 1 to prove the Vector → ClickHouse → Grafana path, and later for pipeline health panels.
-- Retention 7 days: whole daily partitions are dropped (ttl_only_drop_parts).
CREATE TABLE IF NOT EXISTS nsm.vector_internal_metrics
(
    timestamp  DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    name       LowCardinality(String),
    namespace  LowCardinality(String),
    kind       LowCardinality(String),
    tags       Map(LowCardinality(String), String),
    value      Float64 CODEC(Gorilla, ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (name, timestamp)
TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
