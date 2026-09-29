-- nsm.zeek_conn — Zeek Conn::Info (conn.log)
-- One row per connection. Basis for beaconing, long-connection, scanning and exfiltration detections.
-- ORDER BY: host pair first, because per-pair aggregation (beacon intervals, distinct ports in scans) is the main pattern.
-- Time ranges are pruned first by the daily partitions and the partition key's minmax index.
-- Columns are Zeek 8.0.10's logged fields in declaration order (sensors/zeek/tools/dump-log-schema.zeek).
-- Dots in field names become underscores (id.orig_h → id_orig_h); the mapping is zeek_rows in ingest/vector/vector.yaml.
-- Retention 30 days: whole daily partitions are dropped.
CREATE TABLE IF NOT EXISTS nsm.zeek_conn
(
    `ts`             DateTime64(6, 'UTC'),
    `uid`            String CODEC(ZSTD(1)),
    `id_orig_h`      String,
    `id_orig_p`      UInt16,
    `id_resp_h`      String,
    `id_resp_p`      UInt16,
    `proto`          LowCardinality(String),
    `service`        LowCardinality(String),
    `duration`       Float64,
    `orig_bytes`     UInt64,
    `resp_bytes`     UInt64,
    `conn_state`     LowCardinality(String),
    `local_orig`     Bool,
    `local_resp`     Bool,
    `missed_bytes`   UInt64,
    `history`        String CODEC(ZSTD(1)),
    `orig_pkts`      UInt64,
    `orig_ip_bytes`  UInt64,
    `resp_pkts`      UInt64,
    `resp_ip_bytes`  UInt64,
    `tunnel_parents` Array(String) CODEC(ZSTD(1)),
    `ip_proto`       UInt64,
    `community_id`   String CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (id_orig_h, id_resp_h, id_resp_p, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
