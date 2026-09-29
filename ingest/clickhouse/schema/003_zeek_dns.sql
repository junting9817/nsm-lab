-- nsm.zeek_dns — Zeek DNS::Info (dns.log)
-- DNS queries and answers. Basis for DNS tunneling (query length, entropy) and DGA (NXDOMAIN ratio) detections.
-- Columns are Zeek 8.0.10's logged fields in declaration order (sensors/zeek/tools/dump-log-schema.zeek).
-- Dots in field names become underscores (id.orig_h → id_orig_h); the mapping is zeek_rows in ingest/vector/vector.yaml.
-- Retention 30 days: whole daily partitions are dropped.
CREATE TABLE IF NOT EXISTS nsm.zeek_dns
(
    `ts`          DateTime64(6, 'UTC'),
    `uid`         String CODEC(ZSTD(1)),
    `id_orig_h`   String,
    `id_orig_p`   UInt16,
    `id_resp_h`   String,
    `id_resp_p`   UInt16,
    `proto`       LowCardinality(String),
    `trans_id`    UInt64,
    `rtt`         Float64,
    `query`       String CODEC(ZSTD(1)),
    `qclass`      UInt64,
    `qclass_name` LowCardinality(String),
    `qtype`       UInt64,
    `qtype_name`  LowCardinality(String),
    `rcode`       UInt64,
    `rcode_name`  LowCardinality(String),
    `AA`          Bool,
    `TC`          Bool,
    `RD`          Bool,
    `RA`          Bool,
    `Z`           UInt64,
    `answers`     Array(String) CODEC(ZSTD(1)),
    `TTLs`        Array(Float64),
    `rejected`    Bool
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (query, id_orig_h, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
