-- nsm.zeek_ssl — Zeek SSL::Info (ssl.log)
-- TLS handshakes. Basis for self-signed and SNI-mismatch detections (validation_status, sni_matches_cert).
-- Columns are Zeek 8.0.10's logged fields in declaration order (sensors/zeek/tools/dump-log-schema.zeek).
-- Dots in field names become underscores (id.orig_h → id_orig_h); the mapping is zeek_rows in ingest/vector/vector.yaml.
-- Retention 30 days: whole daily partitions are dropped.
CREATE TABLE IF NOT EXISTS nsm.zeek_ssl
(
    `ts`                    DateTime64(6, 'UTC'),
    `uid`                   String CODEC(ZSTD(1)),
    `id_orig_h`             String,
    `id_orig_p`             UInt16,
    `id_resp_h`             String,
    `id_resp_p`             UInt16,
    `version`               LowCardinality(String),
    `cipher`                LowCardinality(String),
    `curve`                 LowCardinality(String),
    `server_name`           String CODEC(ZSTD(1)),
    `resumed`               Bool,
    `last_alert`            LowCardinality(String),
    `next_protocol`         LowCardinality(String),
    `established`           Bool,
    `ssl_history`           String CODEC(ZSTD(1)),
    `cert_chain_fps`        Array(String) CODEC(ZSTD(1)),
    `client_cert_chain_fps` Array(String) CODEC(ZSTD(1)),
    `subject`               String CODEC(ZSTD(1)),
    `issuer`                String CODEC(ZSTD(1)),
    `client_subject`        String CODEC(ZSTD(1)),
    `client_issuer`         String CODEC(ZSTD(1)),
    `sni_matches_cert`      Bool,
    `validation_status`     LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (server_name, id_orig_h, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
