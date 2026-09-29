-- nsm.zeek_x509 — Zeek X509::Info (x509.log)
-- Certificates. log-hostcerts-only means only server certificates are logged.
-- Columns are Zeek 8.0.10's logged fields in declaration order (sensors/zeek/tools/dump-log-schema.zeek).
-- Dots in field names become underscores (id.orig_h → id_orig_h); the mapping is zeek_rows in ingest/vector/vector.yaml.
-- Retention 30 days: whole daily partitions are dropped.
CREATE TABLE IF NOT EXISTS nsm.zeek_x509
(
    `ts`                           DateTime64(6, 'UTC'),
    `fingerprint`                  String CODEC(ZSTD(1)),
    `certificate_version`          UInt64,
    `certificate_serial`           String CODEC(ZSTD(1)),
    `certificate_subject`          String CODEC(ZSTD(1)),
    `certificate_issuer`           String CODEC(ZSTD(1)),
    `certificate_not_valid_before` DateTime64(6, 'UTC'),
    `certificate_not_valid_after`  DateTime64(6, 'UTC'),
    `certificate_key_alg`          LowCardinality(String),
    `certificate_sig_alg`          LowCardinality(String),
    `certificate_key_type`         LowCardinality(String),
    `certificate_key_length`       UInt64,
    `certificate_exponent`         String CODEC(ZSTD(1)),
    `certificate_curve`            LowCardinality(String),
    `san_dns`                      Array(String) CODEC(ZSTD(1)),
    `san_uri`                      Array(String) CODEC(ZSTD(1)),
    `san_email`                    Array(String) CODEC(ZSTD(1)),
    `san_ip`                       Array(String) CODEC(ZSTD(1)),
    `basic_constraints_ca`         Bool,
    `basic_constraints_path_len`   UInt64,
    `host_cert`                    Bool,
    `client_cert`                  Bool
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (fingerprint, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
