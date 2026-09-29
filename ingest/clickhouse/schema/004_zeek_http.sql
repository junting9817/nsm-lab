-- nsm.zeek_http — Zeek HTTP::Info (http.log)
-- HTTP requests and responses. The username/password fields are not loaded.
-- Columns are Zeek 8.0.10's logged fields in declaration order (sensors/zeek/tools/dump-log-schema.zeek).
-- Dots in field names become underscores (id.orig_h → id_orig_h); the mapping is zeek_rows in ingest/vector/vector.yaml.
-- Retention 30 days: whole daily partitions are dropped.
CREATE TABLE IF NOT EXISTS nsm.zeek_http
(
    `ts`                DateTime64(6, 'UTC'),
    `uid`               String CODEC(ZSTD(1)),
    `id_orig_h`         String,
    `id_orig_p`         UInt16,
    `id_resp_h`         String,
    `id_resp_p`         UInt16,
    `trans_depth`       UInt64,
    `method`            LowCardinality(String),
    `host`              String CODEC(ZSTD(1)),
    `uri`               String CODEC(ZSTD(1)),
    `referrer`          String CODEC(ZSTD(1)),
    `version`           LowCardinality(String),
    `user_agent`        String CODEC(ZSTD(1)),
    `origin`            String CODEC(ZSTD(1)),
    `request_body_len`  UInt64,
    `response_body_len` UInt64,
    `status_code`       UInt64,
    `status_msg`        LowCardinality(String),
    `info_code`         UInt64,
    `info_msg`          LowCardinality(String),
    `tags`              Array(String) CODEC(ZSTD(1)),
    `proxied`           Array(String) CODEC(ZSTD(1)),
    `orig_fuids`        Array(String) CODEC(ZSTD(1)),
    `orig_filenames`    Array(String) CODEC(ZSTD(1)),
    `orig_mime_types`   Array(String) CODEC(ZSTD(1)),
    `resp_fuids`        Array(String) CODEC(ZSTD(1)),
    `resp_filenames`    Array(String) CODEC(ZSTD(1)),
    `resp_mime_types`   Array(String) CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (host, id_orig_h, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
