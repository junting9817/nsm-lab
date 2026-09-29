-- nsm.suricata_alert — Suricata EVE alert events
-- Column names are EVE JSON paths flattened with underscores (alert.signature_id → alert_signature_id); the mapping is suricata_rows in vector.yaml.
-- Alerts are few and context matters, so the full original JSON is kept in raw as well (rule metadata, app-layer fields, ...).
-- ORDER BY: per-rule lookups and aggregation (alerts per rule, false-positive tuning) are the main pattern.
-- Retention 90 days.
CREATE TABLE IF NOT EXISTS nsm.suricata_alert
(
    `timestamp`                         DateTime64(6, 'UTC'),
    `flow_id`                           UInt64,
    `community_id`                      String CODEC(ZSTD(1)),
    `in_iface`                          LowCardinality(String),
    `pkt_src`                           LowCardinality(String),
    `src_ip`                            String,
    `src_port`                          UInt16,
    `dest_ip`                           String,
    `dest_port`                         UInt16,
    `proto`                             LowCardinality(String),
    `ip_v`                              UInt8,
    `app_proto`                         LowCardinality(String),
    `direction`                         LowCardinality(String),
    `tx_id`                             UInt64,
    `alert_action`                      LowCardinality(String),
    `alert_gid`                         UInt32,
    `alert_signature_id`                UInt32,
    `alert_rev`                         UInt32,
    `alert_signature`                   LowCardinality(String),
    `alert_category`                    LowCardinality(String),
    `alert_severity`                    UInt8,
    -- Only the rule metadata keys used for ATT&CK coverage and catalog links get columns (the rest stays in raw)
    `alert_metadata_mitre_tactic_id`    Array(String),
    `alert_metadata_mitre_technique_id` Array(String),
    `alert_metadata_nsm_id`             Array(String),
    `http_hostname`                     String CODEC(ZSTD(1)),
    `http_url`                          String CODEC(ZSTD(1)),
    `http_http_method`                  LowCardinality(String),
    `http_http_user_agent`              String CODEC(ZSTD(1)),
    `http_status`                       UInt16,
    `tls_sni`                           String CODEC(ZSTD(1)),
    `tls_version`                       LowCardinality(String),
    `flow_start`                        DateTime64(6, 'UTC'),
    `flow_pkts_toserver`                UInt64,
    `flow_pkts_toclient`                UInt64,
    `flow_bytes_toserver`               UInt64,
    `flow_bytes_toclient`               UInt64,
    `capture_file`                      String CODEC(ZSTD(1)),
    `raw`                               String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (alert_signature_id, src_ip, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
