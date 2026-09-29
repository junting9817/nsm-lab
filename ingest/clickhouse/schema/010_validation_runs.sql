-- nsm.validation_runs — results of the PCAP validation harness (testing/validate.sh), one row per case.
-- Basis for detection latency (MTTD): replay start → first expected alert (docs/kpi.md).
--   mttd_ms    : replay start → time Suricata created the alert (engine latency)
--   visible_ms : replay start → time it was queryable in ClickHouse (pipeline included; when an analyst can see it)
-- No retention limit (few rows, kept as regression history across ruleset changes).
CREATE TABLE IF NOT EXISTS nsm.validation_runs
(
    `run_id`           String,
    `case_name`        LowCardinality(String),
    `pcap`             String,
    `pcap_sha256`      String,
    `attack_technique` LowCardinality(String),
    `primary_sid`      UInt32,
    `started_at`       DateTime64(6, 'UTC'),
    `expected_sids`    Array(UInt32),
    `detected_sids`    Array(UInt32),
    `missing_sids`     Array(UInt32),
    `unexpected_sids`  Array(UInt32),
    `first_alert_at`   Nullable(DateTime64(6, 'UTC')),
    `mttd_ms`          Nullable(Int64),
    `visible_ms`       Nullable(Int64),
    `result`           LowCardinality(String),
    `ruleset_sha256`   String,
    `rules_loaded`     UInt32
)
ENGINE = MergeTree
ORDER BY (started_at, case_name);
