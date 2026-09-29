-- Phase 7 detection history and analyst verdicts.
--
-- nsm.detection_runs — one row per scheduled run of a behavior detection (detections/schedule.py, hourly).
-- nsm.detection_hits — every row a detection returned, with its common columns (DET-101..109 contract) and the
--   detection-specific columns kept as JSON in details. Each hourly run looks at the last 24 h, so the same finding
--   appears in many runs; hit_key (detection_id|src|dst|dst_port) identifies it across runs.
--   current findings = rows of the latest run per detection; daily volume = hit_keys by the day they were first reported.
-- nsm.verdicts — analyst judgements that make the FP rate measurable (docs/kpi.md):
--   source suricata  → subject '<sid>|<src_ip>'   (every alert of that signature from that source)
--   source detection → subject '<hit_key>'
--   verdict: true_positive | false_positive; tune_id links the tuning-log entry; the latest verdict per subject wins.
CREATE TABLE IF NOT EXISTS nsm.detection_runs
(
    `run_id`       String,
    `run_at`       DateTime64(3, 'UTC'),
    `window_start` DateTime64(6, 'UTC'),
    `window_end`   DateTime64(6, 'UTC'),
    `detection_id` LowCardinality(String),
    `result`       LowCardinality(String),
    `hits`         UInt32,
    `duration_ms`  UInt32,
    `backfill`     Bool,
    `error`        String
)
ENGINE = MergeTree
ORDER BY (detection_id, run_at)
TTL toDateTime(run_at) + INTERVAL 180 DAY DELETE;

CREATE TABLE IF NOT EXISTS nsm.detection_hits
(
    `run_id`       String,
    `run_at`       DateTime64(3, 'UTC'),
    `window_start` DateTime64(6, 'UTC'),
    `window_end`   DateTime64(6, 'UTC'),
    `detection_id` LowCardinality(String),
    `severity`     LowCardinality(String),
    `src`          String,
    `dst`          String,
    `dst_port`     UInt16,
    `first_seen`   DateTime64(6, 'UTC'),
    `last_seen`    DateTime64(6, 'UTC'),
    `score`        Float64,
    `summary`      String CODEC(ZSTD(1)),
    `details`      String CODEC(ZSTD(3)),
    `hit_key`      String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(run_at)
ORDER BY (detection_id, hit_key, run_at)
TTL toDateTime(run_at) + INTERVAL 180 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS nsm.verdicts
(
    `created_at` DateTime64(3, 'UTC') DEFAULT now64(3),
    `source`     LowCardinality(String),
    `subject`    String,
    `verdict`    LowCardinality(String),
    `analyst`    LowCardinality(String),
    `tune_id`    String,
    `note`       String CODEC(ZSTD(1))
)
ENGINE = MergeTree
ORDER BY (source, subject, created_at);
