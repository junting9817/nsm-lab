-- nsm.attack_coverage — ATT&CK coverage for the SOC KPI dashboard, rebuilt by detections/attack-layer.py (atomic swap).
--   status: validated (a detection with a passing validation covers it) | observed (seen in production data only) | gap
--   in_target: part of detections/attack-targets.tsv, the denominator of the coverage KPI
CREATE TABLE IF NOT EXISTS nsm.attack_coverage
(
    `technique_id` String,
    `name`         String,
    `tactic`       LowCardinality(String),
    `in_target`    Bool,
    `status`       LowCardinality(String),
    `detections`   Array(String),
    `observed_by`  Array(String),
    `updated_at`   DateTime('UTC')
)
ENGINE = MergeTree
ORDER BY technique_id;
