-- nsm.allowlist — reviewed exceptions for detections (Phase 6 also reads it as the "never block" list).
-- Source of truth: detections/allowlist.tsv in git. detections/sync-allowlist.sh validates it and swaps the table contents.
-- Every row points to a tuning log entry (id) and has a review date; expired or disabled rows are ignored by detections.
CREATE TABLE IF NOT EXISTS nsm.allowlist
(
    `id`           String,                  -- tuning log reference, e.g. TUNE-002
    `detection_id` LowCardinality(String),  -- DET-101 ... or * for every detection
    `match_type`   LowCardinality(String),  -- dst_ip | dst_cidr | sni | sni_suffix
    `value`        String,
    `reason`       String,
    `expires_at`   DateTime('UTC'),
    `enabled`      Bool DEFAULT true
)
ENGINE = MergeTree
ORDER BY (detection_id, match_type, value);
