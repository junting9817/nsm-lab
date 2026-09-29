-- Phase 6 response state. Append-only: the current block list is derived, never updated in place.
--
-- nsm.response_actions — every decision the responder or an analyst makes, one row each.
--   action: block | release | observe (trigger not enforced) | reject (never-block list, rate/size cap, invalid IP)
--   active block set = IPs whose latest block/release row is a block with expires_at in the future
--   a release with a future expires_at suppresses automatic re-blocking until then
--   evidence_at: first evidence of the triggering activity, the start point for MTTR (docs/kpi.md)
-- nsm.response_applies — what the reconciler pushed to the nsm-blocklist VPC firewall rule, one row per change.
--   MTTR = applied_at of the first apply whose `added` contains the IP − evidence_at of the block
-- No TTL: a few rows per day, and the history is the audit trail of automated blocking.
CREATE TABLE IF NOT EXISTS nsm.response_actions
(
    `created_at`  DateTime64(3, 'UTC') DEFAULT now64(3),
    `action`      LowCardinality(String),
    `ip`          String,
    `trigger`     LowCardinality(String),
    `rule`        String,
    `reason`      String,
    `evidence_at` Nullable(DateTime64(3, 'UTC')),
    `expires_at`  Nullable(DateTime64(3, 'UTC')),
    `mode`        LowCardinality(String),
    `actor`       LowCardinality(String),
    `detail`      String CODEC(ZSTD(1))
)
ENGINE = MergeTree
ORDER BY (ip, created_at);

CREATE TABLE IF NOT EXISTS nsm.response_applies
(
    `applied_at`  DateTime64(3, 'UTC') DEFAULT now64(3),
    `firewall`    LowCardinality(String),
    `mode`        LowCardinality(String),
    `result`      LowCardinality(String),
    `ranges`      Array(String),
    `added`       Array(String),
    `removed`     Array(String),
    `duration_ms` UInt32,
    `error`       String
)
ENGINE = MergeTree
ORDER BY applied_at;
