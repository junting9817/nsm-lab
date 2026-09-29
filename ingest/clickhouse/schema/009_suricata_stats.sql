-- nsm.suricata_stats — Suricata EVE stats events (every minute, cumulative counters)
-- Sensor health: kernel drop rate (capture_kernel_drops / capture_kernel_packets), memory use, alert counts.
-- Counters accumulate since engine start; compute per-interval values as differences, allowing for restarts (uptime drops).
-- Suricata does not log zero counters (null-values default), so missing values arrive as the column default 0.
-- Retention 90 days.
CREATE TABLE IF NOT EXISTS nsm.suricata_stats
(
    `timestamp`                         DateTime64(6, 'UTC'),
    `stats_uptime`                      UInt64,
    `stats_capture_kernel_packets`      UInt64,
    `stats_capture_kernel_drops`        UInt64,
    `stats_capture_errors`              UInt64,
    `stats_decoder_pkts`                UInt64,
    `stats_decoder_bytes`               UInt64,
    `stats_decoder_invalid`             UInt64,
    `stats_flow_active`                 UInt64,
    `stats_flow_memuse`                 UInt64,
    `stats_flow_memcap`                 UInt64,
    `stats_flow_emerg_mode_entered`     UInt64,
    `stats_tcp_active_sessions`         UInt64,
    `stats_tcp_memuse`                  UInt64,
    `stats_tcp_reassembly_memuse`       UInt64,
    `stats_tcp_reassembly_gap`          UInt64,
    `stats_tcp_midstream_pickups`       UInt64,
    `stats_detect_alert`                UInt64,
    `stats_detect_alerts_suppressed`    UInt64,
    `stats_detect_alert_queue_overflow` UInt64,
    `stats_pcap_log_written`            UInt64,
    `stats_memcap_pressure`             UInt64,
    `stats_memcap_pressure_max`         UInt64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY timestamp
TTL toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
