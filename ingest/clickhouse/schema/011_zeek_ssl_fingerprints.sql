-- Adds TLS client fingerprint columns to nsm.zeek_ssl (sensors/zeek/scripts/ja3-ja4.zeek, for the Phase 4 rare-JA4 detection)
-- 005 keeps Zeek's own fields as they are; custom fields are added here. Idempotent via IF NOT EXISTS.
ALTER TABLE nsm.zeek_ssl
    ADD COLUMN IF NOT EXISTS `ja3` String CODEC(ZSTD(1)),
    ADD COLUMN IF NOT EXISTS `ja4` LowCardinality(String);
