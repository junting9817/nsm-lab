-- Addresses belonging to this lab. Populated by infra/scripts/setup-lab-addresses.sh from .env, which is git-ignored,
-- so the values live outside the repository and no query, dashboard or document has to contain them.
--
-- Queries that must not count our own traffic say:  NOT IN (SELECT address FROM nsm.lab_addresses)
CREATE TABLE IF NOT EXISTS nsm.lab_addresses
(
    `address` String,                     -- an address this lab owns: the sensor, the honeypot, a test host
    `role`    LowCardinality(String),      -- sensor | honeypot | other, for readability only
    `note`    String,
    `added`   DateTime('UTC')
)
ENGINE = ReplacingMergeTree(added)
ORDER BY address;
