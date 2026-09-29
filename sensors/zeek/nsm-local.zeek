##! Zeek site policy for the NSM sensor (Zeek 8.0.10 LTS).
##!
##! Same load list as the image's default local.zeek, minus detect-MHR.
##! detect-MHR looks up observed file hashes at Team Cymru over DNS, which sends what the sensor saw outside.

# --- same as the default local.zeek ---------------------------------------------
@load misc/loaded-scripts
@load misc/capture-loss
@load misc/stats
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames
@load protocols/http/detect-sql-injection
@load frameworks/files/hash-all-files
@load policy/frameworks/notice/extend-email/hostnames
@load frameworks/telemetry/log

# --- NSM additions ---------------------------------------------------------------
# JSON logs (parsed by Vector)
@load tuning/json-logs
# Flow ID matching Suricata EVE's community_id (seed 0)
@load policy/protocols/conn/community-id-logging
# TLS client fingerprints JA3/JA4 (own implementation, cross-checked against Suricata's built-in values: testing/fingerprints/crosscheck.sh)
@load ./scripts/ja3-ja4

redef digest_salt = "nsm-lab-sensor";

# Regional subnet of the default VPC (same as Suricata HOME_NET)
redef Site::local_nets += { 10.128.0.0/9 };

# Rename conn.log → conn.YYYY-MM-DD-HH-MM-SS.log every hour.
# The nsm-retention timer deletes rotated files after 48 hours.
redef Log::default_rotation_interval = 1 hr;

# The default AF_PACKET ring buffer (128 MiB) is large for the 768 MiB container limit
redef AF_Packet::buffer_size = 32 * 1024 * 1024;
