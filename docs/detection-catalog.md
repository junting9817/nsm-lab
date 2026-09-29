# Detection catalog

When adding or changing a detection rule, update this file **in the same commit**.

## Entry template

### DET-000 — Rule name

| Field | Content |
|---|---|
| Type | Suricata signature / ClickHouse SQL / Sigma |
| Purpose | What it is meant to catch |
| Logic | Conditions and thresholds, and why those thresholds |
| Data source | e.g. `nsm.zeek_conn` |
| ATT&CK | e.g. T1071.001 |
| File | e.g. `detections/sql/beaconing.sql` |
| Validation | How to reproduce and the expected result (e.g. a `testing/validate.sh` case name) |
| False-positive notes | Known benign patterns and exceptions |
| Status | Draft / Validated / Tuning |

## Index

| ID | Name | Type | ATT&CK | Status |
|---|---|---|---|---|
| DET-000 | Pipeline canary | Suricata signature | — (not a detection rule) | Validated |
| DET-001 | ET Open ruleset (external rules) | Suricata signature | Per-rule metadata (validation cases: T1595.002, T1059.004, T1071.004, T1190) | Validated (4 cases) |
| DET-101 | Beaconing | ClickHouse SQL | T1071.001 | Validated (fixtures + live beacon); TUNE-002..004 |
| DET-102 | Long connections | ClickHouse SQL | T1071 | Validated (fixtures); TUNE-005..008 |
| DET-103 | Rare TLS client fingerprint (JA4) | ClickHouse SQL + Zeek script | T1071.001, T1573.002 | Validated (fixtures); baseline warming up |
| DET-104 | Suspicious server certificate | ClickHouse SQL | T1573.002, T1587.003 | Validated (fixtures) |
| DET-105 | DNS tunneling | ClickHouse SQL | T1071.004, T1048 | Validated (fixtures) |
| DET-106 | Suspected DGA (NXDOMAIN spike) | ClickHouse SQL | T1568.002 | Validated (fixtures) |
| DET-107 | Suspected exfiltration | ClickHouse SQL | T1048, T1041 | Validated (fixtures); TUNE-009..010 |
| DET-108 | Standard protocol on non-standard port | ClickHouse SQL | T1571 | Validated (fixtures) |
| DET-109 | Port and host scanning | ClickHouse SQL | T1046, T1595.001 | Validated (fixtures) |
| RSP-001 | Honeypot attacker → block | Grafana alert rule → responder | — (response trigger) | Enforcing since 2026-09-15; TUNE-012 |
| RSP-002 | Severe Suricata alert → block | Grafana alert rule → responder | — (response trigger) | Enforcing since 2026-09-15; TUNE-011 |
| RSP-003 | SSH brute force or scanning → observe | Grafana alert rule → responder | — (response trigger) | Firing in dry-run (observe only) |

### DET-000 — Pipeline canary

| Field | Content |
|---|---|
| Type | Suricata signature (`sid:9000000`) |
| Purpose | Confirms the capture → EVE → Vector → ClickHouse → Grafana path is alive. Not an attack detection rule |
| Logic | Alert when the URI of an HTTP request to `$HOME_NET` starts with `/nsm-pipeline-canary` |
| Data source | `nsm.suricata_alert` (`alert_metadata_nsm_id = ['DET-000']`) |
| ATT&CK | Not applicable |
| File | `detections/suricata/local.rules` |
| Validation | `curl http://<sensor external IP>/nsm-pipeline-canary` → within seconds a row appears in `nsm.suricata_alert` and shows in "Recent Suricata alerts" on the Live Traffic dashboard (confirmed 2026-09-13) |
| False-positive notes | An external scanner requesting the same path can trigger it. When the sensor sends it to its own external IP, only the returning flow (source = sensor external IP) alerts |
| Status | Validated |

### DET-001 — ET Open ruleset

| Field | Content |
|---|---|
| Type | Suricata signatures (Proofpoint Emerging Threats Open, external rules) |
| Purpose | Signature detection of known scanning, exploitation and malware C2 indicators |
| Logic | suricata-update default source `et/open`. As of 2026-09-14: 52,744 enabled out of 68,697, 0 load failures |
| Data source | `nsm.suricata_alert` |
| ATT&CK | The rule's `metadata: mitre_technique_id` → column `alert_metadata_mitre_technique_id` |
| File | `/data/suricata/rules/suricata.rules` (not in the repo), filters: `sensors/suricata/update/{disable,enable,modify}.conf` |
| Updates | `nsm-rules-update.timer` daily at 18:30 UTC (03:30 KST). Downloaded in a separate container; after `suricata -T` passes, the sensor restarts only if the file changed |
| Validation | `sudo testing/validate.sh` — replays 3 synthetic PCAPs onto the dummy interface and checks that the SIDs below are loaded by the production pipeline |
| False-positive notes | The sensor's own requests to the GCE metadata server (169.254.169.254) trigger user-agent rules (2024897, 2060251, 2034567) → suppressed by destination IP (TUNE-001, `sensors/suricata/threshold.config`) |
| Status | Validated |

**Validation cases** (`testing/pcap/cases.json`; 10 full runs on 2026-09-14, all 3/3 PASS — 2 back-to-back, 1 after a rule update and sensor restart, 7 after translating the harness; ranges below cover all 36 PASS rows including single-case runs)

| Case | ATT&CK | Primary SID | Also expected | Engine latency (MTTD) | Queryable after (median) |
|---|---|---|---|---:|---:|
| scan-nmap-nse-http | T1595.002 | 2009358 ET SCAN Nmap Scripting Engine User-Agent | — | 106–166 ms | 2.6–12.1 s (3.9 s) |
| attack-response-id-root | T1059.004 | 2100498 GPL ATTACK_RESPONSE id check returned root | 2019284 ET ATTACK_RESPONSE Output of id command | 102–164 ms | 2.6–13.3 s (3.8 s), one 30.8 s outlier |
| c2-dns-nxransomware | T1071.004 | 2025143 ET MALWARE MSIL/NxRansomware C2 Domain | 2022642, 2066094 (ngrok DNS lookup INFO) | 102–147 ms | 2.6–12.2 s (12.0 s) |
| exploit-apache-path-traversal (added 2026-09-15) | T1190 | 2034125 ET EXPLOIT Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773) | 2011465 ET WEB_SERVER /bin/sh In URI | 169 ms (first run) | 11.6 s (first run) |

The T1190 case is modeled on real RedTail botnet requests against this sensor (user agent `libredtail-http`, same traversal URL) with a harmless
`id` body. Its expected SIDs were taken from an offline `suricata -r` of the sample: first draft answered 403 and also fired
GPL 2101201 "403 Forbidden", so the sample now answers 302 like the real server. First full run: 4/4 PASS.

The queryable-after spread is Vector's idle-file polling, not the engine (`docs/architecture.md` section 7, `docs/kpi.md`).

---

## Behavior-based detections (Phase 4)

All nine run as parameterized ClickHouse SQL through `sudo detections/run.sh <DET-ID>` (defaults: last 24 h, database `nsm`)
and return the same leading columns: `detection_id, severity, src, dst, dst_port, first_seen, last_seen, score, summary`.
Parameters and their defaults are declared in each SQL header (`sudo detections/run.sh --list`).

**Scheduled runs (Phase 7):** `nsm-detections.timer` runs all nine every hour at :07 over the last 24 h (`detections/schedule.py`, installed by `infra/scripts/setup-detections.sh`); rows go to `nsm.detection_hits`, run status to `nsm.detection_runs`. Analyst verdicts (`detections/verdict.sh`) feed the FP-rate KPI. A 48 h backfill on 2026-09-15 applied today's allowlist to past windows.

**Validation method (all nine):** `sudo testing/detections/validate.sh` builds synthetic traffic with positive and negative hosts
per detection (`testing/detections/fixtures.py`), analyzes it with offline Zeek using the production site config, loads it into
the isolated database `nsm_test`, runs the production SQL and checks every host. Result on 2026-09-14: **27/27 host checks passed** (32/32 after the allowlist scenarios below were added).
The first run failed 7 checks until the harness treated RFC 5737 peers as external — evidence that it reports real failures.

**Production review (24 h ending 2026-09-14 01:15 UTC):** every hit came from the sensor host itself and matched known software.
Reviewed exceptions (TUNE-002..010, `detections/allowlist.tsv`) brought DET-101 from 3 to 0 hits, DET-102 from 13 to 2 and DET-107 from 5 to 1;
the residual hits are connections Zeek picked up mid-stream after a restart (no SNI). See `docs/tuning-log.md`.

**Exceptions:** DET-101, 102, 103, 104, 107 and 108 read `nsm.allowlist` (destination IP/CIDR or the connection's own TLS SNI; expired and
disabled rows ignored) and accept `--set use_allowlist=0` to show what the exceptions hide. The fixture harness checks active, expired and
disabled entries (32/32 host checks).

### DET-101 — Beaconing

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_conn` |
| Purpose | Periodic C2 check-ins from a local host to an external destination |
| Logic | Per (src, dst, port, proto) with ≥ 20 outbound connections: score = 0.45·(1 − MAD/median interval) + 0.25·(1 − CV) + 0.15·(1 − MAD/median bytes sent) + 0.15·min(1, conns/50); report when score ≥ 0.8 and median interval ≥ 5 s |
| Data source | `nsm.zeek_conn` (`local_orig AND NOT local_resp`) |
| ATT&CK | T1071.001 |
| File | `detections/sql/DET-101-beaconing.sql` |
| Validation | Fixtures: 60 s ±10% jitter reported (score 0.965); exponential gaps, 60 s ±90% jitter, and a regular pair with only 10 connections not reported. Live (2026-09-14, `testing/beacon-sim/validate_live.sh`): ±20% jitter reported with score 0.912, ±90% jitter not reported (0.630) |
| False-positive notes | Software update polling is perfectly periodic: `grafana.com` and `deb.debian.org` every 600 s, `downloads.claude.ai` every 1800 s (MAD 0) |
| Status | Validated; exceptions TUNE-002..004, TUNE-015 (IPv6 multicast), TUNE-016 (Claude Code telemetry) |

### DET-102 — Long connections

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_conn` |
| Purpose | Outbound sessions kept open for a long time (interactive C2, tunnels) |
| Logic | Outbound connections with duration ≥ 3600 s that overlap the window (started up to 72 h earlier); score = min(1, longest / 4 h) |
| Data source | `nsm.zeek_conn` |
| ATT&CK | T1071 |
| File | `detections/sql/DET-102-long-connections.sql` |
| Validation | Fixtures: 2 h keepalive session reported; 10 min session not reported |
| False-positive notes | HTTP/2 keep-alive and long polling: `api.anthropic.com` (Claude Code), `*-osconfig.googleapis.com` / `*-agentcommunication.googleapis.com` (GCE agents). Zeek logs a connection only when it ends |
| Status | Validated; exceptions TUNE-005..008, TUNE-013 (logging.googleapis.com) |

### DET-103 — Rare TLS client fingerprint (JA4)

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_ssl`; JA4 computed by `sensors/zeek/scripts/ja3-ja4.zeek` |
| Purpose | Custom TLS stacks (malware, offensive tools) that differ from the software normally in use |
| Logic | JA4 seen ≤ 3 times and by ≤ 1 host in the 168 h baseline ending at the window end; outbound only (by `local_nets`) |
| Data source | `nsm.zeek_ssl` (`ja4` column, schema 011) |
| ATT&CK | T1071.001, T1573.002 |
| File | `detections/sql/DET-103-rare-tls-fingerprint.sql` |
| Validation | Fixtures: one-off legacy ClientHello reported; the same browser-like ClientHello from 3 hosts × 30 sessions not reported. JA4/JA3 correctness: `testing/fingerprints/crosscheck.sh` against Suricata 8 (292 flows: JA3 292/292, JA4 291/292 with the 1 difference explained) |
| False-positive notes | JA4 logging started 2026-09-14 00:55 UTC, so the baseline holds hours, not 7 days — everything looks rare during warm-up (5 hits, all sensor software and manual `curl`) |
| Status | Validated; exceptions TUNE-014 (suricata-update), TUNE-017 (Claude Code telemetry); results meaningful after the baseline fills |

### DET-104 — Suspicious server certificate

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_ssl` |
| Purpose | C2 or phishing endpoints with self-signed certificates or certificates that do not match the requested name |
| Logic | Reasons per (src, dst, port, SNI): `self_signed`, `sni_mismatch` (only when a certificate was visible), `untrusted`; severity high when self-signed and mismatched together |
| Data source | `nsm.zeek_ssl` (`validation_status`, `sni_matches_cert`, `cert_chain_fps`) |
| ATT&CK | T1573.002, T1587.003 |
| File | `detections/sql/DET-104-suspicious-certificate.sql` |
| Validation | Fixtures: self-signed + mismatched → high with both reasons; self-signed with matching name → medium with `self_signed`; TLS 1.3-style session without a visible certificate → not reported |
| False-positive notes | TLS 1.3 hides certificates, so coverage is limited to TLS ≤ 1.2 sessions. No production hits |
| Status | Validated |

### DET-105 — DNS tunneling

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_dns` |
| Purpose | Data or C2 carried in DNS query names |
| Logic | Per (src, base domain): ≥ 50 queries, ≥ 30 distinct subdomains, average subdomain length ≥ 20, average Shannon entropy ≥ 3.5 bits/char |
| Data source | `nsm.zeek_dns` |
| ATT&CK | T1071.004, T1048 |
| File | `detections/sql/DET-105-dns-tunneling.sql` |
| Validation | Fixtures: 120 TXT queries with 48-char base32 labels reported (avg length 50.1, entropy 4.51); 120 ordinary lookups not reported |
| False-positive notes | Services using long hash-like subdomains (some CDNs and security products) → `exclude_domains`. Tunneling services (e.g. `*.ngrok.io`) are public suffixes, so each tunnel is its own base domain. No production hits |
| Status | Validated |

### DET-106 — Suspected DGA (NXDOMAIN spike)

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_dns` |
| Purpose | Malware resolving many generated domains in a burst |
| Logic | Per source per 10 min bucket: ≥ 20 NXDOMAIN, ratio ≥ 0.5, ≥ 15 distinct base domains, and ≥ 5× the time-based average of the preceding 24 h |
| Data source | `nsm.zeek_dns` |
| ATT&CK | T1568.002 |
| File | `detections/sql/DET-106-dga-nxdomain-spike.sql` |
| Validation | Fixtures: quiet host bursting 54 NXDOMAIN among 60 random names reported (score 0.95); steady resolver user with 5% NXDOMAIN not reported |
| False-positive notes | Misconfigured search domains can produce NXDOMAIN bursts. No production hits |
| Status | Validated |

### DET-107 — Suspected exfiltration

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_conn` (+ SNI from `nsm.zeek_ssl`) |
| Purpose | Large, upload-heavy transfers, especially outside business hours |
| Logic | PCR = (sent − received)/(sent + received); `upload_heavy` when sent ≥ 50 MiB and PCR ≥ 0.6; `offhours_bulk_upload` when off-hours sent ≥ 10 MiB (Asia/Seoul, weekends or outside 09:00–18:00) and PCR ≥ 0.6 |
| Data source | `nsm.zeek_conn`, `nsm.zeek_ssl` |
| ATT&CK | T1048, T1041 |
| File | `detections/sql/DET-107-exfiltration.sql` |
| Validation | Fixtures (thresholds 2 MB / 0.5 MB): 3 MB upload at 12:00 KST → `upload_heavy` only; 1 MB upload at 01:00 KST → `offhours_bulk_upload` only; 3 MB download not reported |
| False-positive notes | Telemetry and API uploads: `monitoring.googleapis.com` (Ops Agent, up to 84 MiB/day per connection group), `api.anthropic.com` (Claude Code prompts, 88 MiB) |
| Status | Validated; exceptions TUNE-009..010 |

### DET-108 — Standard protocol on non-standard port

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_conn` |
| Purpose | HTTP/TLS/SSH and other protocols moved to unusual ports to evade controls |
| Logic | Zeek's payload-based `service` compared with a standard port list per service; outbound only by default (`include_inbound=1` adds inbound) |
| Data source | `nsm.zeek_conn` |
| ATT&CK | T1571 |
| File | `detections/sql/DET-108-nonstandard-port.sql` |
| Validation | Fixtures: HTTP on 4444 → high; SSH on 2222 → medium; HTTP on 80 and SSH on 22 not reported |
| False-positive notes | With `include_inbound=1`, internet scanners probing port 22 with HTTP/TLS show up. No outbound production hits |
| Status | Validated |

### DET-109 — Port and host scanning

| Field | Details |
|---|---|
| Type | ClickHouse SQL on `nsm.zeek_conn` |
| Purpose | Reconnaissance: many ports on one host (vertical) or one port on many hosts (horizontal) |
| Logic | Vertical ≥ 50 ports or horizontal ≥ 30 hosts, with SYN:SYN-ACK ≥ 3; local sources reported as T1046 (high), external as T1595.001 (low) |
| Data source | `nsm.zeek_conn` (`history`, `conn_state`) |
| ATT&CK | T1046, T1595.001 |
| File | `detections/sql/DET-109-scanning.sql` |
| Validation | Fixtures: external SYN scan of 120 ports → vertical/T1595.001; local sweep of port 445 on 60 hosts → horizontal/T1046/high; normal client not reported |
| False-positive notes | Only ports 22 and 80 reach the VM through the VPC firewall, so inbound internet scans rarely cross the thresholds. No production hits |
| Status | Validated |

---

## Response triggers (Phase 6)

Grafana alert rules (`dashboards/provisioning/alerting/nsm-response.yaml`, evaluated every minute) that send one webhook per source IP
to `nsm-responder`. The rule reports what it saw; the block decision belongs to the responder's policy
(`response/webhook/policy.py`): public IPv4 only, never-block list (`response/never-block.txt` + `/etc/nsm/never-block.local`),
analyst suppression, caps of 200 active blocks and 20 new automatic blocks per 10 minutes, TTL ×4 for each earlier block in
30 days up to 7 days. Decisions go to `nsm.response_actions`; the active list is pushed to the `nsm-blocklist` VPC deny rule.

**Validation (all three):** `sudo testing/response/validate.sh` runs a throwaway responder in test mode against its real webhook
and CLI with TEST-NET-3 attackers: 17 checks covering the refusal paths (bad token, never-block, private, IPv6), per-trigger TTLs,
skip on repeat notifications, observe-only, release with suppression, repeat-offender escalation, manual block, rate cap and the
reconciler's list changes. Result on 2026-09-14: **17/17 PASS**, test rows deleted afterwards. The policy has its own
unit tests (`testing/response/test_policy.py`, 11 tests).

### RSP-001 — Honeypot attacker → block

| Field | Details |
|---|---|
| Type | Grafana alert rule `nsm-rsp-honeypot` on `nsm.cowrie_events` |
| Purpose | Use intent observed on the isolated honeypot to protect the real sensor before the same source probes it |
| Logic | Within 15 minutes, a source that logged in to Cowrie **and** ran a command or transferred a file (`command.input`, `session.file_upload`, `session.file_download[.failed]`), or failed 20+ logins |
| Response | Block 24 h (×4 per earlier block in 30 days, max 7 days) |
| Evidence time (MTTR start) | First Cowrie event from the IP in the rule's 15-minute window |
| False-positive notes | Our own validation logins come from the sensor's external IP, which is on the never-block list (the rule fires, the responder refuses). Credential stuffing from shared hosting or VPN exits can land on addresses other people later use — hence TTLs instead of permanent blocks |
| Status | Validated in dry-run; tuned (TUNE-012): the first real honeypot attacker (118.145.118.102, 2026-09-14 07:31 UTC) logged in as root/ubuntu and uploaded a binary named `sshd` over SFTP without typing a command, which the original rule missed |

### RSP-002 — Severe Suricata alert → block

| Field | Details |
|---|---|
| Type | Grafana alert rule `nsm-rsp-suricata` on `nsm.suricata_alert` |
| Purpose | Stop sources that already tried exploitation or brute force against the sensor |
| Logic | Within 10 minutes, severity-1 alerts on `ens4` from outside `10.128.0.0/9` to inside it (replay interface excluded), except requests to Grafana's datasource API `/api/ds/query` (TUNE-011) |
| Response | Block 6 h (escalating as above) |
| Why severity 1 only | 24 h profile on 2026-09-14: severity 1 = 4 sources, but the two "SQL injection" sources turned out to be the dashboard user's phone (TUNE-011), leaving a React2Shell exploit attempt and a libssh brute forcer; severity 2 = ~40 sources/day, mostly reputation lists (Spamhaus DROP, Dshield, CINS). Blocking reputation hits would mainly blind the sensor to traffic that is already known bad |
| Evidence time (MTTR start) | First qualifying severity-1 alert from the IP in the rule's 10-minute window |
| False-positive notes | **Dashboard use**: Grafana sends panel SQL (e.g. `concat(`) in POST bodies to `/api/ds/query`, which matches SID 2053465 "Possible SQL Injection SELECT CONCAT in HTTP Request Body"; in dry-run this produced a would-be 6 h block of the dashboard user's own mobile IP (TUNE-011). Suricata still alerts; only the response ignores that path (unauthenticated calls get 401). Web vulnerability scanners run by researchers trigger other SQLi rules; TTL-limited |
| Status | Validated in dry-run; tuned (TUNE-011) |

### RSP-003 — SSH brute force or scanning → observe

| Field | Details |
|---|---|
| Type | Grafana alert rule `nsm-rsp-scanner` on `nsm.zeek_conn` |
| Purpose | Record what a scanner-blocking policy would do, without blinding the sensor |
| Logic | 30+ inbound connections to 22/tcp from one source in 10 minutes. DET-109's 50-port vertical threshold cannot fire here because only 22 and 80 reach the VM, so the signal is connection volume: in 24 h per-source counts per 10 minutes had median 1 and p90 46 |
| Response | Observe only (recorded with a would-be 1 h TTL, never pushed) |
| Status | Firing on real traffic: first observe decisions 2026-09-14 07:10 UTC (45.142.193.164, 202.165.25.8) |

