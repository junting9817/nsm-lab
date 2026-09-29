# Tuning log

Every false positive gets a record of what was observed, why it happened, what was changed and what the change achieved.
Detection exceptions live in `detections/allowlist.tsv` (loaded into `nsm.allowlist` by `detections/sync-allowlist.sh`);
each row references an entry below and carries a review date. Suricata suppressions live in `sensors/suricata/threshold.config`.

| Date | ID | Detection | Observed false positive | Cause | Change | Result | Commit |
|---|---|---|---|---|---|---|---|
| 2026-09-14 | TUNE-001 | DET-001 (ET 2024897, 2060251, 2034567) | 62 alerts per 30 min for HTTP requests from the sensor to the GCE metadata server (169.254.169.254) | The guest agent's `Go-http-client` requests `/computeMetadata/v1/instance/credentials/mds-client-certificate` every minute; a host script's `curl` requests `/computeMetadata/v1/instance/?recursive=true` every 5 min. Link-local infrastructure traffic that never leaves the VM | Rules kept; the 3 SIDs suppressed only for destination 169.254.169.254 (`track by_dst`) in `threshold.config` | 30 metadata requests and 0 alerts in the following 9 min; other alerts kept arriving | 0f1d897 |
| 2026-09-14 | TUNE-002 | DET-101 | `grafana.com` reported as a beacon (74 connections, every 600 s, MAD 0) | Grafana server update and plugin checks | Allowlist `sni grafana.com` | DET-101 production hits 3 → 0 (24 h ending 2026-09-14 01:15 UTC) | 2bffee4 |
| 2026-09-14 | TUNE-003 | DET-101 | `deb.debian.org` reported as a beacon (77 connections, every 600 s at hh:x4:19) | Google OS Config agent package inventory. Caught at 02:04:19: apt's HTTPS method owned the socket, followed by `apt-get --just-print -qq full-upgrade`; no cron job or timer runs it, and those strings are in `google_osconfig_agent` | Allowlist `sni deb.debian.org` | included in the 3 → 0 above | 2bffee4 |
| 2026-09-14 | TUNE-004 | DET-101 | `downloads.claude.ai` reported as a beacon (26 connections, every 1800 s) | Claude Code update checks | Allowlist `sni downloads.claude.ai` | included in the 3 → 0 above | 2bffee4 |
| 2026-09-14 | TUNE-005 | DET-102 | Sessions to `api.anthropic.com` lasting up to 120 min | Claude Code keeps HTTP/2 connections to the API open | Allowlist `sni api.anthropic.com` | DET-102 production hits 13 → 2 | 2bffee4 |
| 2026-09-14 | TUNE-006 | DET-102 | Sessions to `asia-northeast3-c-osconfig.googleapis.com` lasting up to 111 min | GCE OS Config agent long polling | Allowlist `sni asia-northeast3-c-osconfig.googleapis.com` | included in 13 → 2 | 2bffee4 |
| 2026-09-14 | TUNE-007 | DET-102 | Sessions to `asia-northeast3-c-agentcommunication.googleapis.com` lasting up to 112 min | GCE guest agent long polling | Allowlist `sni asia-northeast3-c-agentcommunication.googleapis.com` | included in 13 → 2 | 2bffee4 |
| 2026-09-14 | TUNE-008 | DET-102 | Sessions to `monitoring.googleapis.com` lasting exactly 60 min | Ops Agent metric export streams, rotated hourly | Allowlist `sni monitoring.googleapis.com` | included in 13 → 2 | 2bffee4 |
| 2026-09-14 | TUNE-009 | DET-107 | Up to 84 MiB sent to `monitoring.googleapis.com` with PCR 0.98 | Ops Agent metric uploads are upload-only by design | Allowlist `sni monitoring.googleapis.com` for DET-107 | DET-107 production hits 5 → 1 | 2bffee4 |
| 2026-09-14 | TUNE-010 | DET-107 | 88 MiB sent to `api.anthropic.com` with PCR 0.94 | Claude Code sends large prompts and receives small streamed responses | Allowlist `sni api.anthropic.com` for DET-107 | included in 5 → 1 | 2bffee4 |
| 2026-09-14 | TUNE-011 | RSP-002 (response trigger), ET 2053465 | Dry-run decision to block <user phone IP> for 6 h after "ET WEB_SERVER Possible SQL Injection SELECT CONCAT in HTTP Request Body" against port 80 | The source was the dashboard user's phone (Samsung Internet on Android, referer `/d/nsm-honeypot/…`): Grafana POSTs panel SQL containing `concat(` to `/api/ds/query`. All 9 SID 2053465 alerts on record are this pattern from the same mobile carrier range (<user phone IP>/.78), mostly HTTP 200 | RSP-002 query and the responder's evidence lookup exclude `http_url` starting with `/api/ds/query`; Suricata alerting unchanged (unauthenticated calls to that path get 401); dry-run block released with this ID as the reason. The same SID was removed from the IPS branch's drop list | Rule re-evaluated with the change: the phone no longer selected, the libssh brute forcer still is. Enforcement had not been enabled, so no block reached the firewall | beea905 |
| 2026-09-14 | TUNE-012 | RSP-001 (response trigger) | Missed detection, not a false positive: 118.145.118.102 (CN, Beijing Volcano Engine) logged in to Cowrie as root/ubuntu at 07:31 UTC and uploaded a binary named `sshd` over SFTP (sha256 97a1e6f8…), without typing a command | The rule required `cowrie.command.input` after a login; file transfers were not counted | `cowrie.session.file_upload`, `file_download` and `file_download.failed` after a login now qualify | Re-running the rule SQL over the attack window selects 118.145.118.102 | beea905 |
| 2026-09-15 | TUNE-013 | DET-102 | 7 long-session findings to Google front ends (216.239.32–38.174, 142.251.118.95, 172.217.21x.95), 60–61 min each | Ops Agent log export streams to `logging.googleapis.com`, rotated hourly — same pattern as TUNE-008 for monitoring; socket owner `otelopscol` (ss -tnp) | Allowlist `sni logging.googleapis.com` | First scheduled run: DET-102 10 → 4 (the remainder are TUNE-less mid-stream sessions, below) | d8f8b62 |
| 2026-09-15 | TUNE-014 | DET-103 | Rare JA4 to `rules.emergingthreats.net` | `suricata-update`'s Python client, once a day from nsm-rules-update.timer | Allowlist `sni rules.emergingthreats.net` | DET-103 1 → 0 | d8f8b62 |
| 2026-09-15 | TUNE-015 | DET-101 | `fe80::4001:aff:feb2:2 → ff02::2` ICMPv6 type 134 reported as a beacon (29 connections, median 3473 s) | The sensor's own IPv6 router advertisement/solicitation traffic to link-local multicast | Allowlist `dst_cidr ff00::/8` (multicast is never a C2 destination) | DET-101 1 → 0 | d8f8b62 |
| 2026-09-15 | TUNE-016 | DET-101 | `10.178.0.2 → 34.149.66.165:443` every 1800 s with MAD 0.7 s, 149 connections and 13.4 MB uploaded since 2026-09-13 | SNI `http-intake.logs.us5.datadoghq.com`; while a connection was open, `ss -tnp` showed the socket owned by process `claude` (pid 4882): Claude Code, the admin session on this VM, sending its telemetry logs | Allowlist `sni http-intake.logs.us5.datadoghq.com` for DET-101. Alternative left to the user: disable Claude Code's non-essential traffic in its settings | Backfill finding verdicted false positive; DET-101 stays 0 in the next run | d8f8b62 |
| 2026-09-15 | TUNE-017 | DET-103 | Rare JA4 `t13d181100_5d04281c6031_d5fe2c511efa` to the same Datadog intake | Same Claude Code telemetry client as TUNE-016 | Allowlist `sni http-intake.logs.us5.datadoghq.com` for DET-103 | DET-103 stays 0 | d8f8b62 |
| 2026-09-15 | TUNE-018 | DET-001 (ET 2013031) | Top signature on the new SOC KPI dashboard: 1,693 "ET INFO Python-urllib/ Suspicious User Agent" alerts, ~55/h rising to ~250/h after enforcement started | All from 10.178.0.2 to 169.254.169.254:80 `/computeMetadata/v1/…`: nsm-honeypot-pull (every minute), nsm-responder's reconciler (every 30 s in enforce mode) and gcloud fetching tokens with urllib | `suppress gen_id 1, sig_id 2013031, track by_dst, ip 169.254.169.254` in threshold.config (same scope as TUNE-001); Suricata restarted | 0 such alerts in the 6 minutes after the restart despite 6 puller runs and continuous reconciling; verdict false_positive recorded | d16026a |

## Known residual after TUNE-002..010

The remaining hits (DET-102: 2, DET-107: 1) come from 6 connections that started 1–30 s after a Zeek restart
(2026-09-13 13:00:46 and 2026-09-14 00:54:58 UTC). Zeek picked them up mid-stream — history starts without a SYN (`Dad…`, `Aa…`) —
so there is no TLS handshake and no SNI to match. They age out of the 24 h window on their own. Matching them by IP was rejected
because the destinations are shared Google and Anthropic address space.

## Why exceptions match the connection's own SNI

Allowlisting by destination IP would hide any other traffic to the same CDN address. The detections join each connection to its own
TLS server name (`zeek_conn.uid = zeek_ssl.uid`), so an exception for `grafana.com` does not cover a different site served from the
same IP. IP and CIDR rules exist for non-TLS cases. The trade-off: an attacker who can send traffic to an allowlisted name
(for example through the Anthropic API) is not seen by that one detection; other detections still apply.

## Verdicts without an allowlist entry (2026-09-15)

Recorded with `detections/verdict.sh` so the FP rate counts them, but deliberately not suppressed:

- **Mid-stream sessions** (DET-102 ×5, DET-107 ×1): Google agent and `api.anthropic.com` sessions that were already open when Zeek
  (re)started, so Zeek never saw the TLS handshake and there is no SNI to match. They age out of the 24 h window; allowlisting by IP
  would hide any other service on those shared front-end addresses.
- **JA4 baseline warm-up** (DET-103 ×7): one-off TLS clients to www.debian.org, www.google.com, pypi.org, packages.cloud.google.com
  and api.anthropic.com between 01:00 and 08:00 UTC on 2026-09-14, the first hours after JA4 logging started. The clients could not be
  attributed to a process after the fact; the baseline now contains them.

