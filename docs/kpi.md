# SOC KPI definitions

Measurement queries are finalized with the SOC KPI dashboard in Phase 7. This file fixes the definitions and reference timestamps first.

| KPI | Definition | Reference timestamps / formula |
|---|---|---|
| MTTD (mean time to detect) | From attack start to the first alert | Replay start time recorded by the validation harness → timestamp of the first alert for that attack. `nsm.validation_runs.mttd_ms` (implemented in Phase 3) |
| MTTR (mean time to respond) | From the first evidence to the block taking effect | `nsm.response_actions.evidence_at` (first matching event) → `nsm.response_applies.applied_at` of the first change whose `added` contains the IP, after the reconciler confirmed the rule (Phase 6; Response dashboard "Time to block per IP") |
| Daily alert volume | Alerts created per day | Daily counts per rule and severity |
| FP rate | Share of alerts judged false positives | Alerts judged false positive ÷ alerts with a verdict (verdicts per the tuning log) |
| ATT&CK coverage | Share of techniques with a validated detection | Distinct techniques of detections with status "Validated" ÷ number of techniques in the target list |

## Measurements

| Date | Scope | MTTD (engine) | Queryable after (pipeline included) | Source |
|---|---|---:|---:|---|
| 2026-09-14 00:27–00:33 UTC | 3 validation cases, 3 full runs (11 PASS rows) | 102–164 ms | 2.6–5.0 s | `SELECT case_name, mttd_ms, visible_ms FROM nsm.validation_runs WHERE result = 'PASS'` |
| 2026-09-14 00:27–02:33 UTC | 3 validation cases, 10 full runs + single-case runs (36 PASS rows) | 102–166 ms (median 117 ms) | 2.6–13.3 s (median 5.0 s, p90 13.2 s); one 30.8 s outlier | same query |
| 2026-09-14 00:27 → 2026-09-15 04:47 UTC | All PASS rows before the fix below (40 rows, 17 runs, incl. the T1190 case) | median 118 ms | 2.6–13.2 s (median 5.0 s, p90 13.2 s; 48% over 6 s); one 30.8 s outlier | same query |
| 2026-09-15 05:08–05:13 UTC | After `stats.interval` 60 → 8 s: 4 cases, 6 runs (23 PASS rows; the 6th run was cut off after 3 cases) | median 123 ms | 2.8–12.6 s (**median 4.0 s, p90 7.7 s; 13% over 6 s**) | same query, `started_at >= '2026-09-15 05:08'` |

The first row understated the spread: with more runs, 17 of 36 PASS rows took longer than 6 s to become queryable.

## Where the queryable-after time goes

Breakdown measured on 2026-09-14 by timestamping each stage for the same alerts (eve.json write seen by `tail -F`,
Vector file source output seen by `vector tap`, insert start from ClickHouse `system.query_log`):

| Stage | Time | Notes |
|---|---:|---|
| Replay start → Suricata alert timestamp | ~0.1 s | `mttd_ms` |
| Alert timestamp → line in eve.json | ~15 ms | |
| eve.json → Vector file source output | 0.3–1.4 s or ~10 s | Vector re-checks a file that has been idle for more than ~10 s only about every 10 s. Reproduced with a scratch Vector on a scratch file: 1.3 s after a 2 s idle gap, 1.9–8.5 s after 12–25 s idle gaps |
| Vector source → ClickHouse insert | ~1.8 s | Alert sink `batch.timeout_secs: 2` |

On this sensor eve.json is often idle for longer than 10 s (Suricata writes stats once a minute and alerts are sparse), so in production a
first alert after a quiet period can take up to about 12 s to become queryable. For an MTTD measured in minutes this is acceptable,
but the KPI should report it honestly rather than the best case.

The single 30.8 s run (`run_id` 20260914T023124Z) had both expected SIDs created at 106 ms; the extra 20 s was between the Vector source and the
insert and coincided with a `vector tap` debugging session timing out. It was not reproduced without `tap`, so it is treated as an instrumentation artifact.

### Applied in Phase 7: keep eve.json active

`stats.interval` 60 → 8 s (docker-compose.yml), so Suricata writes a stats line more often than Vector's ~10 s idle threshold and the
file source keeps reading continuously. Cost: 7.5 `suricata_stats` rows a minute instead of 1. Result (table above): the median
dropped by a second and the p90 from 13.2 to 7.7 s; the share of cases over 6 s fell from 48% to 13%. Two outliers of ~12.5 s
remain, both the first case of a run; not yet traced to a stage.

Still open if the residual matters: ship alerts through a Suricata EVE unix-socket output to a Vector socket source (push instead of
polling; needs care so alerts are neither duplicated nor lost while Vector restarts), and lower the alert sink `batch.timeout_secs`
(at most ~1 s).

## Response measurements

| Date | Scope | Decision → rule confirmed | Evidence → rule confirmed (MTTR) | Source |
|---|---|---:|---:|---|
| 2026-09-15 | End-to-end manual block of the user's phone (enforce mode) | 7 s block, 16 s release | n/a (manual) | `nsm.response_actions`, `nsm.response_applies`, Compute API read-back, Zeek (docs/architecture.md section 13) |

| 2026-09-14 09:48 | RSP-002, 31.132.90.3 (RedTail exploit sweep), **dry-run** | 23.6 s (to the would-be list) | **29.8 s** (alert 09:48:00.5 → decision 09:48:06.7 → list 09:48:30.3) | `nsm.response_actions`, `nsm.response_applies` |
| 2026-09-14 20:47 | RSP-001, 157.10.198.167 (honeypot login + `echo xsec`), **dry-run** | 20.5 s | **117 s** (first login 20:47:28.7 → decision 20:49:05.0 → list 20:49:25.5) | same |
| 2026-09-15 04:49 | RSP-001, 157.10.198.167, **enforce** | 26.4 s | 920 s as computed — not a pipeline time, see below | same + Compute API |
| 2026-09-15 05:07 | RSP-001, 45.148.10.183, **enforce** | 12.8 s | 798 s as computed — same cause | same |
| 2026-09-15 05:33 | RSP-001, 206.123.140.188 (honeypot credential bot), **enforce**, alert started 05:33:00 | 11.1 s | **165.9 s** (session 05:30:30.2 → alert 05:33:00 → decision 05:33:05.0 → rule confirmed 05:33:16.2) — first clean enforce-mode sample | same + Compute API |

The two dry-run rows are the honest end-to-end times per path. Suricata path: alert queryable within seconds, rule evaluated every 60 s,
decision, then up to one 30 s reconciler interval. Honeypot path: Cowrie → 60 s Vector batch → bucket → pull every 60 s → rule
evaluation every 60 s → decision → reconciler.

The first two automatic blocks in enforce mode are not usable as MTTR samples. Both sources' Grafana alerts had been firing since the
dry-run period (since 2026-09-14 20:49 and 2026-09-15 04:01), and Grafana re-notifies a firing alert only every `repeat_interval` (then
4 h): one was re-sent at the next repeat, the other when Grafana restarted at 05:06. The formula then measured from the first event in
the rule's 15-minute window. `repeat_interval` is now 30 m, and the KPI panels count a block as an MTTR sample only when its Grafana alert started within 20 minutes
of the decision. The 05:33 block is the first sample that qualifies: 166 s on the honeypot path, of which 11 s from decision to
the confirmed rule.
