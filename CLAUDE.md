# GCP-based network detection (NSM) dashboard

## Role

You are a senior security engineer designing and building a network security monitoring (NSM) stack.
I am building a portfolio project aimed at landing a SOC analyst job.
The result must be both "a working lab" and "documentation I can explain in an interview".

## Environment (fixed conditions — measured 2026-09-13)

| Item | Value |
|---|---|
| VM | `myfirstserver` (Compute Engine, managed by Terraform via `import`) |
| Machine type | `e2-standard-2` — 2 vCPU (1 core / 2 threads), RAM 7,945 MiB, no swap |
| OS | **Debian 13 (trixie)** — the original spec was Ubuntu 22.04, but the decision was to keep the existing VM (D1) |
| Project / zone | `<gcp-project-id>` / `asia-northeast3-c` |
| Network | `default` VPC, `ens4` 10.178.0.2, has an external IP (internet-exposed sensor) |
| Boot disk | 10 GB (OS only) |
| Data disk | `nsm-data` 100 GB pd-balanced → `/data` (Docker, ClickHouse, logs, PCAP) |

- SSH: keep the IAP rule (`35.235.240.0/20` → tcp:22), and also keep `default-allow-ssh` (0.0.0.0/0) so the console SSH button works (D5). Key authentication only.
- **Exception (D3)**: the Grafana web UI is published on `0.0.0.0:80` by user decision. Compensating controls are in `docs/architecture.md`.
- Terraform runs on this VM. The user account login (ADC) is kept **only during plan/apply** and revoked immediately afterwards with `gcloud auth application-default revoke` (D2). Apply only after showing the plan to the user and getting approval.
- This VM is **my own lab environment**; all test traffic is generated only inside this VM or between VMs I own.

Decision records (D1–D7) and the resource budget are in `docs/architecture.md`.

## Goal

Build a pipeline that goes all the way through **detection → visualization → automatic blocking**
for real traffic hitting the internet-exposed host and malicious PCAPs I replay.

## Agreed architecture (proposed changes must come with rationale)

```
Suricata (EVE JSON, signature alerts) ─┐
Zeek     (conn/dns/ssl/http/x509)      ─┼─→ Vector ─→ ClickHouse ─→ Grafana
Cowrie   (SSH honeypot, separate VM)   ─┘                    │
                                                             └─→ alert webhook → automatic block script
```

- Suricata = known-threat signatures, Zeek = metadata for behavior analysis. Do not mix the roles.
- ClickHouse is used to handle hundreds of millions of Zeek conn rows on a small VM. Document the rationale for this choice.
- Every component runs as a Docker container. Suricata and Zeek use the host network + AF_PACKET (D4).

## Repository layout

```
.
├── CLAUDE.md
├── README.md                 # architecture diagram + screenshots + detection case studies
├── docker-compose.yml        # whole stack (explicit memory limit per container)
├── .env.example              # secret key list (.env is created by setup-stack.sh)
├── docs/
│   ├── architecture.md       # components, resource budget, network exposure, decision records
│   ├── detection-catalog.md  # per rule: purpose/logic/ATT&CK ID/validation/FP notes
│   ├── tuning-log.md         # false positive found → cause → action history
│   └── kpi.md                # how MTTD/MTTR are measured
├── infra/
│   ├── terraform/            # VM (import), firewall, disk, service account; honeypot.tf (Phase 5)
│   └── scripts/setup-*.sh    # must be safely re-runnable (idempotent)
├── honeypot/                 # Honeypot VM stack delivered via instance metadata: startup.sh, compose, cowrie.cfg, vector.yaml.tftpl
├── ingest/
│   ├── vector/vector.yaml
│   └── clickhouse/
│       ├── config.d/         # server settings (low-memory tuning)
│       ├── users.d/          # accounts and privileges
│       └── schema/           # table DDL, TTL, partitions
├── sensors/
│   ├── suricata/nsm.yaml     # Suricata overrides (list nodes only; map values via compose --set)
│   ├── suricata/update/      # suricata-update filters (disable/enable/modify.conf)
│   └── zeek/                 # Zeek site policy, scripts/ja3-ja4.zeek, log schema extraction tool
├── detections/
│   ├── run.sh                # Detection runner: window/thresholds as ClickHouse query params (--list for defaults)
│   ├── allowlist.tsv         # Reviewed exceptions (TUNE ids), loaded by sync-allowlist.sh into nsm.allowlist
│   ├── suricata/local.rules  # custom rules written for this lab only
│   ├── sigma/                # Sigma sources
│   ├── sql/                  # DET-101..109 behavior detections (common leading output columns)
│   └── attack-map.json       # ATT&CK Navigator layer
├── response/
│   ├── webhook/              # responder.py (webhook, reconciler, CLI) + policy.py (never-block, caps, TTL)
│   ├── firewall/             # nsm-response.sh: analyst block / release / list
│   └── never-block.txt       # addresses the responder must never block
├── dashboards/
│   ├── provisioning/         # Grafana datasource and dashboard provisioning
│   └── json/                 # Grafana dashboard JSON
└── testing/
    ├── pcap/replay.sh        # tcpreplay wrapper for the dummy interface (nsm-replay0) only
    ├── pcap/cases.json       # per case: PCAP, ATT&CK, expected SIDs
    ├── pcap/generate_samples.py  # synthetic PCAP generator (samples/*.pcap are committed)
    ├── pcap/uniquify.py      # new client ports per replay (avoids closed-session collisions)
    ├── beacon-sim/           # Jitter-controlled beacon (own external IP only) + live DET-101 check
    ├── detections/           # Fixture harness: synthetic PCAP → offline Zeek → nsm_test → detection SQL checks
    ├── fingerprints/         # Zeek JA3/JA4 vs Suricata built-in cross-check
    ├── honeypot/             # ssh_attempts.sh + validate.sh: attack our own honeypot, check events and egress policy
    ├── response/             # policy unit tests, test-mode responder harness, firewall permission check
    └── validate.sh           # replay → compare alerts loaded in ClickHouse, results in nsm.validation_runs
```

## Phases — always stop at the end of each phase and get my confirmation

### Phase 1 — Foundation
- Define VM/disk/firewall/service account with Terraform
- VM hardening: SSH keys only, password login blocked, ufw default deny, unattended-upgrades
- Bring up ClickHouse + Grafana + Vector with Docker Compose
- Grafana published on `0.0.0.0:80` (D3); ClickHouse/Vector not exposed externally
- **Done when**: Grafana is reachable in a browser → ClickHouse datasource connection confirmed

### Phase 2 — Collection
- Suricata bound to the main interface with AF_PACKET, EVE JSON output
- Install Zeek, JSON log output, enable conn/dns/ssl/http/x509/notice
- Vector parses both logs and loads them into ClickHouse tables
- Tables use date partitions + TTL (Zeek 30 days, Suricata 90 days)
- **Done when**: live traffic shows up in Grafana panels

### Phase 3 — Signature detection + validation harness
- Adopt the ET Open ruleset, automate suricata-update
- `testing/pcap/replay.sh`: replay a given PCAP onto a dummy interface
- `testing/validate.sh`: compare the expected signature list per PCAP with actual alerts and print PASS/FAIL
- **Done when**: the validation script passes with 3 sample PCAPs

### Phase 4 — Behavior-based detections (the key differentiator)
Implemented directly in ClickHouse SQL:
1. **Beaconing**: MAD and coefficient of variation of connection intervals per src-dst pair → regularity score
2. **Long connections**: outbound sessions over a time threshold
3. **JA3/JA4 rarity**: fingerprints seen N times or fewer overall
4. **Self-signed certificates / SNI-CN mismatch**
5. **DNS tunneling**: query length + Shannon entropy of subdomains
6. **Suspected DGA**: spike in NXDOMAIN ratio
7. **Data exfiltration**: outbound/inbound byte ratio inversion, large transfers outside business hours
8. **Standard protocol on a non-standard port**: Zeek `service` vs `id.resp_p` mismatch
9. **Port/host scanning**: distinct destination port count, SYN:SYN-ACK ratio

For each item, deliver the set: query file + ATT&CK ID + `detection-catalog.md` entry + validation method.
For beaconing, build a jitter-adjustable Python beacon in `testing/beacon-sim/` and validate against it directly.

### Phase 5 — Honeypot
- Deploy Cowrie on a **separate VM in a separate VPC** (never on the same network as the dashboard VM)
- Send logs one-way to the dashboard VM
- Panels for attacker ASN/country/attempted usernames and passwords

### Phase 6 — Response
- Alert webhook receiver → severity and allowlist decision → block decision
- Block source IPs with `gcloud compute firewall-rules`, release automatically when the TTL expires
- Block history table + Grafana panel + manual release path
- Write the Suricata IPS mode (NFQUEUE) setup **only on a separate branch**; the default branch stays IDS

### Phase 7 — Wrap-up
- Six Grafana dashboards: Traffic Overview / Alerts / C2 Hunt / DNS / Honeypot / SOC KPI
- KPIs: MTTD, daily alert volume, FP rate, ATT&CK coverage %
- Script that generates the ATT&CK Navigator layer automatically
- README with the architecture diagram, 3 detection case studies (attack → detection → block timeline), screenshots

## Coding and operations rules

- Every install script must be **idempotent**. Re-running must not break anything.
- Never hardcode secrets; use the `.env` + `.env.example` pattern, `.gitignore` required.
- Set an explicit memory limit per Docker container. Design the total to stay under 70% of VM RAM (5,561 MiB); on 2 vCPU, limit Zeek to 1 worker. The allocation table is in `docs/architecture.md`.
- Prevent disk-full: log rotation, 24-hour PCAP retention and ClickHouse TTLs set up front in Phase 2.
- Small commits, with messages that say "what and why".
- When adding a detection rule, always update `detection-catalog.md` in the same commit.
- Keep `prevent_destroy` and `allow_stopping_for_update = false` on the Terraform instance resource. Claude Code runs on this VM, so any change that stops or replaces the VM is scheduled separately with the user.
- Language: from 2026-09-14 the user asked for English — use English for replies and repo content.

## When to get my confirmation

- When opening a new firewall rule or widening one
- When creating billable resources, e.g. Terraform `apply`
- When proposing to replace a component of the agreed architecture
- At the completion of each phase

## Prohibited

- Do not write code that generates scans or traffic toward targets I do not own.
- Do not bind Grafana/ClickHouse/Suricata management ports to `0.0.0.0`.
  - **Exception**: Grafana web UI 80/tcp (user decision, 2026-09-13, `docs/architecture.md` D3)
- Do not report something as "done" without verifying that it works. Present the verification commands together with their output.

## Progress

- Phase 1: **complete** (user confirmed 2026-09-13)
- Default firewall cleanup (2026-09-13): deleted `default-allow-rdp` and `default-allow-https`. Kept `default-allow-ssh` (D5), `default-allow-http` (D3), `default-allow-icmp`, `default-allow-internal`
- Phase 2: **complete** (user confirmed 2026-09-14)
- Phase 3: **complete** (user confirmed 2026-09-14). TUNE-001 applied (metadata server alert suppression)
- Phase 4: **complete** (user moved on to Phase 5, 2026-09-14). Shared allowlist TUNE-002..010
- Phase 1–3 docs and code comments translated to English (2026-09-14). Existing commit messages stay as they are
- Open finding (2026-09-14): alert visible latency 2.6–13.3 s because of Vector idle-file polling (`docs/kpi.md`); options deferred to Phase 7
- Phase 5 decisions (D6, 2026-09-14): honeypot in us-central1 e2-micro (no user preference), egress Google APIs only, SSH 22 only
- Phase 5 Stage A (bootstrap) applied and validated 2026-09-14: honeypot `nsm-honeypot-1` <honeypot-external-ip>, bucket `<gcp-project-id>-nsm-honeypot-logs`, pull timer enabled, ADC revoked
- Phase 5 Stage B (live) applied and validated 2026-09-14 06:34 UTC: Cowrie open to the internet, egress denied except Google APIs (validated: egress blocked). `honeypot_stage = "live"` pinned in terraform.tfvars; ADC revoked
- Phase 5: **complete** (user confirmed 2026-09-14, "Great. Keep going")
- Phase 6 decisions (D7): dedicated SA + VM stop for the firewall credential, triggers honeypot + Suricata severity 1 enforced, SSH scanning observe-only, dry-run first
- Phase 6 step 1 applied 2026-09-14 07:38 UTC (user approved): static IP nsm-sensor-ip <sensor-external-ip> (in use by myfirstserver), nsm-blocklist (disabled), role nsmBlocklistUpdater, conditional binding for nsm-sensor; follow-up plan no changes; ADC revoked
- Phase 6 step 2 done 2026-09-14 07:50 UTC: user switched the VM to nsm-sensor (full API scope) in the Cloud Console; IP unchanged; attach_dedicated_sa = true in terraform.tfvars (confirm a no-change plan at the next ADC session)
- Phase 6 step 3 PASS: check-firewall-permissions.sh as nsm-sensor → nsm-blocklist 200/200, dashboard and honeypot egress rules 403. nsm-stack-boot.service added after Suricata failed to restart post-stop. IPS NFQUEUE variant on branch ips-nfqueue (13532ed + b787f60, not deployed)
- Phase 6 tuning before enforcement: TUNE-011 (RSP-002 would have blocked the user's phone: Grafana /api/ds/query SQL matched SID 2053465), TUNE-012 (RSP-001 now counts file uploads/downloads)
- Phase 6 step 4 done 2026-09-15: RESPONDER_MODE=enforce since 04:14 UTC (user approved "Keep doing"); end-to-end test with the user's phone <user phone IP>: block confirmed in 7 s, reload hung, Zeek 0 connections after apply, release confirmed in 16 s, reload worked
- Phase 6: **complete** (user confirmed 2026-09-15, "OK. Let's do Phase 7"). First clean automatic MTTR observed 2026-09-15 05:33 (166 s). Still to do: no-change terraform plan with attach_dedicated_sa = true at the next ADC session
- Phase 7 built: detection scheduler + verdicts + ATT&CK layer (13/16 validated), 5 dashboards as code (+Honeypot, Response), T1190 harness case, TUNE-013..018, stats.interval 8 s (queryable p50 4.0 s / p90 7.7 s), Grafana 768 MiB + GOMEMLIMIT + unused plugins disabled (after a scanner-induced OOM), first clean enforce MTTR 166 s (206.123.140.188), README with 3 case studies and screenshots (docs/screenshots/capture.sh)
- Current: **Phase 7** built and validated, waiting for user confirmation. User's phone IPs redacted from tracked docs; they remain in earlier git history (user decision before publishing)
