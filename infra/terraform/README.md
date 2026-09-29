# Terraform — sensor VM base resources

Terraform runs on this VM. The user's account login is kept only while planning and applying, and revoked right after
(docs/architecture.md D2).

## What it manages

| Resource | Action | Cost |
|---|---|---|
| `google_compute_instance.sensor` | Existing VM **imported**; tag added, deletion protection on (no stop) | unchanged |
| `google_compute_disk.data` + `google_compute_attached_disk.data` | 100 GB pd-balanced disk created and attached (no stop) | **new** |
| `google_compute_firewall.iap_ssh` | IAP range → tcp:22 | none |
| `google_compute_firewall.dashboard_http` | `dashboard_source_ranges` → tcp:80 | none |
| `google_service_account.sensor` + 2 IAM bindings | Dedicated service account (attaching it to the VM is a separate step) | none |
| `google_project_service.required` | compute / iam / iap / storage APIs enabled | none |

Phase 5 honeypot (`honeypot.tf`, docs/architecture.md section 12):

| Resource | Action | Cost |
|---|---|---|
| `google_compute_network.honeypot` + `google_compute_subnetwork.honeypot` | Separate VPC `nsm-honeypot`, subnet 10.250.0.0/24 in us-central1 | none |
| `google_compute_firewall.honeypot_*` (4) | Cowrie 22/tcp, IAP → 22222, egress to Google APIs, deny other egress (live only) | none |
| `google_storage_bucket.honeypot_logs` + 3 IAM bindings | One-way log bucket: honeypot objectCreator, sensor objectViewer; 30-day lifecycle | **new** (small) |
| `google_service_account.honeypot` | Honeypot identity with no project roles | none |
| `google_compute_instance.honeypot` | e2-micro Debian 13, 10 GB pd-standard, external IP, Shielded VM | **new** |

Safeguards:

- `prevent_destroy` on the VM and the data disk — a planned replacement or deletion stops the plan with an error.
- `allow_stopping_for_update = false` on the VM — any change that needs a stop fails at apply time.

## How to run

```bash
# 0) Install Terraform (idempotent, verifies the repository key fingerprint)
sudo infra/scripts/setup-terraform.sh

# 1) Log in — needs a pasted code, so the user runs it in a separate SSH window
gcloud auth application-default login --no-launch-browser

# 2) Review the plan
cd infra/terraform
[ -f terraform.tfvars ] || cp terraform.tfvars.example terraform.tfvars   # set project_id
terraform init
terraform plan -out=phase1.tfplan
```

**Expected plan summary** (first run in Phase 1):

```
Plan: 1 to import, 10 to add, 1 to change, 0 to destroy.
```

- The single change must be the VM tag (`nsm-sensor`), `deletion_protection` and `allow_stopping_for_update`.
- If `destroy`, `must be replaced` or `forces replacement` appears anywhere, do not apply.

```bash
# 3) Apply after approval — a saved plan file applies without a yes prompt
terraform apply phase1.tfplan
terraform output

# 4) Revoke the login immediately and confirm
gcloud auth application-default revoke --quiet
ls ~/.config/gcloud/application_default_credentials.json   # must say "No such file"
```

## Honeypot stages (Phase 5)

Every step below is a separate plan → user approval → apply → revoke session.

```bash
# Stage A — bootstrap: egress open, Cowrie reachable only from the sensor's external IP
terraform plan -out=honeypot-bootstrap.tfplan        # honeypot_stage defaults to "bootstrap"
terraform apply honeypot-bootstrap.tfplan
sudo infra/scripts/setup-honeypot-ingest.sh          # bucket now readable → pull timer enabled
sudo testing/honeypot/validate.sh                    # expects: events arrive, egress OPEN (positive control)

# Stage B — live: egress denied except Google APIs, Cowrie open to the internet (user-approved exposure)
terraform plan -var honeypot_stage=live -out=honeypot-live.tfplan
terraform apply honeypot-live.tfplan
sudo testing/honeypot/validate.sh                    # expects: events arrive, egress BLOCKED
```

Keep `honeypot_stage = "live"` in `terraform.tfvars` after Stage B so later plans do not quietly reopen egress.
To update Cowrie, Vector or the OS: set bootstrap, `terraform apply -replace=google_compute_instance.honeypot`, validate, set live.
Boot diagnostics without a user login: `gcloud storage ls gs://<bucket>/startup/` from the sensor VM.

## Automated response (Phase 6)

`response.tf`: static sensor IP (promotes the ephemeral address in use), the `nsm-blocklist` deny rule (created disabled; the
responder owns its source ranges and `disabled`), a custom role `nsmBlocklistUpdater` and a conditional binding for `nsm-sensor`.

```bash
# 1) On the VM, in an ADC session: plan → approval → apply. Expected: 4 to add, 0 to change, 0 to destroy.
terraform plan -out=response.tfplan && terraform apply response.tfplan

# 2) In Cloud Shell (this VM stops, so neither this session nor Terraform can run here): ~2 minutes of downtime.
gcloud compute instances stop myfirstserver --zone=asia-northeast3-c
gcloud compute instances set-service-account myfirstserver --zone=asia-northeast3-c \
  --service-account=nsm-sensor@<gcp-project-id>.iam.gserviceaccount.com --scopes=cloud-platform
gcloud compute instances start myfirstserver --zone=asia-northeast3-c

# 2b) Without Cloud Shell (done this way on 2026-09-14): Cloud Console → Compute Engine → VM instances → myfirstserver →
#     Stop → Edit → Service account: nsm-sensor, Access scopes: allow full access to all Cloud APIs → Save → Start.

# 3) Back on the VM: containers restart on their own (nsm-stack-boot.service fills any gap). Record the switch, then verify with no user login.
#    terraform.tfvars: attach_dedicated_sa = true   (the next plan must show no changes)
testing/response/check-firewall-permissions.sh
```

## Problems hit during the import (2026-09-13)

The first plan wanted to replace the existing VM (`1 to destroy`); `prevent_destroy` stopped it with an error.

| Symptom | Cause | Fix |
|---|---|---|
| `key_revocation_action_type = "NONE" -> null # forces replacement` | The console-created VM has a value that the code did not set, so the provider compared against null (a ForceNew attribute) | Set `"NONE"` explicitly |
| `service_account.email -> (known after apply)` | `depends_on` on the default service account data source deferred the lookup to apply time → risk of a planned service account change (needs a stop) | Removed `depends_on` from the data source |

Lesson: even when a plan fails, the `-out` file is still written to disk. Delete a failed plan file right away.

## Follow-ups

- **Default network rule cleanup** — done on 2026-09-14 with `infra/scripts/cleanup-default-firewall.sh`: `default-allow-rdp` and
  `default-allow-https` deleted; `default-allow-ssh` kept for the console SSH button (docs/architecture.md D5).
- **Switch to the dedicated service account** — part of Phase 6 (see above). `attach_dedicated_sa = true` in `terraform.tfvars`
  only records it afterwards; the stop/start itself runs from Cloud Shell.
- **English descriptions** — resource descriptions were translated on 2026-09-14; the next plan shows them as in-place updates
  of `google_compute_firewall.*` and `google_service_account.sensor`.
