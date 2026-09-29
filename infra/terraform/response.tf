# Phase 6 — automated response (docs/architecture.md section 13).
#
# The responder (response/webhook/responder.py) keeps one deny rule's source ranges equal to its active block list.
# Least privilege rests on two properties:
#   1. a firewall rule's action and direction cannot be changed after creation (GCP), so a credential that can only
#      update this deny rule can never allow traffic — the worst misuse is blocking too much
#   2. the permission is conditioned to this rule and the network it lives in, so other rules (including the honeypot's
#      egress deny) stay out of reach. The condition is verified by a negative test from the VM before enforcement.
# The VM has to run as google_service_account.sensor (attach_dedicated_sa) for the binding to apply.

# Stopping the VM to switch service accounts releases an ephemeral external IP. Promoting the address already in use
# to a static one keeps it across stops, which the dashboard URL, the never-block list and the self-test tooling all
# depend on. Promotion does not touch the VM. The address itself is in nsm.lab_addresses, loaded from .env.
resource "google_compute_address" "sensor" {
  name         = "nsm-sensor-ip"
  description  = "Sensor external IP, promoted from ephemeral so it survives stop/start"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
  address      = google_compute_instance.sensor.network_interface[0].access_config[0].nat_ip

  lifecycle {
    prevent_destroy = true
    # The address is fixed once promoted; never plan a replacement if the instance attribute is read differently.
    ignore_changes = [address]
  }
}

resource "google_compute_firewall" "blocklist" {
  name        = "nsm-blocklist"
  description = "Automated response: deny all traffic from blocked sources to the sensor. Source ranges are managed by nsm-responder"
  network     = var.network
  direction   = "INGRESS"
  # Below 1000, so it wins over every allow rule (IAP, dashboard, default-allow-ssh). IAP is on the never-block list.
  priority = 900

  # A rule needs at least one range; the responder disables the rule whenever its list is empty.
  source_ranges = ["192.0.2.1/32"]
  target_tags   = [local.sensor_tag]
  disabled      = true

  deny {
    protocol = "all"
  }

  lifecycle {
    ignore_changes = [source_ranges, disabled]
  }

  depends_on = [google_project_service.required]
}

resource "google_project_iam_custom_role" "blocklist_updater" {
  role_id     = "nsmBlocklistUpdater"
  title       = "NSM blocklist updater"
  description = "Read and update the nsm-blocklist deny rule (Phase 6 responder)"
  # firewalls.update needs networks.updatePolicy on the rule's network; no create or delete permissions.
  permissions = [
    "compute.firewalls.get",
    "compute.firewalls.update",
    "compute.networks.updatePolicy",
  ]
}

resource "google_project_iam_member" "sensor_blocklist" {
  project = var.project_id
  role    = google_project_iam_custom_role.blocklist_updater.id
  member  = "serviceAccount:${google_service_account.sensor.email}"

  condition {
    title       = "nsm-blocklist only"
    description = "Limits the role to the blocklist rule and its network"
    expression  = "resource.name == \"projects/${var.project_id}/global/firewalls/${google_compute_firewall.blocklist.name}\" || resource.name == \"projects/${var.project_id}/global/networks/${var.network}\""
  }
}
