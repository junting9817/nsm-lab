# With depends_on this lookup would be deferred to apply time, the VM's service_account.email would become
# "(known after apply)" and the provider would plan a service account change (which requires stopping the VM).
# The compute API is already enabled because the VM exists.
data "google_compute_default_service_account" "default" {}

# Dedicated service account for the sensor VM.
# The default Compute Engine service account often holds project Editor, far too much for an internet-facing VM.
# Phase 1 grants only what the Ops Agent needs to write; Phase 6 adds a custom role for firewall blocking.
resource "google_service_account" "sensor" {
  account_id   = "nsm-sensor"
  display_name = "NSM sensor VM"
  description  = "Least-privilege account for the NSM sensor VM"

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "sensor" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.sensor.email}"
}
