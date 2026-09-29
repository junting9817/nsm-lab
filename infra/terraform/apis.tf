# Required APIs. Fine if already enabled; never disabled on destroy (other resources depend on them).
resource "google_project_service" "required" {
  for_each = toset([
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iap.googleapis.com",     # IAP TCP forwarding (SSH)
    "storage.googleapis.com", # honeypot log bucket (Phase 5)
  ])

  service            = each.value
  disable_on_destroy = false
}
