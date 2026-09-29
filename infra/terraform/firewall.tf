locals {
  # IAP TCP forwarding source range, fixed in Google's documentation
  iap_tcp_forwarding_range = "35.235.240.0/20"
}

resource "google_compute_firewall" "iap_ssh" {
  name        = "nsm-allow-iap-ssh"
  description = "Allow SSH only from the IAP TCP forwarding range"
  network     = var.network
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = [local.iap_tcp_forwarding_range]
  target_tags   = [local.sensor_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  depends_on = [google_project_service.required]
}

resource "google_compute_firewall" "dashboard_http" {
  name        = "nsm-allow-dashboard-http"
  description = "Grafana dashboard 80/tcp (docs/architecture.md D3). Sources come from dashboard_source_ranges"
  network     = var.network
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = var.dashboard_source_ranges
  target_tags   = [local.sensor_tag]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  depends_on = [google_project_service.required]
}
