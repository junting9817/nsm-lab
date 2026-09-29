# Phase 5 — Cowrie SSH honeypot on its own VM in its own VPC (docs/architecture.md section 12).
#
# Isolation: the honeypot VPC has no peering, VPN or shared subnet with the sensor's default network.
# Log transfer is one-way through a Cloud Storage bucket: the honeypot can only create objects, the sensor VM can only read them.
#
# Stages (var.honeypot_stage):
#   bootstrap — egress open so the startup script can install Docker and pull images; 22/tcp open only to test sources
#   live      — egress denied except Google APIs (private.googleapis.com VIP); 22/tcp open to the internet
# Rebuild to update: set bootstrap, `terraform apply -replace=google_compute_instance.honeypot`, wait for the stack, set live.

locals {
  honeypot_tag  = "nsm-honeypot"
  honeypot_live = var.honeypot_stage == "live"

  honeypot_bucket = "${var.project_id}-nsm-honeypot-logs"

  # private.googleapis.com — Google APIs reachable without general internet egress (Google documentation, fixed range)
  google_apis_private_vip = "199.36.153.8/30"

  # Before going live, only the sensor VM (ours) may reach Cowrie, for testing/honeypot/validate.sh.
  honeypot_test_sources = length(var.honeypot_test_source_ranges) > 0 ? var.honeypot_test_source_ranges : [
    "${google_compute_instance.sensor.network_interface[0].access_config[0].nat_ip}/32",
  ]
}

# --- network --------------------------------------------------------------------------------------------------

resource "google_compute_network" "honeypot" {
  name                    = "nsm-honeypot"
  description             = "Isolated VPC for the Cowrie honeypot; no peering or VPN to the sensor network"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required]
}

resource "google_compute_subnetwork" "honeypot" {
  name          = "nsm-honeypot-${var.honeypot_region}"
  description   = "Honeypot subnet"
  region        = var.honeypot_region
  network       = google_compute_network.honeypot.id
  ip_cidr_range = var.honeypot_subnet_cidr

  # Lets the VM use private.googleapis.com; the live stage allows no other egress.
  private_ip_google_access = true
}

# A custom VPC starts with implied rules: deny all ingress, allow all egress.

resource "google_compute_firewall" "honeypot_cowrie" {
  name        = "nsm-honeypot-allow-cowrie-ssh"
  description = "Cowrie on 22/tcp. bootstrap: test sources only; live: the whole internet (user-approved exposure)"
  network     = google_compute_network.honeypot.id
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = local.honeypot_live ? ["0.0.0.0/0"] : local.honeypot_test_sources
  target_tags   = [local.honeypot_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "honeypot_iap_admin" {
  name        = "nsm-honeypot-allow-iap-admin"
  description = "Real sshd on 22222/tcp, only from the IAP TCP forwarding range"
  network     = google_compute_network.honeypot.id
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = [local.iap_tcp_forwarding_range]
  target_tags   = [local.honeypot_tag]

  allow {
    protocol = "tcp"
    ports    = ["22222"]
  }
}

resource "google_compute_firewall" "honeypot_egress_google_apis" {
  name               = "nsm-honeypot-allow-egress-google-apis"
  description        = "Only egress in the live stage: HTTPS to private.googleapis.com for log shipping"
  network            = google_compute_network.honeypot.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = [local.google_apis_private_vip]
  target_tags        = [local.honeypot_tag]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "honeypot_egress_deny" {
  name               = "nsm-honeypot-deny-egress"
  description        = "Deny all other egress so Cowrie cannot fetch attacker URLs or relay traffic. Disabled only in the bootstrap stage"
  network            = google_compute_network.honeypot.id
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [local.honeypot_tag]
  disabled           = !local.honeypot_live

  deny {
    protocol = "all"
  }
}

# --- one-way log transfer -------------------------------------------------------------------------------------

resource "google_storage_bucket" "honeypot_logs" {
  name                        = local.honeypot_bucket
  location                    = upper(var.honeypot_region)
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  # The honeypot cannot delete objects anyway; soft delete would only add storage cost for expired logs.
  soft_delete_policy {
    retention_duration_seconds = 0
  }

  lifecycle_rule {
    condition {
      age = var.honeypot_log_retention_days
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    component = "nsm-honeypot"
  }

  depends_on = [google_project_service.required]
}

resource "google_service_account" "honeypot" {
  account_id   = "nsm-honeypot"
  display_name = "NSM honeypot VM"
  description  = "Honeypot VM identity: may only create objects in the honeypot log bucket"

  depends_on = [google_project_service.required]
}

# objectCreator: create only — no read, list, overwrite or delete, so a compromised honeypot cannot touch shipped logs.
resource "google_storage_bucket_iam_member" "honeypot_writer" {
  bucket = google_storage_bucket.honeypot_logs.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.honeypot.email}"
}

# The sensor VM pulls with its devstorage.read_only scope; grant read to both the current and the dedicated account.
resource "google_storage_bucket_iam_member" "sensor_reader" {
  for_each = {
    default   = data.google_compute_default_service_account.default.email
    dedicated = google_service_account.sensor.email
  }

  bucket = google_storage_bucket.honeypot_logs.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${each.value}"
}

# --- honeypot VM ----------------------------------------------------------------------------------------------

resource "google_compute_instance" "honeypot" {
  name         = "nsm-honeypot-1"
  description  = "Cowrie SSH honeypot (disposable: rebuilt instead of patched)"
  zone         = var.honeypot_zone
  machine_type = var.honeypot_machine_type
  tags         = [local.honeypot_tag]

  labels = {
    component = "nsm-honeypot"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-13"
      size  = 10
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.honeypot.id

    # External IP: the honeypot must be reachable from the internet.
    access_config {}
  }

  service_account {
    email  = google_service_account.honeypot.email
    scopes = ["https://www.googleapis.com/auth/devstorage.read_write"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    startup-script  = file("${path.module}/../../honeypot/startup.sh")
    nsm-compose     = file("${path.module}/../../honeypot/docker-compose.yml")
    nsm-cowrie-cfg  = file("${path.module}/../../honeypot/cowrie/cowrie.cfg")
    nsm-vector-yaml = templatefile("${path.module}/../../honeypot/vector/vector.yaml.tftpl", { bucket = google_storage_bucket.honeypot_logs.name })
    nsm-bucket      = google_storage_bucket.honeypot_logs.name

    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
  }

  # Disposable: no deletion protection, and Terraform may stop it for changes that need a stop.
  deletion_protection       = false
  allow_stopping_for_update = true

  # The startup script uploads its log and Vector ships events as soon as the VM boots.
  depends_on = [
    google_storage_bucket_iam_member.honeypot_writer,
    google_compute_firewall.honeypot_egress_google_apis,
  ]
}
