# Sensor VM — the existing VM created in the console, imported and managed here (docs/architecture.md D1).
import {
  to = google_compute_instance.sensor
  id = "projects/${var.project_id}/zones/${var.zone}/instances/${var.instance_name}"
}

locals {
  sensor_tag = "nsm-sensor"

  # Default access scopes from console creation, kept while the VM uses the default service account.
  default_sa_scopes = [
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/logging.write",
    "https://www.googleapis.com/auth/monitoring.write",
    "https://www.googleapis.com/auth/service.management.readonly",
    "https://www.googleapis.com/auth/servicecontrol",
    "https://www.googleapis.com/auth/trace.append",
  ]
}

resource "google_compute_instance" "sensor" {
  name         = var.instance_name
  zone         = var.zone
  machine_type = var.machine_type

  # http-server / https-server are tags added in the console; https-server has no rule since the default rule cleanup.
  tags = ["http-server", "https-server", local.sensor_tag]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-13"
    }
  }

  network_interface {
    network = var.network

    # Keep the external IP: this sensor observes real traffic from the internet.
    access_config {}
  }

  service_account {
    email  = var.attach_dedicated_sa ? google_service_account.sensor.email : data.google_compute_default_service_account.default.email
    scopes = var.attach_dedicated_sa ? ["cloud-platform"] : local.default_sa_scopes
  }

  scheduling {
    on_host_maintenance = "MIGRATE"
    automatic_restart   = true
    preemptible         = false
  }

  # Actual value on the console-created VM. If omitted the provider compares against null and plans a replacement (ForceNew).
  key_revocation_action_type = "NONE"

  deletion_protection = true

  # Work sessions run on this VM, so by default any change that needs a stop fails at apply time.
  allow_stopping_for_update = var.attach_dedicated_sa

  lifecycle {
    prevent_destroy = true

    ignore_changes = [
      # Creation parameters of the console-made boot disk may differ from code; never replace it for that.
      boot_disk,
      # The data disk is managed by google_compute_attached_disk (required pairing per the provider docs).
      attached_disk,
      # ssh-keys are managed by the console and gcloud.
      metadata,
      # Changing Shielded VM settings requires a stop. Current: vTPM on, Secure Boot off.
      shielded_instance_config,
    ]
  }
}
