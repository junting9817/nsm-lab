# Dedicated disk for logs, PCAP and ClickHouse data, separate from the 10 GB boot disk so a full disk cannot stop the OS.
resource "google_compute_disk" "data" {
  name = "nsm-data"
  zone = var.zone
  type = var.data_disk_type
  size = var.data_disk_size_gb

  labels = {
    role = "nsm-data"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Attaches to the running VM without a stop; the guest sees it as /dev/disk/by-id/google-nsm-data.
resource "google_compute_attached_disk" "data" {
  disk        = google_compute_disk.data.id
  instance    = google_compute_instance.sensor.id
  device_name = "nsm-data"
  mode        = "READ_WRITE"
}
