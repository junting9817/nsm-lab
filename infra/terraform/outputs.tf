output "sensor_external_ip" {
  description = "Sensor VM external IP"
  value       = google_compute_instance.sensor.network_interface[0].access_config[0].nat_ip
}

output "dashboard_url" {
  description = "Grafana URL"
  value       = "http://${google_compute_instance.sensor.network_interface[0].access_config[0].nat_ip}/"
}

output "data_disk_guest_path" {
  description = "Data disk path inside the guest (setup-disk.sh default)"
  value       = "/dev/disk/by-id/google-${google_compute_attached_disk.data.device_name}"
}

output "iap_ssh_command" {
  description = "SSH command through IAP"
  value       = "gcloud compute ssh ${var.instance_name} --zone=${var.zone} --tunnel-through-iap"
}

output "sensor_service_account" {
  description = "Dedicated sensor service account (attached to the VM when attach_dedicated_sa=true)"
  value       = google_service_account.sensor.email
}

output "honeypot_external_ip" {
  description = "Honeypot (Cowrie) external IP"
  value       = google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip
}

output "honeypot_bucket" {
  description = "One-way honeypot log bucket"
  value       = google_storage_bucket.honeypot_logs.name
}

output "honeypot_stage" {
  description = "Current honeypot stage (bootstrap or live)"
  value       = var.honeypot_stage
}

output "honeypot_admin_ssh" {
  description = "Admin SSH to the honeypot through IAP (run from Cloud Shell; the real sshd listens on 22222)"
  value       = "gcloud compute start-iap-tunnel ${google_compute_instance.honeypot.name} 22222 --local-host-port=localhost:2222 --zone=${var.honeypot_zone} & ssh -p 2222 localhost"
}

output "blocklist_firewall" {
  description = "VPC firewall rule whose source ranges the responder manages"
  value       = google_compute_firewall.blocklist.name
}
