variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "Region"
  type        = string
  default     = "asia-northeast3"
}

variable "zone" {
  description = "Zone of the sensor VM and its data disk"
  type        = string
  default     = "asia-northeast3-c"
}

variable "network" {
  description = "VPC network the sensor VM is attached to"
  type        = string
  default     = "default"
}

variable "instance_name" {
  description = "Name of the existing sensor VM (import target)"
  type        = string
  default     = "myfirstserver"
}

variable "machine_type" {
  description = "Sensor VM machine type. Changing it requires stopping the VM."
  type        = string
  default     = "e2-standard-2"
}

variable "data_disk_size_gb" {
  description = "Size of the data disk for logs, PCAP and ClickHouse (GB)"
  type        = number
  default     = 100
}

variable "data_disk_type" {
  description = "Data disk type"
  type        = string
  default     = "pd-balanced"
}

variable "dashboard_source_ranges" {
  description = <<-EOT
    Source CIDRs allowed to reach Grafana (80/tcp).
    The default is open to everyone, per user decision D3 (docs/architecture.md).
    Narrow it to your own public IP/32 where possible.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "attach_dedicated_sa" {
  description = <<-EOT
    When true, the VM's service account is switched to the dedicated account (nsm-sensor).
    Changing the service account requires stopping the VM, so Terraform may stop it only while this is true.
    Work running on the VM (including the Claude Code session) is interrupted, so enable it only in a maintenance window.
  EOT
  type        = bool
  default     = false
}

# --- Phase 5 honeypot (honeypot.tf) ---------------------------------------------------------------------------

variable "honeypot_stage" {
  description = <<-EOT
    bootstrap: egress open for installing Docker and pulling images; Cowrie 22/tcp reachable only from honeypot_test_source_ranges.
    live: egress denied except Google APIs; Cowrie 22/tcp open to the internet.
  EOT
  type        = string
  default     = "bootstrap"

  validation {
    condition     = contains(["bootstrap", "live"], var.honeypot_stage)
    error_message = "honeypot_stage must be \"bootstrap\" or \"live\"."
  }
}

variable "honeypot_region" {
  description = "Honeypot region (us-central1 is a Compute Engine Free Tier region for one e2-micro)"
  type        = string
  default     = "us-central1"
}

variable "honeypot_zone" {
  description = "Honeypot zone"
  type        = string
  default     = "us-central1-a"
}

variable "honeypot_machine_type" {
  description = "Honeypot machine type (Cowrie + Vector limits total 576 MiB)"
  type        = string
  default     = "e2-micro"
}

variable "honeypot_subnet_cidr" {
  description = "Honeypot subnet; must not overlap anything the sensor network could route to"
  type        = string
  default     = "10.250.0.0/24"
}

variable "honeypot_test_source_ranges" {
  description = "Sources allowed to reach Cowrie in the bootstrap stage. Empty = the sensor VM's external IP/32"
  type        = list(string)
  default     = []
}

variable "honeypot_log_retention_days" {
  description = "Days before shipped honeypot log objects are deleted from the bucket (the sensor keeps its copy in ClickHouse)"
  type        = number
  default     = 30
}
