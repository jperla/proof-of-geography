variable "anchor_id" { type = string }
variable "project_id" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "machine_type" { type = string }
variable "tee_type" {
  type        = string
  description = "SEV_SNP or TDX"
}
variable "tcp_port" { type = number }
variable "udp_port" { type = number }
variable "user_data" { type = string }

resource "google_compute_address" "anchor_ip" {
  name         = "${var.anchor_id}-ip"
  region       = var.region
  network_tier = "STANDARD" # Standard Tier forces local metro peering rather than distant PoP hairpinning
}

resource "google_compute_firewall" "anchor_fw" {
  name    = "${var.anchor_id}-fw"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = [tostring(var.tcp_port)]
  }
  allow {
    protocol = "udp"
    ports    = [tostring(var.udp_port), "1024-65535"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = [var.anchor_id]
}

resource "google_compute_instance" "anchor" {
  name         = var.anchor_id
  machine_type = var.machine_type
  zone         = var.zone
  tags         = [var.anchor_id, "pog-anchor"]

  confidential_instance_config {
    confidential_instance_type = var.tee_type
  }

  # Hardware live-migration MUST be disabled (`TERMINATE`) for Confidential VMs.
  scheduling {
    on_host_maintenance = "TERMINATE"
    automatic_restart   = true
  }

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    network  = "default"
    nic_type = "GVNIC"
    access_config {
      nat_ip       = google_compute_address.anchor_ip.address
      network_tier = "STANDARD"
    }
  }

  metadata = {
    user-data = var.user_data
  }
}

output "public_ip" {
  value = google_compute_address.anchor_ip.address
}

output "tee_type" {
  value = var.tee_type
}
