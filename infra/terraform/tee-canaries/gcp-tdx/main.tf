# Staged Reversible GCP Intel TDX Confidential Space Canary (Zero New Compute Spend)
#
# Governance & Security Invariants:
# - Targets existing unpublished Intel TDX `c3-standard-4` VMs in `pog-pilot-20261125`
#   (`gcp-us-east4-ashburn` Wave 0 canary; then `gcp-us-west1-oregon`, `gcp-europe-west9-paris` Wave 1).
# - NEVER modifies the shared `pog-isolated-ingress` firewall rule or the 14 published diagnostic GCP nodes.
# - Security-sensitive changes staged here for explicit operator review BEFORE apply:
#   1. Enable `confidentialcomputing.googleapis.com` API on `pog-pilot-20261125`.
#   2. Create dedicated least-privilege service account `pog-tdx-canary` bound ONLY to
#      `roles/confidentialcomputing.workloadUser` (NOT `roles/editor`).
#   3. Create scoped VPC firewall rule `pog-tdx-canary-ingress` on `pog-isolated-vpc` for tag
#      `pog-tdx-canary`: ONLY `tcp:7443`, `tcp:7445`, `udp:40000-40999` (ZERO `tcp:22` SSH).
#   4. Preserve original Rocky 9 boot disk with `auto-delete=no` before reimaging `gcp-us-east4-ashburn`
#      onto production `confidential-space-261001` (NO debug image, NO SSH, NO shell) running pinned
#      `ghcr.io/jperla/proof-of-geography/pog-anchor@sha256:<GCP_TDX_DIGEST>` with EMPTY `cmd_override`.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  type    = string
  default = "pog-pilot-20261125"
}

variable "vpc_network_name" {
  type    = string
  default = "pog-isolated-vpc"
}

variable "pinned_gcp_tdx_image_ref" {
  description = "Immutable digest-pinned GHCR zero-shell Confidential Space image (MUST use @sha256:...)."
  type        = string
}

variable "confidential_space_image" {
  description = "Production Confidential Space OS image (NEVER use confidential-space-debug!)."
  type        = string
  default     = "projects/confidential-space-images/global/images/confidential-space-261001"
}

variable "allow_https_443" {
  description = "Keep false until TLS reverse proxy/LB is explicitly configured."
  type        = bool
  default     = false
}

resource "google_project_service" "confidential_computing" {
  project            = var.project_id
  service            = "confidentialcomputing.googleapis.com"
  disable_on_destroy = false
}

resource "google_service_account" "tdx_canary" {
  project      = var.project_id
  account_id   = "pog-tdx-canary"
  display_name = "PoG Intel TDX Confidential Space Canary (Least-Privilege Attestation Only)"
}

resource "google_project_iam_member" "tdx_canary_workload_user" {
  project = var.project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.tdx_canary.email}"
}

resource "google_compute_firewall" "tdx_canary_ingress" {
  project       = var.project_id
  name          = "pog-tdx-canary-ingress"
  network       = var.vpc_network_name
  direction     = "INGRESS"
  priority      = 900
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["pog-tdx-canary"]

  allow {
    protocol = "tcp"
    ports    = var.allow_https_443 ? ["443", "7443", "7445"] : ["7443", "7445"]
  }
  allow {
    protocol = "udp"
    ports    = ["40000-40999"]
  }
}

output "canary_service_account_email" {
  value = google_service_account.tdx_canary.email
}

output "canary_reimage_commands_after_approval" {
  description = "Reversible rollback-preserving reimage sequence for existing gcp-us-east4-ashburn (zero new compute spend)."
  value = join("\n", [
    "# 1. Preserve current Rocky 9 boot disk as non-auto-deleting rollback disk:",
    "gcloud compute instances set-disk-auto-delete gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --disk=gcp-us-east4-ashburn --no-auto-delete",
    "# 2. Stop VM & create Confidential Space production boot disk (NO debug, NO SSH):",
    "gcloud compute instances stop gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a",
    "gcloud compute disks create gcp-us-east4-ashburn-cs-tdx --project=${var.project_id} --zone=us-east4-a --type=pd-balanced --size=20GB --image=${var.confidential_space_image}",
    "# 3. Swap boot disk, attach least-privilege SA, remove ssh-keys/pog-pilot tag, bind pinned digest (empty cmd_override!):",
    "gcloud compute instances detach-disk gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --disk=gcp-us-east4-ashburn",
    "gcloud compute instances attach-disk gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --disk=gcp-us-east4-ashburn-cs-tdx --boot",
    "gcloud compute instances set-service-account gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --service-account=${google_service_account.tdx_canary.email} --scopes=cloud-platform",
    "gcloud compute instances remove-tags gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --tags=pog-pilot",
    "gcloud compute instances add-tags gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --tags=pog-tdx-canary",
    "gcloud compute instances remove-metadata gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --keys=ssh-keys,user-data",
    "gcloud compute instances add-metadata gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a --metadata=^~^tee-image-reference=${var.pinned_gcp_tdx_image_ref}~tee-env-POG_ANCHOR_ID=gcp-us-east4-ashburn~tee-restart-policy=Always",
    "gcloud compute instances start gcp-us-east4-ashburn --project=${var.project_id} --zone=us-east4-a",
    "# Rollback: stop VM, detach gcp-us-east4-ashburn-cs-tdx, reattach preserved disk gcp-us-east4-ashburn --boot, restore tags/metadata, start VM."
  ])
}
