# Isolated Operator-Owned GCP Intel TDX Confidential Space Deployment for Verified LLM Demo
#
# Governance & Security Invariants:
# - Reuses existing already-running, paid-for unpublished Intel TDX `c3-standard-4` VM
#   `gcp-europe-west9-paris` (`34.1.13.45`, reserved static IP `ip-gcp-europe-west9-paris`) -> $0/mo new compute/IP spend!
# - NEVER modifies shared `pog-isolated-ingress` or `pog-isolated-web-ingress` firewall rules,
#   the 42 published diagnostic nodes, `proofofgeography.com` Locate Me, or Ashburn/Oregon TDX canary slots.
# - Tightens attack surface vs `pog-pilot`:
#   1. Dedicated least-privilege SA `pog-tdx-llm-demo` bound ONLY to `roles/confidentialcomputing.workloadUser`.
#   2. Scoped firewall rule `pog-tdx-llm-demo-ingress` targeting ONLY tag `pog-tdx-llm-demo`:
#      ONLY `tcp:443` (end-to-end enclave `rustls` TLS 1.3 + ACME TLS-ALPN-01) — ZERO `tcp:22` SSH, ZERO `tcp:80`!
#   3. Additive DNS A record `llm.proofofgeography.com -> 34.1.13.45` in `proofofgeography-com`.
#   4. Preserves original Rocky 9 boot disk (`--no-auto-delete`) for instant rollback.

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

variable "dns_project_id" {
  type    = string
  default = "quill-cloud-proxy"
}

variable "vpc_network_name" {
  type    = string
  default = "pog-isolated-vpc"
}

variable "pinned_llm_demo_image_ref" {
  description = "Immutable digest-pinned GHCR FROM scratch Verified LLM image (@sha256:...)."
  type        = string
}

variable "confidential_space_image" {
  description = "Production Confidential Space OS image (NEVER use confidential-space-debug!)."
  type        = string
  default     = "projects/confidential-space-images/global/images/confidential-space-261001"
}

resource "google_project_service" "confidential_computing" {
  project            = var.project_id
  service            = "confidentialcomputing.googleapis.com"
  disable_on_destroy = false
}

resource "google_service_account" "llm_demo" {
  project      = var.project_id
  account_id   = "pog-tdx-llm-demo"
  display_name = "PoG Verified LLM Intel TDX Demo (Least-Privilege Attestation Only)"
}

resource "google_project_iam_member" "llm_demo_workload_user" {
  project = var.project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.llm_demo.email}"
}

resource "google_compute_firewall" "llm_demo_ingress" {
  project       = var.project_id
  name          = "pog-tdx-llm-demo-ingress"
  network       = var.vpc_network_name
  direction     = "INGRESS"
  priority      = 900
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["pog-tdx-llm-demo"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_dns_record_set" "llm_demo_a" {
  project      = var.dns_project_id
  managed_zone = "proofofgeography-com"
  name         = "llm.proofofgeography.com."
  type         = "A"
  ttl          = 300
  rrdatas      = ["34.1.13.45"]
}
