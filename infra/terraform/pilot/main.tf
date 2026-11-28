terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "gcp_project_id" {
  type        = string
  description = "Brand-new dedicated GCP project strictly isolated for Proof of Geography pilot"
}

variable "release_tarball_url" {
  type    = string
  default = "https://github.com/jperla/proof-of-geography/releases/download/v0.1.4/pog-linux-x86_64.tar.gz"
}

variable "allow_ssh" {
  type        = bool
  default     = false
  description = "Keep false in public mode (zero public SSH attack surface!)"
}

variable "lockdown_egress" {
  type        = bool
  default     = true
  description = "Keep true in public mode (blocks all Anchor outbound TCP, IMDS, and RFC1918!)"
}

variable "ssh_public_key" {
  type        = string
  description = "Ephemeral SSH public key used solely for initial provisioning & telemetry"
}

variable "enable_azure" {
  type    = bool
  default = false
}

variable "azure_subscription_id" {
  type    = string
  default = "2fc83893-ca6c-48e4-b090-8860fba33d33"
}

variable "paris_llm_demo_external_managed" {
  type        = bool
  default     = true
  description = "When true, gcp-europe-west9-paris VM instance lifecycle is owned by the isolated Confidential Space Verified LLM demo (subnet and static IP remain managed here; all other regions and fleet safeguards remain untouched)."
}

provider "google" {
  project = var.gcp_project_id
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id != "" ? var.azure_subscription_id : null
}

# =============================================================================
# 1. ISOLATED GCP NETWORK & 7 HARDWARE TEE CONFIDENTIAL VMs + PARIS LLM SUBNET/IP
#    (14 legacy SoftwareDev pilot VMs retired -> 100% Hardware TEE Constellation!)
#    Lives in its own dedicated GCP project + custom isolated VPC (zero shared VPC)
#    Zero IAM service accounts, Shielded VM Secure Boot + vTPM, SELinux Enforcing
# =============================================================================

locals {
  gcp_pilot_nodes = {
    # --- North America (3 GCP Hardware TEEs: 2 Intel TDX + 1 AMD SEV-SNP) ---
    "gcp-us-west1-oregon"                  = { region = "us-west1", zone = "us-west1-a", cidr = "10.210.1.0/24", machine = "c3-standard-4", tee = "TDX", min_cpu = null, lat = 45.5946, lon = -121.1787, city = "The Dalles, OR, USA", slug = "pdx-gcp" }
    "gcp-us-central1-iowa"                 = { region = "us-central1", zone = "us-central1-a", cidr = "10.210.5.0/24", machine = "n2d-standard-2", tee = "SEV_SNP", min_cpu = "AMD Milan", lat = 41.2619, lon = -95.8608, city = "Council Bluffs, IA, USA", slug = "dsm-gcp" }
    "gcp-us-east4-ashburn"                 = { region = "us-east4", zone = "us-east4-a", cidr = "10.210.2.0/24", machine = "c3-standard-4", tee = "TDX", min_cpu = null, lat = 39.0438, lon = -77.4874, city = "Ashburn, VA, USA", slug = "iad-gcp" }

    # --- Europe (3 GCP AMD SEV-SNP Anchors + externally managed Paris Verified LLM subnet/IP) ---
    "gcp-europe-west2-london"              = { region = "europe-west2", zone = "europe-west2-c", cidr = "10.210.18.0/24", machine = "n2d-standard-2", tee = "SEV_SNP", min_cpu = "AMD Milan", lat = 51.5074, lon = -0.1278, city = "London, UK", slug = "lhr-gcp" }
    "gcp-europe-west4-netherlands"         = { region = "europe-west4", zone = "europe-west4-a", cidr = "10.210.19.0/24", machine = "n2d-standard-2", tee = "SEV_SNP", min_cpu = "AMD Milan", lat = 52.3676, lon = 4.9041, city = "Amsterdam, Netherlands", slug = "ams-gcp" }
    "gcp-europe-west3-frankfurt"           = { region = "europe-west3", zone = "europe-west3-a", cidr = "10.210.3.0/24", machine = "n2d-standard-2", tee = "SEV_SNP", min_cpu = "AMD Milan", lat = 50.1109, lon = 8.6821, city = "Frankfurt, Germany", slug = "fra-gcp" }
    "gcp-europe-west9-paris"               = { region = "europe-west9", zone = "europe-west9-b", cidr = "10.210.21.0/24", machine = "c3-standard-4", tee = "TDX", min_cpu = null, lat = 48.8566, lon = 2.3522, city = "Paris, France", slug = "cdg-gcp" }

    # --- APAC (1 GCP AMD SEV-SNP Anchor) ---
    "gcp-asia-southeast1-singapore"        = { region = "asia-southeast1", zone = "asia-southeast1-a", cidr = "10.210.6.0/24", machine = "n2d-standard-2", tee = "SEV_SNP", min_cpu = "AMD Milan", lat = 1.3521, lon = 103.8198, city = "Jurong West, Singapore", slug = "sin-gcp" }
  }
}

resource "google_compute_network" "pog_isolated_vpc" {
  name                    = "pog-isolated-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "pog_subnets" {
  for_each      = local.gcp_pilot_nodes
  name          = "snet-${each.key}"
  region        = each.value.region
  network       = google_compute_network.pog_isolated_vpc.id
  ip_cidr_range = each.value.cidr
}

resource "google_compute_firewall" "pog_ingress" {
  name      = "pog-isolated-ingress"
  network   = google_compute_network.pog_isolated_vpc.id
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = var.allow_ssh ? ["22", "443", "7443", "7445"] : ["443", "7443", "7445"]
  }
  allow {
    protocol = "udp"
    ports    = ["40000-40999"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["pog-pilot"]
}

# Strict egress lockdown: Anchors NEVER need to reach cloud metadata or initiate outbound TCP scans.
resource "google_compute_firewall" "pog_egress_deny_private" {
  count              = var.lockdown_egress ? 1 : 0
  name               = "pog-isolated-egress-deny-private"
  network            = google_compute_network.pog_isolated_vpc.id
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
  target_tags        = ["pog-pilot"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_firewall" "pog_egress_allow_udp" {
  count              = var.lockdown_egress ? 1 : 0
  name               = "pog-isolated-egress-allow-udp"
  network            = google_compute_network.pog_isolated_vpc.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["pog-pilot"]

  allow {
    protocol = "udp"
    ports    = ["123", "1024-65535"]
  }
}

resource "google_compute_firewall" "pog_egress_deny_all" {
  count              = var.lockdown_egress ? 1 : 0
  name               = "pog-isolated-egress-deny-all"
  network            = google_compute_network.pog_isolated_vpc.id
  direction          = "EGRESS"
  priority           = 65500
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["pog-pilot"]

  deny {
    protocol = "all"
  }
}

# =============================================================================
# 1B. DEDICATED ISOLATED PUBLIC WEB VISUALIZER (proofofgeography.com)
#     Rocky Linux 9 SELinux Enforcing, strictly separated from TEE Anchors!
# =============================================================================

resource "google_compute_firewall" "pog_web_ingress" {
  name      = "pog-isolated-web-ingress"
  network   = google_compute_network.pog_isolated_vpc.id
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = var.allow_ssh ? ["22", "80", "443"] : ["80", "443"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["pog-web"]
}

resource "google_compute_firewall" "pog_web_egress_deny_private" {
  count              = var.lockdown_egress ? 1 : 0
  name               = "pog-isolated-web-egress-deny-private"
  network            = google_compute_network.pog_isolated_vpc.id
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
  target_tags        = ["pog-web"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_address" "pog_web_ip" {
  name         = "ip-pog-web"
  region       = "us-west1"
  network_tier = "STANDARD"
}

resource "google_compute_instance" "pog_web" {
  name                      = "pog-web-visualizer"
  machine_type              = "e2-small"
  zone                      = "us-west1-a"
  tags                      = ["pog-web"]
  allow_stopping_for_update = true

  service_account {
    scopes = []
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = {
    project = "proof-of-geography-pilot"
    role    = "public-web"
    os      = "rocky-linux-9"
  }

  boot_disk {
    initialize_params {
      image = "rocky-linux-cloud/rocky-linux-9-optimized-gcp"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.pog_subnets["gcp-us-west1-oregon"].id
    access_config {
      nat_ip       = google_compute_address.pog_web_ip.address
      network_tier = "STANDARD"
    }
  }

  metadata = {
    ssh-keys = "pog:${var.ssh_public_key}"
    user-data = templatefile("${path.module}/cloud-init-web.yaml", {
      release_tarball_url = var.release_tarball_url
      ssh_public_key      = var.ssh_public_key
    })
  }
}

resource "google_compute_address" "gcp_ips" {
  for_each     = local.gcp_pilot_nodes
  name         = "ip-${each.key}"
  region       = each.value.region
  network_tier = "STANDARD"
}

resource "google_compute_instance" "gcp_nodes" {
  for_each = {
    for k, v in local.gcp_pilot_nodes : k => v
    if !(var.paris_llm_demo_external_managed && k == "gcp-europe-west9-paris")
  }
  name                      = each.key
  machine_type              = each.value.machine
  min_cpu_platform          = each.value.min_cpu
  zone                      = each.value.zone
  tags                      = ["pog-pilot", each.key]
  allow_stopping_for_update = true

  # Zero IAM service account attached -> IMDS cannot yield any GCP credentials even if compromised!
  service_account {
    scopes = []
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = {
    project = "proof-of-geography-pilot"
    role    = "anchor-tee"
    os      = "rocky-linux-9"
  }

  dynamic "confidential_instance_config" {
    for_each = each.value.tee != "NONE" ? [1] : []
    content {
      confidential_instance_type = each.value.tee
    }
  }

  scheduling {
    on_host_maintenance = each.value.tee != "NONE" ? "TERMINATE" : "MIGRATE"
    automatic_restart   = true
  }

  boot_disk {
    initialize_params {
      image = "rocky-linux-cloud/rocky-linux-9-optimized-gcp"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.pog_subnets[each.key].id
    nic_type   = "GVNIC"
    access_config {
      nat_ip       = google_compute_address.gcp_ips[each.key].address
      network_tier = "STANDARD"
    }
  }

  metadata = {
    ssh-keys = "pog:${var.ssh_public_key}"
    user-data = templatefile("${path.module}/cloud-init-pilot.yaml", {
      anchor_id           = each.key
      cloud_provider      = "gcp"
      release_tarball_url = var.release_tarball_url
      ssh_public_key      = var.ssh_public_key
      extra_flags         = contains(["SEV", "NONE"], each.value.tee) ? "--allow-dev-tee --allow-dev-prover" : "--allow-dev-prover"
    })
  }
}

output "web_ip" {
  value = google_compute_address.pog_web_ip.address
}

output "pilot_endpoints" {
  value = merge(
    {
      for k, v in local.gcp_pilot_nodes : k => {
        ip             = google_compute_address.gcp_ips[k].address
        cloud_provider = "gcp"
        region         = v.region
        city           = v.city
        lat            = v.lat
        lon            = v.lon
        slug           = v.slug
      }
    },
    local.aws_pilot_outputs,
    local.azure_pilot_outputs
  )
}
