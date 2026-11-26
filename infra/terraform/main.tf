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
    # Extensible sovereign/Asian cloud providers (enable per deployment profile):
    # - OVHcloud (OpenStack): terraform-provider-openstack/openstack
    # - ByteDance / Volcengine / BytePlus: volcengine/volcengine
    # - Tencent Cloud: tencentcloudstack/tencentcloud
  }
}

# =============================================================================
# Proof of Geography — 24-Node Multi-Cloud Global Anchor Grid
# Spans 6 independent cloud providers so NO single cloud or country controls
# a Byzantine quorum:
#   - 8 GCP Confidential VMs (AMD SEV-SNP Genoa Secure TSC + Intel TDX)
#   - 8 AWS Anchors (EC2 AMD SEV-SNP c6a.large + AWS Nitro Enclave fallback)
#   - 4 Azure Confidential VMs (AMD SEV-SNP DCas_v5 + Intel TDX DCes_v5)
#   - 2 OVHcloud EU Sovereign Anchors (France GRA11 + Poland WAW1)
#   - 1 ByteDance / BytePlus Confidential Anchor (Singapore/Johor)
#   - 1 Tencent Cloud Confidential CVM Anchor (Hong Kong)
# =============================================================================

locals {
  cloud_init_rendered = templatefile("${path.module}/cloud-init/anchor-bootstrap.yaml", {
    pog_image_tag = var.pog_image_tag
    tcp_port      = var.anchor_tcp_port
    udp_port      = var.anchor_udp_port
  })

  gcp_nodes = {
    "gcp-us-east4-ashburn"          = { region = "us-east4", zone = "us-east4-a", machine = "c3d-standard-4", tee = "SEV_SNP", lat = 39.0438, lon = -77.4874 }
    "gcp-us-central1-iowa"          = { region = "us-central1", zone = "us-central1-a", machine = "c3-standard-4", tee = "TDX", lat = 41.2619, lon = -95.8608 }
    "gcp-us-west1-oregon"           = { region = "us-west1", zone = "us-west1-b", machine = "c3d-standard-4", tee = "SEV_SNP", lat = 45.5946, lon = -121.1787 }
    "gcp-europe-west3-frankfurt"    = { region = "europe-west3", zone = "europe-west3-a", machine = "c3d-standard-4", tee = "SEV_SNP", lat = 50.1109, lon = 8.6821 }
    "gcp-europe-west2-london"       = { region = "europe-west2", zone = "europe-west2-a", machine = "c3d-standard-4", tee = "SEV_SNP", lat = 51.5074, lon = -0.1278 }
    "gcp-asia-northeast1-tokyo"     = { region = "asia-northeast1", zone = "asia-northeast1-a", machine = "c3d-standard-4", tee = "SEV_SNP", lat = 35.6762, lon = 139.6503 }
    "gcp-asia-east1-taiwan"         = { region = "asia-east1", zone = "asia-east1-b", machine = "n2d-standard-2", tee = "SEV_SNP", lat = 24.0518, lon = 120.5161 }
    "gcp-asia-southeast1-singapore" = { region = "asia-southeast1", zone = "asia-southeast1-a", machine = "c3-standard-4", tee = "TDX", lat = 1.3521, lon = 103.8198 }
  }

  aws_nodes = {
    "aws-us-east-1-nvirginia"  = { region = "us-east-1", instance = "c6a.large", mode = "sev_snp", lat = 39.0180, lon = -77.4590 }
    "aws-us-west-2-oregon"     = { region = "us-west-2", instance = "c6a.large", mode = "sev_snp", lat = 45.8399, lon = -119.7006 }
    "aws-us-west-1-sanjose"    = { region = "us-west-1", instance = "c6i.xlarge", mode = "nitro", lat = 37.3382, lon = -121.8863 }
    "aws-eu-central-1-fra"     = { region = "eu-central-1", instance = "c6a.large", mode = "sev_snp", lat = 50.1167, lon = 8.6833 }
    "aws-eu-north-1-stockholm" = { region = "eu-north-1", instance = "c6a.large", mode = "sev_snp", lat = 59.3293, lon = 18.0686 }
    "aws-ap-northeast-1-tokyo" = { region = "ap-northeast-1", instance = "c6a.large", mode = "sev_snp", lat = 35.6895, lon = 139.6917 }
    "aws-ap-northeast-2-seoul" = { region = "ap-northeast-2", instance = "c6i.xlarge", mode = "nitro", lat = 37.5665, lon = 126.9780 }
    "aws-ap-southeast-2-syd"   = { region = "ap-southeast-2", instance = "c6a.large", mode = "sev_snp", lat = -33.8688, lon = 151.2093 }
  }

  azure_nodes = {
    "azure-southcentralus-texas"  = { location = "southcentralus", vm_size = "Standard_DC2as_v5", tee = "SEV_SNP", lat = 29.4241, lon = -98.4936 }
    "azure-canadacentral-toronto" = { location = "canadacentral", vm_size = "Standard_DC2es_v5", tee = "TDX", lat = 43.6532, lon = -79.3832 }
    "azure-westeurope-amsterdam"  = { location = "westeurope", vm_size = "Standard_DC2es_v5", tee = "TDX", lat = 52.3676, lon = 4.9041 }
    "azure-brazilsouth-saopaulo"  = { location = "brazilsouth", vm_size = "Standard_DC2as_v5", tee = "SEV_SNP", lat = -23.5505, lon = -46.6333 }
  }
}

provider "google" {
  project = var.gcp_project_id
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

# Deploy 8 GCP Confidential VM Anchors (AMD SEV-SNP Genoa + Intel TDX).
module "gcp_anchors" {
  source   = "./modules/gcp-anchor"
  for_each = var.enable_gcp ? local.gcp_nodes : {}

  anchor_id    = each.key
  project_id   = var.gcp_project_id
  region       = each.value.region
  zone         = each.value.zone
  machine_type = each.value.machine
  tee_type     = each.value.tee
  tcp_port     = var.anchor_tcp_port
  udp_port     = var.anchor_udp_port
  user_data    = local.cloud_init_rendered
}

# Deploy 4 Azure Confidential VM Anchors (AMD SEV-SNP + Intel TDX).
module "azure_anchors" {
  source   = "./modules/azure-anchor"
  for_each = var.enable_azure ? local.azure_nodes : {}

  anchor_id   = each.key
  location    = each.value.location
  vm_size     = each.value.vm_size
  tee_type    = each.value.tee
  tcp_port    = var.anchor_tcp_port
  udp_port    = var.anchor_udp_port
  custom_data = base64encode(local.cloud_init_rendered)
}

# AWS multi-region deployment: instantiate `modules/aws-anchor` with regional provider aliases
# (see `modules/aws-anchor/README.md` and `modules/{ovh,bytedance,tencent}-anchor/` for
# OVHcloud, ByteDance/Volcengine/BytePlus, and Tencent Cloud multi-provider stacks).
