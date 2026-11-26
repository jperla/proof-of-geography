# =============================================================================
# Proof of Geography — 72-Node Rim-Surrounded Global Anchor Grid Blueprint
#
# Architecture:
#   - 42 Hyperscaler Confidential VMs (24 GCP + 13 AWS + 5 Azure) provisioned
#     directly via Terraform (zero touch on default VPCs or existing projects!)
#   - 30 Sovereign / Outer-Rim Bare-Metal SEV-SNP Nodes (OVHcloud + Tencent +
#     BytePlus + Regional IXP Edge in Iceland, Faroe Islands, Azores, Lisbon,
#     Casablanca, Cairo, Istanbul, Bucharest, Almaty, Anchorage, Honolulu,
#     Halifax, Miami, San Juan PR, Panama City, Marseille) exported cleanly as
#     an automated cloud-init / SSH bootstrap inventory!
# =============================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

variable "grid_config_path" {
  type        = string
  default     = "../../../config/global_grid_72.json"
  description = "Path to the canonical 72-node rim-surrounded Anchor topology"
}

variable "release_tarball_url" {
  type    = string
  default = "https://github.com/jperla/proof-of-geography/releases/download/v0.1.2/pog-linux-x86_64.tar.gz"
}

locals {
  grid = jsondecode(file(var.grid_config_path))

  gcp_nodes   = { for a in local.grid.anchors : a.anchor_id => a if a.cloud_provider == "gcp" }
  aws_nodes   = { for a in local.grid.anchors : a.anchor_id => a if a.cloud_provider == "aws" }
  azure_nodes = { for a in local.grid.anchors : a.anchor_id => a if a.cloud_provider == "azure" }
  ovh_nodes   = { for a in local.grid.anchors : a.anchor_id => a if a.cloud_provider == "ovh" }
  edge_nodes  = { for a in local.grid.anchors : a.anchor_id => a if contains(["edge", "tencent", "bytedance"], a.cloud_provider) }
}

output "grid_72_summary" {
  value = {
    total_nodes     = length(local.grid.anchors)
    gcp_nodes       = length(local.gcp_nodes)
    aws_nodes       = length(local.aws_nodes)
    azure_nodes     = length(local.azure_nodes)
    ovh_nodes       = length(local.ovh_nodes)
    edge_sovereign  = length(local.edge_nodes)
    gcp_regions     = sort(distinct([for a in values(local.gcp_nodes) : a.region]))
    aws_regions     = sort(distinct([for a in values(local.aws_nodes) : a.region]))
    rim_edge_cities = sort([for a in values(local.edge_nodes) : "${a.city} (${a.region})"])
  }
}
