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
  default = "https://github.com/jperla/proof-of-geography/releases/download/v0.1.0/pog-linux-x86_64.tar.gz"
}

variable "ssh_public_key" {
  type        = string
  description = "Ephemeral SSH public key used solely to run cross-anchor mesh benchmarks"
}

variable "enable_azure" {
  type    = bool
  default = false
}

variable "azure_location" {
  type    = string
  default = "centralus"
}

variable "azure_subscription_id" {
  type    = string
  default = ""
}

provider "google" {
  project = var.gcp_project_id
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id != "" ? var.azure_subscription_id : null
}

# =============================================================================
# 1. ISOLATED GCP NETWORK & 4 AMD SEV-SNP CONFIDENTIAL VMs
#    Lives in its own brand-new GCP project + custom isolated VPC (zero shared VPC)
# =============================================================================

locals {
  gcp_pilot_nodes = {
    "gcp-us-west1-oregon"        = { region = "us-west1", zone = "us-west1-b", cidr = "10.210.1.0/24", machine = "n2d-standard-2", lat = 45.5946, lon = -121.1787, city = "The Dalles, OR, USA" }
    "gcp-us-east4-ashburn"       = { region = "us-east4", zone = "us-east4-a", cidr = "10.210.2.0/24", machine = "n2d-standard-2", lat = 39.0438, lon = -77.4874, city = "Ashburn, VA, USA" }
    "gcp-europe-west3-frankfurt" = { region = "europe-west3", zone = "europe-west3-a", cidr = "10.210.3.0/24", machine = "n2d-standard-2", lat = 50.1109, lon = 8.6821, city = "Frankfurt, Germany" }
    "gcp-asia-northeast1-tokyo"  = { region = "asia-northeast1", zone = "asia-northeast1-a", cidr = "10.210.4.0/24", machine = "n2d-standard-2", lat = 35.6762, lon = 139.6503, city = "Tokyo, Japan" }
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
  name    = "pog-isolated-ingress"
  network = google_compute_network.pog_isolated_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22", "7443", "7445"]
  }
  allow {
    protocol = "udp"
    ports    = ["1024-65535"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["pog-pilot"]
}

resource "google_compute_address" "gcp_ips" {
  for_each     = local.gcp_pilot_nodes
  name         = "ip-${each.key}"
  region       = each.value.region
  network_tier = "STANDARD"
}

resource "google_compute_instance" "gcp_nodes" {
  for_each     = local.gcp_pilot_nodes
  name         = each.key
  machine_type = each.value.machine
  zone         = each.value.zone
  tags         = ["pog-pilot", each.key]

  labels = {
    project = "proof-of-geography-pilot"
    role    = "anchor-tee"
  }

  confidential_instance_config {
    confidential_instance_type = "SEV_SNP"
  }

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
    })
  }
}

# =============================================================================
# 2. OPTIONAL ISOLATED AZURE RESOURCE GROUP & AMD SEV-SNP CONFIDENTIAL VM
# =============================================================================

resource "azurerm_resource_group" "pog_rg" {
  count    = var.enable_azure ? 1 : 0
  name     = "rg-pog-pilot-isolated"
  location = var.azure_location
  tags     = { project = "proof-of-geography-pilot" }
}

resource "azurerm_virtual_network" "pog_vnet" {
  count               = var.enable_azure ? 1 : 0
  name                = "vnet-pog-isolated"
  address_space       = ["10.220.0.0/16"]
  location            = azurerm_resource_group.pog_rg[0].location
  resource_group_name = azurerm_resource_group.pog_rg[0].name
}

resource "azurerm_subnet" "pog_snet" {
  count                = var.enable_azure ? 1 : 0
  name                 = "snet-pog-isolated"
  resource_group_name  = azurerm_resource_group.pog_rg[0].name
  virtual_network_name = azurerm_virtual_network.pog_vnet[0].name
  address_prefixes     = ["10.220.1.0/24"]
}

resource "azurerm_public_ip" "pog_pip" {
  count               = var.enable_azure ? 1 : 0
  name                = "pip-pog-azure"
  location            = azurerm_resource_group.pog_rg[0].location
  resource_group_name = azurerm_resource_group.pog_rg[0].name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "pog_nsg" {
  count               = var.enable_azure ? 1 : 0
  name                = "nsg-pog-isolated"
  location            = azurerm_resource_group.pog_rg[0].location
  resource_group_name = azurerm_resource_group.pog_rg[0].name

  security_rule {
    name                       = "AllowPogTcp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "7443", "7445"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "AllowPogUdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "1024-65535"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "pog_nic" {
  count               = var.enable_azure ? 1 : 0
  name                = "nic-pog-azure"
  location            = azurerm_resource_group.pog_rg[0].location
  resource_group_name = azurerm_resource_group.pog_rg[0].name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.pog_snet[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pog_pip[0].id
  }
}

resource "azurerm_network_interface_security_group_association" "pog_assoc" {
  count                     = var.enable_azure ? 1 : 0
  network_interface_id      = azurerm_network_interface.pog_nic[0].id
  network_security_group_id = azurerm_network_security_group.pog_nsg[0].id
}

resource "azurerm_linux_virtual_machine" "azure_node" {
  count               = var.enable_azure ? 1 : 0
  name                = "azure-${var.azure_location}-pilot"
  resource_group_name = azurerm_resource_group.pog_rg[0].name
  location            = azurerm_resource_group.pog_rg[0].location
  size                = "Standard_DC2as_v5"
  admin_username      = "pog"
  network_interface_ids = [
    azurerm_network_interface.pog_nic[0].id,
  ]
  custom_data = base64encode(templatefile("${path.module}/cloud-init-pilot.yaml", {
    anchor_id           = "azure-${var.azure_location}-pilot"
    cloud_provider      = "azure"
    release_tarball_url = var.release_tarball_url
    ssh_public_key      = var.ssh_public_key
  }))

  admin_ssh_key {
    username   = "pog"
    public_key = var.ssh_public_key
  }

  secure_boot_enabled = true
  vtpm_enabled        = true

  os_disk {
    caching                  = "ReadWrite"
    storage_account_type     = "StandardSSD_LRS"
    security_encryption_type = "VMGuestStateOnly"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "cvm"
    version   = "latest"
  }
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
      }
    },
    local.aws_pilot_outputs,
    var.enable_azure ? {
      "azure-${var.azure_location}-pilot" = {
        ip             = azurerm_public_ip.pog_pip[0].ip_address
        cloud_provider = "azure"
        region         = var.azure_location
        city           = "Azure ${var.azure_location}"
        lat            = 41.5868
        lon            = -93.6250
      }
    } : {}
  )
}
