# Staged Reversible Azure Confidential VM Canary (Measured SEV-SNP / TDX Guest — NOT Trusted Launch)
#
# Governance & Security Invariants:
# - Dedicated resource group `RG-POG-TEE-CANARIES` — ZERO touch on `RG-POG-ANCHORS-GLOBAL` (14 diagnostic nodes)
#   or `TR-AZURE` (`tr-azure-clickhouse-1`).
# - Requires operator approval for incremental spend (0 existing Azure Confidential VMs):
#   * Smallest SEV-SNP Milan (`eastus`): `Standard_DC2as_v5` = $62.78/mo compute (+ ~$3.65 IPv4 + ~$4.80 disk = ~$71.23/mo).
#   * Recommended Uniform SEV-SNP Genoa (`eastus` & 12+ regions): `Standard_DC2as_v6` = $72.93/mo compute (~$81.38/mo total).
#   * Intel TDX option (`eastus` / `westus3`): `Standard_DC2es_v6` = $81.03/mo compute (~$89.48/mo total).
# - Enforces `security_type = "ConfidentialVM"`, `secure_boot_enabled = true`, `vtpm_enabled = true`, and
#   `security_encryption_type = "VMGuestStateOnly"` (or `"DiskWithVMGuestState"`).
# - Coordinates fixed to Ashburn/N. Virginia (`39.0438, -77.4874`), correcting the Boydton (`eastus2`) coordinate bug
#   in `infra/terraform/pilot/azure_isolated.tf:41-43`.
# - ZERO SSH ingress (`tcp/22` omitted); measured immutable guest image verified via HCL `0x01400001` SEV-SNP +
#   vTPM `TPM2_Quote` PCRs (PCR4, PCR7, PCR9/11) by `crates/pog-tee/src/azure_cvm.rs` & `scripts/verify_public_node.py`.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "anchor_id" {
  type    = string
  default = "azure-eastus-ashburn-cvm-canary"
}

variable "vm_size" {
  description = "Azure Confidential VM SKU: Standard_DC2as_v6 ($72.93/mo SEV-SNP Genoa), Standard_DC2as_v5 ($62.78/mo SEV-SNP Milan), or Standard_DC2es_v6 ($81.03/mo Intel TDX)."
  type        = string
  default     = "Standard_DC2as_v6"
}

variable "measured_cvm_image_id" {
  description = "Resource ID of the measured zero-SSH immutable UKI/dm-verity Azure Compute Gallery CVM image (built from infra/images/flake.nix)."
  type        = string
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "cvm" {
  name     = "RG-POG-TEE-CANARIES"
  location = var.location
  tags     = { Project = "proof-of-geography-tee-canary", SecurityMode = "ConfidentialVM-MeasuredGuest" }
}

resource "azurerm_virtual_network" "cvm" {
  name                = "vnet-${var.anchor_id}"
  address_space       = ["10.212.0.0/16"]
  location            = azurerm_resource_group.cvm.location
  resource_group_name = azurerm_resource_group.cvm.name
}

resource "azurerm_subnet" "cvm" {
  name                 = "snet-${var.anchor_id}"
  resource_group_name  = azurerm_resource_group.cvm.name
  virtual_network_name = azurerm_virtual_network.cvm.name
  address_prefixes     = ["10.212.1.0/24"]
}

resource "azurerm_public_ip" "cvm" {
  name                = "pip-${var.anchor_id}"
  location            = azurerm_resource_group.cvm.location
  resource_group_name = azurerm_resource_group.cvm.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "cvm" {
  name                = "nsg-${var.anchor_id}"
  location            = azurerm_resource_group.cvm.location
  resource_group_name = azurerm_resource_group.cvm.name

  # ZERO TCP/22 SSH rule! Only PoG probe ports.
  security_rule {
    name                       = "allow-pog-tcp-handshake"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["7443", "7445"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "allow-pog-udp-range"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "40000-40999"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "cvm" {
  name                = "nic-${var.anchor_id}"
  location            = azurerm_resource_group.cvm.location
  resource_group_name = azurerm_resource_group.cvm.name

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.cvm.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.cvm.id
  }
}

resource "azurerm_network_interface_security_group_association" "cvm" {
  network_interface_id      = azurerm_network_interface.cvm.id
  network_security_group_id = azurerm_network_security_group.cvm.id
}

resource "azurerm_linux_virtual_machine" "cvm" {
  name                  = var.anchor_id
  resource_group_name   = azurerm_resource_group.cvm.name
  location              = azurerm_resource_group.cvm.location
  size                  = var.vm_size
  admin_username        = "pogunused"
  source_image_id       = var.measured_cvm_image_id
  network_interface_ids = [azurerm_network_interface.cvm.id]

  # Measured immutable UKI/dm-verity image disables sshd, waagent, and login shells.
  disable_password_authentication = true
  admin_ssh_key {
    username   = "pogunused"
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4pRSJHWXHAY+5UtSZYPIwE6wRxJaichgLR2odv8bej pog-unused-no-sshd"
  }

  # Mandatory Confidential VM settings (NEVER TrustedLaunch!)
  secure_boot_enabled = true
  vtpm_enabled        = true

  os_disk {
    caching                  = "ReadWrite"
    storage_account_type     = "StandardSSD_LRS"
    disk_size_gb             = 30
    security_encryption_type = "VMGuestStateOnly"
  }

  tags = {
    Project       = "proof-of-geography-tee-canary"
    TeeMode       = "azure-confidential-vm-hcl-vtpm"
    AuditedCoords = "39.0438,-77.4874"
  }
}

output "azure_cvm_canary_ip" {
  value = azurerm_public_ip.cvm.ip_address
}
