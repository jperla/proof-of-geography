# =============================================================================
# 3. ISOLATED AZURE MULTI-REGION ROCKY LINUX 9.9 ANCHOR GRID (14 REGIONS)
#    Dedicated resource group `rg-pog-anchors-global` — ZERO touch on any
#    existing Azure resources or VNets!
# =============================================================================

locals {
  azure_anchor_nodes = {
    "azure-northcentralus-chicago" = {
      location = "northcentralus"
      cidr     = "10.220.1.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "ord-az"
      city     = "Chicago, IL, USA"
      lat      = 41.8781
      lon      = -87.6298
    }
    "azure-westus3-phoenix" = {
      location = "westus3"
      cidr     = "10.220.2.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "phx-az"
      city     = "Phoenix, AZ, USA"
      lat      = 33.4484
      lon      = -112.0740
    }
    "azure-southcentralus-sanantonio" = {
      location = "southcentralus"
      cidr     = "10.220.3.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "sat-az"
      city     = "San Antonio, TX, USA"
      lat      = 29.4241
      lon      = -98.4936
    }
    "azure-eastus-virginia" = {
      location = "eastus"
      cidr     = "10.220.4.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "ric-az"
      city     = "Boydton, VA, USA"
      lat      = 36.6676
      lon      = -78.3875
    }
    "azure-canadacentral-toronto" = {
      location = "canadacentral"
      cidr     = "10.220.5.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "yyz-az"
      city     = "Toronto, ON, Canada"
      lat      = 43.6532
      lon      = -79.3832
    }
    "azure-swedencentral-gavle" = {
      location = "swedencentral"
      cidr     = "10.220.6.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "gvl-az"
      city     = "Gävle, Sweden"
      lat      = 60.6749
      lon      = 17.1413
    }
    "azure-polandcentral-warsaw" = {
      location = "polandcentral"
      cidr     = "10.220.7.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "waw-az"
      city     = "Warsaw, Poland"
      lat      = 52.2297
      lon      = 21.0122
    }
    "azure-italynorth-milan" = {
      location = "italynorth"
      cidr     = "10.220.8.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "mxp-az"
      city     = "Milan, Italy"
      lat      = 45.4642
      lon      = 9.1900
    }
    "azure-spaincentral-madrid" = {
      location = "spaincentral"
      cidr     = "10.220.9.0/24"
      vm_size  = "Standard_D2s_v4"
      slug     = "mad-az"
      city     = "Madrid, Spain"
      lat      = 40.4168
      lon      = -3.7038
    }
    "azure-uaenorth-dubai" = {
      location = "uaenorth"
      cidr     = "10.220.10.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "dxb-az"
      city     = "Dubai, UAE"
      lat      = 25.2048
      lon      = 55.2708
    }
    "azure-israelcentral-telaviv" = {
      location = "israelcentral"
      cidr     = "10.220.11.0/24"
      vm_size  = "Standard_D2ls_v6"
      slug     = "tlv-az"
      city     = "Tel Aviv, Israel"
      lat      = 32.0853
      lon      = 34.7818
    }
    "azure-southafricanorth-johannesburg" = {
      location = "southafricanorth"
      cidr     = "10.220.12.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "jnb-az"
      city     = "Johannesburg, South Africa"
      lat      = -26.2041
      lon      = 28.0473
    }
    "azure-koreacentral-seoul" = {
      location = "koreacentral"
      cidr     = "10.220.13.0/24"
      vm_size  = "Standard_D2als_v7"
      slug     = "icn-az"
      city     = "Seoul, South Korea"
      lat      = 37.5665
      lon      = 126.9780
    }
    "azure-chilecentral-santiago" = {
      location = "chilecentral"
      cidr     = "10.220.14.0/24"
      vm_size  = "Standard_D2als_v6"
      slug     = "scl-az"
      city     = "Santiago, Chile"
      lat      = -33.4489
      lon      = -70.6693
    }
  }
}

resource "azurerm_resource_group" "pog_global_rg" {
  count    = var.enable_azure ? 1 : 0
  name     = "rg-pog-anchors-global"
  location = "eastus"
  tags     = { project = "proof-of-geography-pilot", os = "rocky-linux-9" }
}

resource "azurerm_virtual_network" "pog_az_vnet" {
  for_each            = var.enable_azure ? local.azure_anchor_nodes : {}
  name                = "vnet-${each.key}"
  address_space       = [each.value.cidr]
  location            = each.value.location
  resource_group_name = azurerm_resource_group.pog_global_rg[0].name
}

resource "azurerm_subnet" "pog_az_snet" {
  for_each             = var.enable_azure ? local.azure_anchor_nodes : {}
  name                 = "snet-${each.key}"
  resource_group_name  = azurerm_resource_group.pog_global_rg[0].name
  virtual_network_name = azurerm_virtual_network.pog_az_vnet[each.key].name
  address_prefixes     = [each.value.cidr]
}

resource "azurerm_public_ip" "pog_az_pip" {
  for_each            = var.enable_azure ? local.azure_anchor_nodes : {}
  name                = "pip-${each.key}"
  location            = each.value.location
  resource_group_name = azurerm_resource_group.pog_global_rg[0].name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "pog_az_nsg" {
  for_each            = var.enable_azure ? local.azure_anchor_nodes : {}
  name                = "nsg-${each.key}"
  location            = each.value.location
  resource_group_name = azurerm_resource_group.pog_global_rg[0].name

  security_rule {
    name                       = "AllowPogTcp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = var.allow_ssh ? ["22", "443", "7443", "7445"] : ["443", "7443", "7445"]
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
    destination_port_range     = "40000-40999"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  dynamic "security_rule" {
    for_each = var.lockdown_egress ? [1] : []
    content {
      name                       = "AllowPogUdpEgress"
      priority                   = 200
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Udp"
      source_port_range          = "*"
      destination_port_ranges    = ["123", "1024-65535"]
      source_address_prefix      = "*"
      destination_address_prefix = "Internet"
    }
  }

  dynamic "security_rule" {
    for_each = var.lockdown_egress ? [1] : []
    content {
      name                       = "DenyAllInternetEgress"
      priority                   = 400
      direction                  = "Outbound"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "Internet"
    }
  }
}

resource "azurerm_network_interface" "pog_az_nic" {
  for_each            = var.enable_azure ? local.azure_anchor_nodes : {}
  name                = "nic-${each.key}"
  location            = each.value.location
  resource_group_name = azurerm_resource_group.pog_global_rg[0].name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.pog_az_snet[each.key].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pog_az_pip[each.key].id
  }
}

resource "azurerm_network_interface_security_group_association" "pog_az_assoc" {
  for_each                  = var.enable_azure ? local.azure_anchor_nodes : {}
  network_interface_id      = azurerm_network_interface.pog_az_nic[each.key].id
  network_security_group_id = azurerm_network_security_group.pog_az_nsg[each.key].id
}

resource "azurerm_linux_virtual_machine" "azure_nodes" {
  for_each            = var.enable_azure ? local.azure_anchor_nodes : {}
  name                = each.key
  resource_group_name = azurerm_resource_group.pog_global_rg[0].name
  location            = each.value.location
  size                = each.value.vm_size
  admin_username      = "pog"
  network_interface_ids = [
    azurerm_network_interface.pog_az_nic[each.key].id,
  ]

  custom_data = base64encode(templatefile("${path.module}/cloud-init-pilot.yaml", {
    anchor_id           = each.key
    cloud_provider      = "azure"
    release_tarball_url = var.release_tarball_url
    ssh_public_key      = var.ssh_public_key
    extra_flags         = "--allow-dev-tee --allow-dev-prover"
  }))

  admin_ssh_key {
    username   = "pog"
    public_key = var.ssh_public_key
  }

  secure_boot_enabled = true
  vtpm_enabled        = true

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  plan {
    name      = "9-base"
    product   = "rockylinux-x86_64"
    publisher = "resf"
  }

  source_image_reference {
    publisher = "resf"
    offer     = "rockylinux-x86_64"
    sku       = "9-base"
    version   = "9.9.20261112"
  }

  tags = {
    project = "proof-of-geography-pilot"
    os      = "rocky-linux-9"
    role    = "anchor-azure"
  }

  lifecycle {
    ignore_changes = [custom_data]
  }
}

locals {
  azure_pilot_outputs = var.enable_azure ? {
    for k, v in local.azure_anchor_nodes : k => {
      ip             = azurerm_public_ip.pog_az_pip[k].ip_address
      cloud_provider = "azure"
      region         = v.location
      city           = v.city
      lat            = v.lat
      lon            = v.lon
      slug           = v.slug
    }
  } : {}
}
