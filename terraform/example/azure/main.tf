# Minimal Azure example for the policies in this repository.
#
# Resources suffixed `_good` are meant to PASS every policy; resources suffixed
# `_bad` are meant to FAIL on purpose. Never apply this configuration as-is.
# All names and identifiers are fictional (Northwind Logistics); the
# subscription id is the all-zero placeholder.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

locals {
  location            = "westeurope"
  resource_group_name = "rg-northwind-example"
  subscription_id     = "00000000-0000-0000-0000-000000000000"
  common_tags = {
    owner       = "platform-team"
    environment = "prod"
  }
}

resource "azurerm_resource_group" "example" {
  name     = local.resource_group_name
  location = local.location
  tags     = local.common_tags
}

# --- Object storage ----------------------------------------------------------

# PASS: public blob access disabled, HTTPS enforced, private container.
resource "azurerm_storage_account" "data_good" {
  name                            = "northwinddataprod"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  tags                            = { owner = "data-platform", environment = "prod" }
}

resource "azurerm_storage_container" "invoices_good" {
  name                  = "invoices"
  storage_account_id    = azurerm_storage_account.data_good.id
  container_access_type = "private"
}

# FAIL (OPA: allow_nested_items_to_be_public = true; Checkov: CKV2_CUSTOM_3).
resource "azurerm_storage_account" "data_bad" {
  name                            = "northwinddatadev"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
}

# FAIL (OPA: container_access_type = "blob").
resource "azurerm_storage_container" "public_bad" {
  name                  = "exports"
  storage_account_id    = azurerm_storage_account.data_bad.id
  container_access_type = "blob"
}

# --- Disks and databases -------------------------------------------------------

# PASS: customer-managed key through a disk encryption set.
resource "azurerm_managed_disk" "data_good" {
  name                   = "orders-data-prod"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  storage_account_type   = "Premium_LRS"
  create_option          = "Empty"
  disk_size_gb           = 256
  disk_encryption_set_id = "/subscriptions/${local.subscription_id}/resourceGroups/${local.resource_group_name}/providers/Microsoft.Compute/diskEncryptionSets/des-northwind-prod"
  tags                   = { owner = "orders-team" }
}

# FAIL (OPA: no disk_encryption_set_id).
resource "azurerm_managed_disk" "data_bad" {
  name                 = "orders-data-dev"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 64
}

resource "azurerm_mssql_server" "example" {
  name                         = "sql-northwind-example"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "replace-me-with-a-key-vault-reference"
  minimum_tls_version          = "1.2"
  tags                         = local.common_tags
}

# PASS
resource "azurerm_mssql_database" "orders_good" {
  name                                = "orders"
  server_id                           = azurerm_mssql_server.example.id
  sku_name                            = "S1"
  transparent_data_encryption_enabled = true
  tags                                = { owner = "orders-team" }
}

# FAIL (OPA: transparent_data_encryption_enabled = false).
resource "azurerm_mssql_database" "orders_bad" {
  name                                = "orders-dev"
  server_id                           = azurerm_mssql_server.example.id
  sku_name                            = "Basic"
  transparent_data_encryption_enabled = false
}

# --- Network -------------------------------------------------------------------

# PASS: inline rule only denies.
resource "azurerm_network_security_group" "web_good" {
  name                = "nsg-web-prod"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  tags                = local.common_tags

  security_rule {
    name                       = "deny-rdp"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# PASS: HTTPS from the internet.
resource "azurerm_network_security_rule" "https_good" {
  name                        = "allow-https"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.web_good.name
}

# PASS: SSH from the corporate range only.
resource "azurerm_network_security_rule" "ssh_good" {
  name                        = "allow-ssh-corporate"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "10.20.0.0/16"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.web_good.name
}

# FAIL (OPA: inline rule allows 20-30 from Internet).
resource "azurerm_network_security_group" "web_bad" {
  name                = "nsg-web-dev"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  security_rule {
    name                       = "allow-mgmt-range"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "20-30"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-https"
    priority                   = 210
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

# FAIL (OPA: SSH from *).
resource "azurerm_network_security_rule" "ssh_bad" {
  name                        = "allow-ssh-any"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.web_bad.name
}

# FAIL (OPA: 3389 in destination_port_ranges from 0.0.0.0/0 in source_address_prefixes).
resource "azurerm_network_security_rule" "mgmt_bad" {
  name                        = "allow-mgmt-lists"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["3389", "8080"]
  source_address_prefixes     = ["0.0.0.0/0"]
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.web_bad.name
}
