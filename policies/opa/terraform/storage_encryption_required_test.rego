package terraform.storage_encryption_required

import rego.v1

plan(resources) := {"resource_changes": resources}

resource(address, resource_type, after) := {
	"address": address,
	"type": resource_type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

test_encrypted_volume_and_database_pass if {
	volume := resource("aws_ebs_volume.data", "aws_ebs_volume", {"encrypted": true, "size": 100})
	database := resource("aws_db_instance.orders", "aws_db_instance", {"storage_encrypted": true})
	result := deny with input as plan([volume, database])
	count(result) == 0
}

test_unencrypted_volume_is_denied if {
	volume := resource("aws_ebs_volume.data", "aws_ebs_volume", {"encrypted": false, "size": 100})
	result := deny with input as plan([volume])
	count(result) == 1
}

test_volume_without_encrypted_attribute_is_denied if {
	volume := resource("aws_ebs_volume.data", "aws_ebs_volume", {"size": 100})
	result := deny with input as plan([volume])
	count(result) == 1
}

test_unencrypted_database_is_denied if {
	database := resource("aws_db_instance.orders", "aws_db_instance", {"storage_encrypted": false})
	result := deny with input as plan([database])
	count(result) == 1
	some msg in result
	contains(msg, "storage_encrypted")
}

test_update_of_unencrypted_volume_is_denied if {
	volume := {
		"address": "aws_ebs_volume.data",
		"type": "aws_ebs_volume",
		"change": {"actions": ["update"], "after": {"encrypted": false}, "after_unknown": {}},
	}
	result := deny with input as plan([volume])
	count(result) == 1
}

test_deleted_unencrypted_volume_is_ignored if {
	volume := {
		"address": "aws_ebs_volume.old",
		"type": "aws_ebs_volume",
		"change": {"actions": ["delete"], "after": null, "after_unknown": {}},
	}
	result := deny with input as plan([volume])
	count(result) == 0
}

test_azure_disk_with_encryption_set_passes if {
	disk := resource("azurerm_managed_disk.data", "azurerm_managed_disk", {"disk_encryption_set_id": "/subscriptions/example/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des"})
	result := deny with input as plan([disk])
	count(result) == 0
}

test_azure_disk_with_unknown_encryption_set_passes if {
	disk := {
		"address": "azurerm_managed_disk.data",
		"type": "azurerm_managed_disk",
		"change": {"actions": ["create"], "after": {"name": "data"}, "after_unknown": {"disk_encryption_set_id": true}},
	}
	result := deny with input as plan([disk])
	count(result) == 0
}

test_azure_disk_without_encryption_set_is_denied if {
	disk := resource("azurerm_managed_disk.data", "azurerm_managed_disk", {"disk_encryption_set_id": null})
	result := deny with input as plan([disk])
	count(result) == 1
}

test_azure_database_with_tde_disabled_is_denied if {
	database := resource("azurerm_mssql_database.orders", "azurerm_mssql_database", {"transparent_data_encryption_enabled": false})
	result := deny with input as plan([database])
	count(result) == 1
}

test_azure_database_with_default_tde_passes if {
	database := resource("azurerm_mssql_database.orders", "azurerm_mssql_database", {"name": "orders"})
	result := deny with input as plan([database])
	count(result) == 0
}
