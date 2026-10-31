package terraform.s3_blob_public_access_blocked

import rego.v1

plan(resources) := {"resource_changes": resources}

resource(address, resource_type, after) := {
	"address": address,
	"type": resource_type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

bucket := resource("aws_s3_bucket.logs", "aws_s3_bucket", {"bucket": "northwind-logs", "acl": null})

full_block := resource("aws_s3_bucket_public_access_block.logs", "aws_s3_bucket_public_access_block", {
	"bucket": "northwind-logs",
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
})

test_bucket_with_full_block_passes if {
	result := deny with input as plan([bucket, full_block])
	count(result) == 0
}

test_bucket_without_block_is_denied if {
	result := deny with input as plan([bucket])
	count(result) == 1
	some msg in result
	contains(msg, "no aws_s3_bucket_public_access_block")
}

test_block_with_one_flag_false_is_denied if {
	weak_block := resource("aws_s3_bucket_public_access_block.logs", "aws_s3_bucket_public_access_block", {
		"bucket": "northwind-logs",
		"block_public_acls": true,
		"block_public_policy": false,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	})
	result := deny with input as plan([bucket, weak_block])
	count(result) == 1
	some msg in result
	contains(msg, "block_public_policy")
}

test_block_with_unknown_bucket_reference_is_accepted if {
	unknown_block := {
		"address": "aws_s3_bucket_public_access_block.logs",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"actions": ["create"],
			"after": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
			"after_unknown": {"bucket": true},
		},
	}
	result := deny with input as plan([bucket, unknown_block])
	count(result) == 0
}

test_public_read_acl_is_denied if {
	acl := resource("aws_s3_bucket_acl.logs", "aws_s3_bucket_acl", {"bucket": "northwind-logs", "acl": "public-read"})
	result := deny with input as plan([bucket, full_block, acl])
	count(result) == 1
}

test_deleted_bucket_is_ignored if {
	deleted := {
		"address": "aws_s3_bucket.old",
		"type": "aws_s3_bucket",
		"change": {"actions": ["delete"], "after": null, "after_unknown": {}},
	}
	result := deny with input as plan([deleted])
	count(result) == 0
}

test_azure_storage_account_public_blob_access_is_denied if {
	account := resource("azurerm_storage_account.data", "azurerm_storage_account", {"allow_nested_items_to_be_public": true})
	result := deny with input as plan([account])
	count(result) == 1
}

test_azure_storage_account_without_the_attribute_is_denied if {
	account := resource("azurerm_storage_account.data", "azurerm_storage_account", {"name": "northwinddata"})
	result := deny with input as plan([account])
	count(result) == 1
}

test_azure_private_account_and_container_pass if {
	account := resource("azurerm_storage_account.data", "azurerm_storage_account", {"allow_nested_items_to_be_public": false})
	container := resource("azurerm_storage_container.invoices", "azurerm_storage_container", {"container_access_type": "private"})
	result := deny with input as plan([account, container])
	count(result) == 0
}

test_azure_blob_container_access_is_denied if {
	container := resource("azurerm_storage_container.invoices", "azurerm_storage_container", {"container_access_type": "blob"})
	result := deny with input as plan([container])
	count(result) == 1
}
