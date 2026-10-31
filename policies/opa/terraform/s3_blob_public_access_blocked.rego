# Policy: S3 / Blob public access blocked
#
# Object storage must never be reachable anonymously. On AWS every bucket needs
# an aws_s3_bucket_public_access_block with all four flags set, and no public
# ACL. On Azure the storage account must disable public blob access and no
# container may use a public access type.
#
# Controls: CIS AWS Foundations Benchmark 2.1.4 · CIS Azure Foundations Benchmark 3.7 ·
# ISO/IEC 27001:2022 A.8.3 and A.8.20 · NIST CSF 2.0 PR.AA-05 · PR.DS-01
package terraform.s3_blob_public_access_blocked

import rego.v1

import data.lib.tfplan

public_access_flags := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

public_acls := {"public-read", "public-read-write", "authenticated-read"}

public_container_access := {"blob", "container"}

# --- AWS -------------------------------------------------------------------

deny contains msg if {
	some bucket in tfplan.of_type("aws_s3_bucket")
	not has_public_access_block(bucket)
	msg := sprintf("%s: S3 bucket has no aws_s3_bucket_public_access_block", [bucket.address])
}

deny contains msg if {
	some block in tfplan.of_type("aws_s3_bucket_public_access_block")
	some flag in public_access_flags
	not block.change.after[flag] == true
	msg := sprintf("%s: %s must be true", [block.address, flag])
}

deny contains msg if {
	some bucket in tfplan.of_type("aws_s3_bucket")
	bucket.change.after.acl in public_acls
	msg := sprintf("%s: S3 bucket ACL %q grants public access", [bucket.address, bucket.change.after.acl])
}

deny contains msg if {
	some acl in tfplan.of_type("aws_s3_bucket_acl")
	acl.change.after.acl in public_acls
	msg := sprintf("%s: S3 bucket ACL %q grants public access", [acl.address, acl.change.after.acl])
}

# A block belongs to a bucket when it names the same bucket ...
has_public_access_block(bucket) if {
	some block in tfplan.of_type("aws_s3_bucket_public_access_block")
	block.change.after.bucket == bucket.change.after.bucket
}

# ... or when the reference is only known after apply (bucket = aws_s3_bucket.x.id).
# Reference buckets by `.bucket` rather than `.id` to get an exact match.
has_public_access_block(_) if {
	some block in tfplan.of_type("aws_s3_bucket_public_access_block")
	tfplan.unknown(block, "bucket")
}

# --- Azure -----------------------------------------------------------------

deny contains msg if {
	some account in tfplan.of_type("azurerm_storage_account")
	not account.change.after.allow_nested_items_to_be_public == false
	msg := sprintf("%s: allow_nested_items_to_be_public must be false", [account.address])
}

deny contains msg if {
	some container in tfplan.of_type("azurerm_storage_container")
	container.change.after.container_access_type in public_container_access
	msg := sprintf("%s: container_access_type %q allows anonymous access", [container.address, container.change.after.container_access_type])
}
