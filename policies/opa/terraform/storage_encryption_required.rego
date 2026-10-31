# Policy: storage encryption required
#
# Block storage and databases must be encrypted at rest with a configuration
# that is explicit in the plan: EBS volumes and RDS instances on AWS, managed
# disks (customer-managed key) and SQL databases (TDE) on Azure.
#
# Controls: CIS AWS Foundations Benchmark 2.2.1 and 2.3.1 · CIS Azure Foundations Benchmark 7.3 ·
# ISO/IEC 27001:2022 A.8.24 · NIST CSF 2.0 PR.DS-01
package terraform.storage_encryption_required

import rego.v1

import data.lib.tfplan

# --- AWS -------------------------------------------------------------------

deny contains msg if {
	some volume in tfplan.of_type("aws_ebs_volume")
	not volume.change.after.encrypted == true
	msg := sprintf("%s: EBS volume must set encrypted = true", [volume.address])
}

deny contains msg if {
	some instance in tfplan.of_type("aws_db_instance")
	not instance.change.after.storage_encrypted == true
	msg := sprintf("%s: RDS instance must set storage_encrypted = true", [instance.address])
}

# --- Azure -----------------------------------------------------------------

deny contains msg if {
	some disk in tfplan.of_type("azurerm_managed_disk")
	not customer_managed_key(disk)
	msg := sprintf("%s: managed disk must reference a disk_encryption_set_id", [disk.address])
}

deny contains msg if {
	some database in tfplan.of_type("azurerm_mssql_database")
	database.change.after.transparent_data_encryption_enabled == false
	msg := sprintf("%s: transparent_data_encryption_enabled must not be false", [database.address])
}

customer_managed_key(disk) if {
	disk.change.after.disk_encryption_set_id != null
	disk.change.after.disk_encryption_set_id != ""
}

# The encryption set is usually created in the same plan, so its id is unknown.
customer_managed_key(disk) if {
	tfplan.unknown(disk, "disk_encryption_set_id")
}
