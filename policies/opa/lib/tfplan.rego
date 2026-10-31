# Shared helpers for the Terraform plan policies.
#
# Input is the JSON produced by `terraform show -json tfplan`. Policies only look
# at `resource_changes`, which lists every resource the plan will touch with its
# planned state in `change.after` and the attributes still unknown at plan time
# in `change.after_unknown`.
package lib.tfplan

import rego.v1

# Resources that the plan will create or update. Deletions and no-ops are
# ignored: a misconfigured resource that is being destroyed is not a finding.
resources contains resource if {
	some resource in input.resource_changes
	some action in resource.change.actions
	action in {"create", "update"}
}

# Planned resources of one Terraform type, e.g. of_type("aws_s3_bucket").
of_type(resource_type) := {resource | some resource in resources; resource.type == resource_type}

# True when an attribute's value is only known after apply (for example a
# reference to another resource's computed id).
unknown(resource, attribute) if {
	resource.change.after_unknown[attribute] == true
}
