# Policy: required labels
#
# Every object must carry the labels the platform team relies on for
# ownership, cost allocation and incident routing. `environment` must be one
# of the known values so that environment-scoped policies can key on it.
#
# Controls: ISO/IEC 27001:2022 A.5.9 and A.8.9 · NIST CSF 2.0 ID.AM-01 · ID.AM-02
package kubernetes.required_labels

import rego.v1

import data.lib.k8s

required_labels := {"app.kubernetes.io/name", "owner", "environment"}

allowed_environments := {"dev", "test", "staging", "prod"}

deny contains msg if {
	some label in required_labels
	not has_label(label)
	msg := sprintf("%s: missing required label %q", [k8s.object_ref, label])
}

# A label counts as present only when it has a non-empty value.
has_label(label) if {
	value := input.metadata.labels[label]
	value != ""
}

deny contains msg if {
	environment := input.metadata.labels.environment
	not environment in allowed_environments
	msg := sprintf("%s: label environment=%q is not one of %v", [k8s.object_ref, environment, sort(allowed_environments)])
}
