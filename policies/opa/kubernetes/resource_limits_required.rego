# Policy: resource limits required
#
# Every container must declare CPU and memory limits and requests. Without
# limits a single workload can starve the node; without requests the scheduler
# cannot place it safely.
#
# Controls: ISO/IEC 27001:2022 A.8.6 and A.8.9 · NIST CSF 2.0 PR.PS-01 · PR.IR-04
package kubernetes.resource_limits_required

import rego.v1

import data.lib.k8s

resource_names := {"cpu", "memory"}

deny contains msg if {
	some container in k8s.containers
	some resource in resource_names
	not container.resources.limits[resource]
	msg := sprintf("%s: container %q has no %s limit (resources.limits.%s)", [k8s.object_ref, container.name, resource, resource])
}

deny contains msg if {
	some container in k8s.containers
	some resource in resource_names
	not container.resources.requests[resource]
	msg := sprintf("%s: container %q has no %s request (resources.requests.%s)", [k8s.object_ref, container.name, resource, resource])
}
