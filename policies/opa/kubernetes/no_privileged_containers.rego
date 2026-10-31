# Policy: no privileged containers
#
# Containers must not run with `securityContext.privileged: true` and must not
# allow privilege escalation. A privileged container has the host's device and
# kernel access; one escape and the node is gone.
#
# Controls: CIS Kubernetes Benchmark 5.2.1 and 5.2.5 · ISO/IEC 27001:2022 A.8.9 ·
# NIST CSF 2.0 PR.PS-01
package kubernetes.no_privileged_containers

import rego.v1

import data.lib.k8s

deny contains msg if {
	some container in k8s.containers
	container.securityContext.privileged == true
	msg := sprintf("%s: container %q must not run privileged (securityContext.privileged=true)", [k8s.object_ref, container.name])
}

deny contains msg if {
	some container in k8s.containers
	container.securityContext.allowPrivilegeEscalation == true
	msg := sprintf("%s: container %q must not allow privilege escalation (securityContext.allowPrivilegeEscalation=true)", [k8s.object_ref, container.name])
}
