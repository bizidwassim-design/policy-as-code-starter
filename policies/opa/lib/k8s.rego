# Shared helpers for the Kubernetes policies.
#
# Every Kubernetes policy imports this package so that a rule written once
# against `k8s.containers` covers Pods, Deployments, StatefulSets, DaemonSets,
# Jobs, ReplicaSets and CronJobs alike, including init and ephemeral containers.
package lib.k8s

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "ReplicationController"}

default kind := "<unknown-kind>"

kind := input.kind

default name := "<unnamed>"

name := input.metadata.name

# The PodSpec, wherever the manifest keeps it.
pod_spec := input.spec if {
	input.kind == "Pod"
}

pod_spec := input.spec.template.spec if {
	input.kind in workload_kinds
}

pod_spec := input.spec.jobTemplate.spec.template.spec if {
	input.kind == "CronJob"
}

# All containers of the workload, whatever their role.
containers contains container if {
	some container in pod_spec.containers
}

containers contains container if {
	some container in pod_spec.initContainers
}

containers contains container if {
	some container in pod_spec.ephemeralContainers
}

# Prefix used by every deny message so findings can be grouped per object.
object_ref := sprintf("%s/%s", [kind, name])
