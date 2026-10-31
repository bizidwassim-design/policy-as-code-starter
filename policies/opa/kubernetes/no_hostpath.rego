# Policy: no hostPath volumes
#
# Workloads must not mount directories from the node. A hostPath volume is a
# read (and often write) path into the node's filesystem, container runtime
# socket or kubelet credentials.
#
# Controls: CIS Kubernetes Benchmark 5.2.11 · ISO/IEC 27001:2022 A.8.9 ·
# NIST CSF 2.0 PR.PS-01
package kubernetes.no_hostpath

import rego.v1

import data.lib.k8s

deny contains msg if {
	some volume in k8s.pod_spec.volumes
	volume.hostPath
	msg := sprintf("%s: volume %q mounts hostPath %q from the node", [k8s.object_ref, volume.name, volume.hostPath.path])
}
