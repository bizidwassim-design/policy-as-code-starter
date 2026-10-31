package kubernetes.no_hostpath

import rego.v1

pod(volumes) := {"kind": "Pod", "metadata": {"name": "web"}, "spec": {"containers": [{"name": "app"}], "volumes": volumes}}

test_hostpath_volume_is_denied if {
	result := deny with input as pod([{"name": "docker-sock", "hostPath": {"path": "/var/run/docker.sock"}}])
	count(result) == 1
	some msg in result
	contains(msg, "/var/run/docker.sock")
}

test_two_hostpath_volumes_are_denied_twice if {
	result := deny with input as pod([
		{"name": "root", "hostPath": {"path": "/"}},
		{"name": "logs", "hostPath": {"path": "/var/log"}},
	])
	count(result) == 2
}

test_emptydir_and_configmap_pass if {
	result := deny with input as pod([
		{"name": "scratch", "emptyDir": {}},
		{"name": "config", "configMap": {"name": "app-config"}},
	])
	count(result) == 0
}

test_no_volumes_pass if {
	result := deny with input as {"kind": "Pod", "metadata": {"name": "web"}, "spec": {"containers": [{"name": "app"}]}}
	count(result) == 0
}

test_hostpath_in_daemonset_is_denied if {
	daemonset := {
		"kind": "DaemonSet",
		"metadata": {"name": "node-agent"},
		"spec": {"template": {"spec": {
			"containers": [{"name": "agent"}],
			"volumes": [{"name": "proc", "hostPath": {"path": "/proc"}}],
		}}},
	}
	result := deny with input as daemonset
	count(result) == 1
	some msg in result
	contains(msg, "DaemonSet/node-agent")
}
