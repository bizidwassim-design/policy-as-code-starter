package kubernetes.no_privileged_containers

import rego.v1

pod(containers) := {"kind": "Pod", "metadata": {"name": "web"}, "spec": {"containers": containers}}

test_privileged_container_is_denied if {
	result := deny with input as pod([{"name": "app", "securityContext": {"privileged": true}}])
	count(result) == 1
	some msg in result
	contains(msg, "Pod/web")
	contains(msg, "privileged")
}

test_privilege_escalation_is_denied if {
	result := deny with input as pod([{"name": "app", "securityContext": {"allowPrivilegeEscalation": true}}])
	count(result) == 1
}

test_unprivileged_container_passes if {
	result := deny with input as pod([{"name": "app", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false}}])
	count(result) == 0
}

test_container_without_security_context_passes if {
	result := deny with input as pod([{"name": "app"}])
	count(result) == 0
}

test_privileged_init_container_in_deployment_is_denied if {
	deployment := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {
			"initContainers": [{"name": "setup", "securityContext": {"privileged": true}}],
			"containers": [{"name": "api"}],
		}}},
	}
	result := deny with input as deployment
	count(result) == 1
	some msg in result
	contains(msg, "Deployment/api")
	contains(msg, "setup")
}

test_privileged_container_in_cronjob_is_denied if {
	cronjob := {
		"kind": "CronJob",
		"metadata": {"name": "nightly"},
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "job", "securityContext": {"privileged": true}}]}}}}},
	}
	result := deny with input as cronjob
	count(result) == 1
}
