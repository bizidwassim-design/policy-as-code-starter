package kubernetes.resource_limits_required

import rego.v1

pod(resources) := {"kind": "Pod", "metadata": {"name": "web"}, "spec": {"containers": [{"name": "app", "resources": resources}]}}

full_resources := {
	"limits": {"cpu": "500m", "memory": "256Mi"},
	"requests": {"cpu": "100m", "memory": "128Mi"},
}

test_full_resources_pass if {
	result := deny with input as pod(full_resources)
	count(result) == 0
}

test_no_resources_block_is_denied_four_times if {
	result := deny with input as {"kind": "Pod", "metadata": {"name": "web"}, "spec": {"containers": [{"name": "app"}]}}
	count(result) == 4
}

test_missing_memory_limit_is_denied if {
	result := deny with input as pod({
		"limits": {"cpu": "500m"},
		"requests": {"cpu": "100m", "memory": "128Mi"},
	})
	count(result) == 1
	some msg in result
	contains(msg, "memory limit")
}

test_missing_requests_are_denied if {
	result := deny with input as pod({"limits": {"cpu": "500m", "memory": "256Mi"}})
	count(result) == 2
}

test_sidecar_without_limits_is_denied if {
	deployment := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"containers": [
			{"name": "api", "resources": full_resources},
			{"name": "log-shipper"},
		]}}},
	}
	result := deny with input as deployment
	count(result) == 4
	every msg in result {
		contains(msg, "log-shipper")
	}
}
