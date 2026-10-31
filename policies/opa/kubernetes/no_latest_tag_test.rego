package kubernetes.no_latest_tag

import rego.v1

pod(image) := {"kind": "Pod", "metadata": {"name": "web"}, "spec": {"containers": [{"name": "app", "image": image}]}}

test_explicit_latest_tag_is_denied if {
	result := deny with input as pod("nginx:latest")
	count(result) == 1
}

test_missing_tag_is_denied if {
	result := deny with input as pod("nginx")
	count(result) == 1
}

test_registry_port_without_tag_is_denied if {
	result := deny with input as pod("registry.example:5000/team/app")
	count(result) == 1
}

test_semver_tag_passes if {
	result := deny with input as pod("nginx:1.27.2")
	count(result) == 0
}

test_registry_port_with_tag_passes if {
	result := deny with input as pod("registry.example:5000/team/app:2024.10")
	count(result) == 0
}

test_digest_passes if {
	result := deny with input as pod("nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	count(result) == 0
}

test_init_container_with_latest_is_denied if {
	deployment := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {
			"initContainers": [{"name": "migrate", "image": "northwind/migrate:latest"}],
			"containers": [{"name": "api", "image": "northwind/api:3.1.0"}],
		}}},
	}
	result := deny with input as deployment
	count(result) == 1
	some msg in result
	contains(msg, "migrate")
}
