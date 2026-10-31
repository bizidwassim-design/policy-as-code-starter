package kubernetes.required_labels

import rego.v1

deployment(labels) := {"kind": "Deployment", "metadata": {"name": "api", "labels": labels}, "spec": {"template": {"spec": {"containers": [{"name": "api"}]}}}}

good_labels := {"app.kubernetes.io/name": "api", "owner": "platform-team", "environment": "prod"}

test_all_labels_present_pass if {
	result := deny with input as deployment(good_labels)
	count(result) == 0
}

test_no_labels_at_all_is_denied_three_times if {
	result := deny with input as {"kind": "Deployment", "metadata": {"name": "api"}}
	count(result) == 3
}

test_missing_owner_is_denied if {
	result := deny with input as deployment({"app.kubernetes.io/name": "api", "environment": "prod"})
	count(result) == 1
	some msg in result
	contains(msg, "\"owner\"")
}

test_unknown_environment_is_denied if {
	result := deny with input as deployment({"app.kubernetes.io/name": "api", "owner": "platform-team", "environment": "production"})
	count(result) == 1
	some msg in result
	contains(msg, "environment=\"production\"")
}

test_empty_label_value_counts_as_missing if {
	result := deny with input as deployment({"app.kubernetes.io/name": "api", "owner": "", "environment": "dev"})
	count(result) == 1
}
