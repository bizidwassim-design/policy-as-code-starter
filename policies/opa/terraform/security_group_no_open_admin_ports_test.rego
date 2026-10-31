package terraform.security_group_no_open_admin_ports

import rego.v1

plan(resources) := {"resource_changes": resources}

resource(address, resource_type, after) := {
	"address": address,
	"type": resource_type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

ingress(from_port, to_port, protocol, cidr_blocks) := {
	"from_port": from_port,
	"to_port": to_port,
	"protocol": protocol,
	"cidr_blocks": cidr_blocks,
	"ipv6_cidr_blocks": [],
}

security_group(rules) := resource("aws_security_group.web", "aws_security_group", {"name": "web", "ingress": rules})

test_https_from_internet_passes if {
	result := deny with input as plan([security_group([ingress(443, 443, "tcp", ["0.0.0.0/0"])])])
	count(result) == 0
}

test_ssh_from_private_range_passes if {
	result := deny with input as plan([security_group([ingress(22, 22, "tcp", ["10.0.0.0/8"])])])
	count(result) == 0
}

test_ssh_from_internet_is_denied if {
	result := deny with input as plan([security_group([ingress(22, 22, "tcp", ["0.0.0.0/0"])])])
	count(result) == 1
	some msg in result
	contains(msg, "aws_security_group.web")
}

test_port_range_covering_rdp_is_denied if {
	result := deny with input as plan([security_group([ingress(3000, 4000, "tcp", ["0.0.0.0/0"])])])
	count(result) == 1
}

test_all_traffic_from_internet_is_denied if {
	result := deny with input as plan([security_group([ingress(0, 0, "-1", ["0.0.0.0/0"])])])
	count(result) == 1
}

test_ssh_from_ipv6_internet_is_denied if {
	rule := {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}
	result := deny with input as plan([security_group([rule])])
	count(result) == 1
}

test_standalone_rdp_rule_from_internet_is_denied if {
	rule := resource("aws_security_group_rule.rdp", "aws_security_group_rule", {
		"type": "ingress",
		"from_port": 3389,
		"to_port": 3389,
		"protocol": "tcp",
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": null,
	})
	result := deny with input as plan([rule])
	count(result) == 1
}

test_standalone_egress_rule_is_ignored if {
	rule := resource("aws_security_group_rule.out", "aws_security_group_rule", {
		"type": "egress",
		"from_port": 0,
		"to_port": 0,
		"protocol": "-1",
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": null,
	})
	result := deny with input as plan([rule])
	count(result) == 0
}

test_vpc_ingress_rule_all_protocols_from_internet_is_denied if {
	rule := resource("aws_vpc_security_group_ingress_rule.any", "aws_vpc_security_group_ingress_rule", {
		"cidr_ipv4": "0.0.0.0/0",
		"cidr_ipv6": null,
		"ip_protocol": "-1",
		"from_port": null,
		"to_port": null,
	})
	result := deny with input as plan([rule])
	count(result) == 1
}

test_vpc_ingress_rule_https_from_internet_passes if {
	rule := resource("aws_vpc_security_group_ingress_rule.https", "aws_vpc_security_group_ingress_rule", {
		"cidr_ipv4": "0.0.0.0/0",
		"cidr_ipv6": null,
		"ip_protocol": "tcp",
		"from_port": 443,
		"to_port": 443,
	})
	result := deny with input as plan([rule])
	count(result) == 0
}

nsg_rule(name, source, port_range) := resource(sprintf("azurerm_network_security_rule.%s", [name]), "azurerm_network_security_rule", {
	"name": name,
	"direction": "Inbound",
	"access": "Allow",
	"source_address_prefix": source,
	"source_address_prefixes": [],
	"destination_port_range": port_range,
	"destination_port_ranges": [],
})

test_azure_ssh_from_any_is_denied if {
	result := deny with input as plan([nsg_rule("ssh", "*", "22")])
	count(result) == 1
}

test_azure_rdp_from_internet_tag_is_denied if {
	result := deny with input as plan([nsg_rule("rdp", "Internet", "3389")])
	count(result) == 1
}

test_azure_range_covering_ssh_is_denied if {
	result := deny with input as plan([nsg_rule("mgmt", "0.0.0.0/0", "20-30")])
	count(result) == 1
}

test_azure_wildcard_port_from_internet_is_denied if {
	result := deny with input as plan([nsg_rule("any", "*", "*")])
	count(result) == 1
}

test_azure_https_from_internet_passes if {
	result := deny with input as plan([nsg_rule("https", "Internet", "443")])
	count(result) == 0
}

test_azure_ssh_from_corporate_range_passes if {
	result := deny with input as plan([nsg_rule("ssh", "10.20.0.0/16", "22")])
	count(result) == 0
}

test_azure_deny_rule_is_ignored if {
	rule := resource("azurerm_network_security_rule.block", "azurerm_network_security_rule", {
		"name": "block-ssh",
		"direction": "Inbound",
		"access": "Deny",
		"source_address_prefix": "*",
		"source_address_prefixes": [],
		"destination_port_range": "22",
		"destination_port_ranges": [],
	})
	result := deny with input as plan([rule])
	count(result) == 0
}

test_azure_prefix_and_port_lists_are_checked if {
	rule := resource("azurerm_network_security_rule.lists", "azurerm_network_security_rule", {
		"name": "lists",
		"direction": "Inbound",
		"access": "Allow",
		"source_address_prefix": null,
		"source_address_prefixes": ["10.0.0.0/8", "0.0.0.0/0"],
		"destination_port_range": null,
		"destination_port_ranges": ["8080", "3389"],
	})
	result := deny with input as plan([rule])
	count(result) == 1
}

test_azure_inline_security_rule_is_denied if {
	group := resource("azurerm_network_security_group.web", "azurerm_network_security_group", {"security_rule": [{
		"name": "allow-ssh",
		"direction": "Inbound",
		"access": "Allow",
		"source_address_prefix": "Internet",
		"source_address_prefixes": [],
		"destination_port_range": "22",
		"destination_port_ranges": [],
	}]})
	result := deny with input as plan([group])
	count(result) == 1
	some msg in result
	contains(msg, "allow-ssh")
}
