# Policy: security groups must not expose admin ports to the internet
#
# No inbound rule may allow SSH (22) or RDP (3389) from 0.0.0.0/0, ::/0 or the
# Azure "Internet" / "*" sources. Covers AWS security groups (inline ingress
# blocks, aws_security_group_rule, aws_vpc_security_group_ingress_rule) and
# Azure network security groups (azurerm_network_security_rule and inline
# security_rule blocks).
#
# Controls: CIS AWS Foundations Benchmark 5.2 and 5.3 · CIS Azure Foundations Benchmark 6.1 and 6.2 ·
# ISO/IEC 27001:2022 A.8.20 and A.8.22 · NIST CSF 2.0 PR.IR-01
package terraform.security_group_no_open_admin_ports

import rego.v1

import data.lib.tfplan

admin_ports := {22, 3389}

anywhere_ipv4 := "0.0.0.0/0"

anywhere_ipv6 := "::/0"

azure_anywhere := {"*", "0.0.0.0/0", "0.0.0.0", "::/0", "Internet"}

# --- AWS -------------------------------------------------------------------

deny contains msg if {
	some group in tfplan.of_type("aws_security_group")
	some rule in group.change.after.ingress
	open_to_internet(rule)
	aws_rule_covers_admin_port(rule)
	msg := sprintf("%s: inline ingress rule (%v-%v/%v) allows an admin port from the internet", [group.address, rule.from_port, rule.to_port, rule.protocol])
}

deny contains msg if {
	some rule in tfplan.of_type("aws_security_group_rule")
	rule.change.after.type == "ingress"
	open_to_internet(rule.change.after)
	aws_rule_covers_admin_port(rule.change.after)
	msg := sprintf("%s: ingress rule (%v-%v/%v) allows an admin port from the internet", [rule.address, rule.change.after.from_port, rule.change.after.to_port, rule.change.after.protocol])
}

deny contains msg if {
	some rule in tfplan.of_type("aws_vpc_security_group_ingress_rule")
	open_to_internet(rule.change.after)
	aws_rule_covers_admin_port(rule.change.after)
	msg := sprintf("%s: ingress rule (%v-%v/%v) allows an admin port from the internet", [rule.address, rule.change.after.from_port, rule.change.after.to_port, rule.change.after.ip_protocol])
}

# Accepts the three AWS rule shapes: cidr_blocks / ipv6_cidr_blocks lists and
# the single cidr_ipv4 / cidr_ipv6 attributes.
open_to_internet(rule) if {
	anywhere_ipv4 in rule.cidr_blocks
}

open_to_internet(rule) if {
	anywhere_ipv6 in rule.ipv6_cidr_blocks
}

open_to_internet(rule) if {
	rule.cidr_ipv4 == anywhere_ipv4
}

open_to_internet(rule) if {
	rule.cidr_ipv6 == anywhere_ipv6
}

# Protocol -1 means every port.
aws_rule_covers_admin_port(rule) if {
	rule.protocol == "-1"
}

aws_rule_covers_admin_port(rule) if {
	rule.ip_protocol == "-1"
}

aws_rule_covers_admin_port(rule) if {
	some port in admin_ports
	rule.from_port <= port
	port <= rule.to_port
}

# --- Azure -----------------------------------------------------------------

deny contains msg if {
	some rule in tfplan.of_type("azurerm_network_security_rule")
	azure_rule_is_open_admin(rule.change.after)
	msg := sprintf("%s: NSG rule %q allows an admin port inbound from the internet", [rule.address, rule.change.after.name])
}

deny contains msg if {
	some group in tfplan.of_type("azurerm_network_security_group")
	some rule in group.change.after.security_rule
	azure_rule_is_open_admin(rule)
	msg := sprintf("%s: inline security rule %q allows an admin port inbound from the internet", [group.address, rule.name])
}

azure_rule_is_open_admin(rule) if {
	rule.direction == "Inbound"
	rule.access == "Allow"
	azure_source_is_internet(rule)
	azure_rule_covers_admin_port(rule)
}

azure_source_is_internet(rule) if {
	rule.source_address_prefix in azure_anywhere
}

azure_source_is_internet(rule) if {
	some prefix in rule.source_address_prefixes
	prefix in azure_anywhere
}

azure_rule_covers_admin_port(rule) if {
	azure_range_covers_admin_port(rule.destination_port_range)
}

azure_rule_covers_admin_port(rule) if {
	some port_range in rule.destination_port_ranges
	azure_range_covers_admin_port(port_range)
}

# Azure port ranges are strings: "*", "22" or "20-30".
azure_range_covers_admin_port(port_range) if {
	port_range == "*"
}

azure_range_covers_admin_port(port_range) if {
	is_string(port_range)
	regex.match(`^[0-9]+$`, port_range)
	to_number(port_range) in admin_ports
}

azure_range_covers_admin_port(port_range) if {
	is_string(port_range)
	regex.match(`^[0-9]+-[0-9]+$`, port_range)
	bounds := split(port_range, "-")
	some port in admin_ports
	to_number(bounds[0]) <= port
	port <= to_number(bounds[1])
}
