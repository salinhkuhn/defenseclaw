package defenseclaw.firewall_test

import rego.v1

import data.defenseclaw.firewall

# --- Blocked destination ---

test_blocked_destination if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "169.254.169.254",
		"port": 80,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": ["169.254.169.254"],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443, 80],
		}

	result.action == "deny"
}

# --- Allowed domain + port ---

test_allowed_domain_and_port if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "api.github.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": ["169.254.169.254"],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443],
		}

	result.action == "allow"
	result.rule_name == "domain-allowlist"
}

# --- Domain allowed but port restricted ---

test_allowed_domain_wrong_port if {
	result := firewall with input as {
		"target_type": "mcp",
		"destination": "api.github.com",
		"port": 8080,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": [],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443],
		}

	result.action == "deny"
	result.rule_name == "port-restricted"
}

# --- Unknown domain: default deny ---

test_unknown_domain_deny if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "evil.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": [],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443],
		}

	result.action == "deny"
}

# --- Default allow policy ---

test_default_allow_policy if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "anywhere.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "allow",
			"blocked_destinations": ["169.254.169.254"],
			"allowed_domains": [],
			"allowed_ports": [],
		}

	result.action == "allow"
}

# --- Empty allowed_ports means all ports allowed ---

test_empty_ports_allows_all if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "api.github.com",
		"port": 9999,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": [],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [],
		}

	result.action == "allow"
}
