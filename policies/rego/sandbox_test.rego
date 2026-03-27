package defenseclaw.sandbox_test

import rego.v1

import data.defenseclaw.sandbox

test_allowed_endpoints_filter_denied if {
	result := sandbox with input as {
		"skill_name": "my-skill",
		"requested_endpoints": ["api.github.com", "169.254.169.254", "safe.example.com"],
		"requested_permissions": ["read"],
	}
		with data.sandbox as {
			"default_permissions": ["network"],
			"denied_endpoints_global": ["169.254.169.254"],
		}
		with data.firewall as {
			"blocked_destinations": ["10.0.0.1"],
		}

	"api.github.com" in result.allowed_endpoints
	"safe.example.com" in result.allowed_endpoints
	not "169.254.169.254" in result.allowed_endpoints
}

test_denied_from_request if {
	result := sandbox with input as {
		"skill_name": "my-skill",
		"requested_endpoints": ["169.254.169.254", "10.0.0.1"],
		"requested_permissions": [],
	}
		with data.sandbox as {
			"default_permissions": [],
			"denied_endpoints_global": ["169.254.169.254"],
		}
		with data.firewall as {
			"blocked_destinations": ["10.0.0.1"],
		}

	"169.254.169.254" in result.denied_from_request
	"10.0.0.1" in result.denied_from_request
}

test_permissions_merged if {
	result := sandbox with input as {
		"skill_name": "my-skill",
		"requested_endpoints": [],
		"requested_permissions": ["write", "execute"],
	}
		with data.sandbox as {
			"default_permissions": ["read", "network"],
			"denied_endpoints_global": [],
		}
		with data.firewall as {
			"blocked_destinations": [],
		}

	"read" in result.permissions
	"network" in result.permissions
	"write" in result.permissions
	"execute" in result.permissions
}

test_skill_always_allowed if {
	result := sandbox with input as {
		"skill_name": "my-special-skill",
		"requested_endpoints": [],
		"requested_permissions": [],
	}
		with data.sandbox as {
			"default_permissions": [],
			"denied_endpoints_global": [],
		}
		with data.firewall as {
			"blocked_destinations": [],
		}

	"my-special-skill" in result.allowed_skills
}
