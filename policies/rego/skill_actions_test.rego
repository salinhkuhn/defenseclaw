package defenseclaw.skill_actions_test

import rego.v1

import data.defenseclaw.skill_actions

# --- Basic severity mapping ---

test_critical_blocks if {
	result := skill_actions with input as {"severity": "CRITICAL"}
		with data.actions as {"CRITICAL": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {}

	result.runtime_action == "block"
	result.file_action == "quarantine"
	result.install_action == "block"
	result.should_block
	result.should_quarantine
	result.should_block_install
}

test_low_allows if {
	result := skill_actions with input as {"severity": "LOW"}
		with data.actions as {"LOW": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {}

	result.runtime_action == "allow"
	result.file_action == "none"
	result.install_action == "none"
	not result.should_block
	not result.should_quarantine
	not result.should_block_install
}

# --- Scanner-type override ---

test_mcp_override_blocks_medium if {
	result := skill_actions with input as {"severity": "MEDIUM", "target_type": "mcp"}
		with data.actions as {"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {
			"mcp": {"MEDIUM": {"runtime": "block", "file": "quarantine", "install": "block"}},
		}

	result.runtime_action == "block"
	result.file_action == "quarantine"
	result.install_action == "block"
	result.should_block
}

test_skill_uses_global_when_no_override if {
	result := skill_actions with input as {"severity": "MEDIUM", "target_type": "skill"}
		with data.actions as {"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {
			"mcp": {"MEDIUM": {"runtime": "block", "file": "quarantine", "install": "block"}},
		}

	result.runtime_action == "allow"
	not result.should_block
}

test_plugin_override if {
	result := skill_actions with input as {"severity": "HIGH", "target_type": "plugin"}
		with data.actions as {"HIGH": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {
			"plugin": {"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"}},
		}

	result.runtime_action == "block"
	result.should_block
}

# --- No target_type (backward compat) ---

test_no_target_type_uses_global if {
	result := skill_actions with input as {"severity": "HIGH"}
		with data.actions as {"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {
			"mcp": {"HIGH": {"runtime": "allow", "file": "none", "install": "none"}},
		}

	result.runtime_action == "block"
	result.should_block
}
