package defenseclaw.skill_actions

import rego.v1

# Maps a severity level to runtime, file, and install actions.
# Supports per-scanner-type overrides via data.scanner_overrides.
#
# Input fields:
#   severity    - "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INFO"
#   target_type - optional "skill", "mcp", or "plugin" for scanner-specific lookup
#
# Static data (data.json):
#   actions.<SEVERITY>.runtime              - "block" or "allow"
#   actions.<SEVERITY>.file                 - "quarantine" or "none"
#   actions.<SEVERITY>.install              - "block", "allow", or "none"
#   scanner_overrides.<TYPE>.<SEVERITY>.*   - per-scanner overrides

default runtime_action := "allow"

default file_action := "none"

default install_action := "none"

# Resolve effective action: scanner override > global
_effective := action if {
	input.target_type
	action := data.scanner_overrides[input.target_type][input.severity]
} else := action if {
	action := data.actions[input.severity]
}

runtime_action := action if {
	action := _effective.runtime
}

file_action := action if {
	action := _effective.file
}

install_action := action if {
	action := _effective.install
}

should_block if {
	runtime_action == "block"
}

should_quarantine if {
	file_action == "quarantine"
}

should_block_install if {
	install_action == "block"
}
