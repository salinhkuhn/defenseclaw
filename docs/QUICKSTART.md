# Quick Start Guide

Get DefenseClaw running in under 5 minutes.

## Prerequisites

- **Go 1.22+** — to build from source
- **Python 3.11+** — for scanner dependencies
- **[uv](https://docs.astral.sh/uv/)** (recommended) or pip

## 1. Build

```bash
git clone https://github.com/defenseclaw/defenseclaw.git
cd defenseclaw
make build
```

For DGX Spark (linux/arm64):

```bash
make build-linux-arm64
scp defenseclaw-linux-arm64 spark:/usr/local/bin/defenseclaw
```

## 2. Initialize

```bash
defenseclaw init
```

This creates `~/.defenseclaw/` with:
- `config.yaml` — scanner paths, policy settings
- `audit.db` — SQLite audit log
- `quarantine/` — blocked skill storage
- `plugins/` — custom scanner plugins
- `policies/` — OpenShell policy files

Scanner dependencies are installed automatically during init.
Use `--skip-install` to skip this step.

## 3. First Scan

```bash
# Scan a skill
defenseclaw scan skill ./path/to/skill/

# Scan an MCP server
defenseclaw scan mcp https://mcp-server.example.com

# Generate AI bill of materials
defenseclaw scan aibom .

# Run all scanners against current directory
defenseclaw scan
```

## 4. Block/Allow Enforcement

```bash
# Block a skill (quarantines files + updates sandbox policy)
defenseclaw block skill ./malicious-skill --reason "exfil pattern"

# Block an MCP server (adds to network deny-list)
defenseclaw block mcp https://shady.example.com --reason "hidden instructions"

# View what's blocked
defenseclaw list blocked

# Allow a previously blocked skill (re-scans first, rejects if still HIGH/CRITICAL)
defenseclaw allow skill ./malicious-skill

# Allow without re-scanning
defenseclaw allow skill ./malicious-skill --skip-rescan --reason "manually verified"

# View allow list
defenseclaw list allowed

# Emergency quarantine (block + move files in one step)
defenseclaw quarantine ./risky-skill
```

## 5. Audit Log

```bash
# View recent audit events
defenseclaw audit

# Show more events
defenseclaw audit -n 50
```

Every action (scan, block, allow, quarantine, init) is logged.

## 6. Next Steps

- `defenseclaw tui` — open the dashboard (iteration 3)
- `defenseclaw deploy` — full orchestrated deploy (iteration 4)

See [CLI Reference](CLI.md) for all commands.
