# DefenseClaw

Enterprise governance layer for [OpenClaw](https://github.com/nvidia/openclaw). Scans skills, MCP servers, and code before they run. Enforces block/allow lists. Provides a terminal dashboard for security operators.

## Quick Start

```bash
# Install (coming soon)
curl -sSf https://get.defenseclaw.dev | sh

# Initialize
defenseclaw init

# Scan a skill
defenseclaw scan skill ./path/to/skill

# Open the dashboard
defenseclaw tui
```

## What It Does

- **Scan before run** — skills, MCP servers, A2A agents, code, AI dependencies
- **Block/allow lists** — operator-managed enforcement for skills and MCP servers
- **Terminal dashboard** — scan findings, policy violations, enforcement actions
- **Audit trail** — every action logged to SQLite with timestamps and context

## Scanner Dependencies

DefenseClaw wraps four open-source security projects as its scanning engines. Install them before running scans.

### Prerequisites

- **Python 3.11+**
- **[uv](https://docs.astral.sh/uv/)** (recommended) or pip

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Skill Scanner

[cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) — Security scanner for AI Agent Skills. Detects prompt injection, data exfiltration, and malicious code patterns using pattern-based detection (YAML + YARA), LLM-as-a-judge, and behavioral dataflow analysis.

```bash
# Using uv (recommended)
uv pip install cisco-ai-skill-scanner

# Using pip
pip install cisco-ai-skill-scanner

# Verify
skill-scanner --help
```

Optional LLM analyzer setup:

```bash
export SKILL_SCANNER_LLM_API_KEY="your_api_key"
export SKILL_SCANNER_LLM_MODEL="claude-3-5-sonnet-20241022"
```

### MCP Scanner

[cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) — Scans MCP servers and tools for security findings. Combines Cisco AI Defense inspect API, YARA rules, and LLM-as-a-judge to detect malicious MCP tools.

```bash
# Using uv (recommended)
uv tool install --python 3.13 cisco-ai-mcp-scanner

# From source
uv tool install --python 3.13 --from git+https://github.com/cisco-ai-defense/mcp-scanner cisco-ai-mcp-scanner

# Verify
mcp-scanner --help
```

Optional API and LLM setup:

```bash
# Cisco AI Defense API (for API analyzer)
export MCP_SCANNER_API_KEY="your_cisco_api_key"

# LLM analyzer
export MCP_SCANNER_LLM_API_KEY="your_llm_api_key"
export MCP_SCANNER_LLM_MODEL="gpt-4o"
```

### AI BOM

[cisco-ai-defense/aibom](https://github.com/cisco-ai-defense/aibom) — Scans codebases and container images to inventory AI framework components (models, agents, tools, prompts). Produces an AI bill of materials.

```bash
# Using uv (recommended)
uv tool install --python 3.13 cisco-aibom

# From source
uv tool install --python 3.13 --from git+https://github.com/cisco-ai-defense/aibom cisco-aibom

# Verify
cisco-aibom --help
```

AI BOM requires a DuckDB catalog. Download it from the [releases page](https://github.com/cisco-ai-defense/aibom/releases):

```bash
VERSION="0.5.1"  # use the latest release tag
mkdir -p ~/.aibom/catalogs

curl -fL \
  -o ~/.aibom/catalogs/aibom_catalog-${VERSION}.duckdb \
  "https://github.com/cisco-ai-defense/aibom/releases/download/${VERSION}/aibom_catalog-${VERSION}.duckdb"

export AIBOM_DB_PATH=~/.aibom/catalogs/aibom_catalog-${VERSION}.duckdb
```

### Project CodeGuard

[cosai-oasis/project-codeguard](https://github.com/cosai-oasis/project-codeguard) — Model-agnostic security framework from the Coalition for Secure AI (CoSAI). Provides security rules that guide AI assistants to generate more secure code automatically.

CodeGuard is not a CLI tool — it ships as security rules and skills in markdown format. Download the latest release and place the rules in your project:

```bash
# Download the latest release
curl -fL -o codeguard-rules.zip \
  "https://github.com/cosai-oasis/project-codeguard/releases/latest/download/codeguard-rules.zip"

# Extract into your project or DefenseClaw policies directory
unzip codeguard-rules.zip -d ~/.defenseclaw/codeguard-rules/
```

Or clone the repository directly:

```bash
git clone https://github.com/cosai-oasis/project-codeguard.git ~/.defenseclaw/codeguard-rules
```

See the [Project CodeGuard getting started guide](https://project-codeguard.org/getting-started/) for detailed integration instructions.

### Quick Install (All Scanners)

The bundled script installs all Python scanner dependencies at once:

```bash
bash scripts/setup-scanners.sh
```

## Documentation

- [Quick Start Guide](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [CLI Reference](docs/CLI.md)
- [TUI Guide](docs/TUI.md)
- [Plugin Development](docs/PLUGINS.md)
- [Testing](docs/TESTING.md)
- [Contributing](docs/CONTRIBUTING.md)

## Building from Source

```bash
make build              # Current platform
make build-linux-arm64  # DGX Spark
make build-darwin-arm64 # Apple Silicon
make test               # Run tests
```

Requires Go 1.22+.

## License

Apache 2.0 — see [LICENSE](LICENSE).
