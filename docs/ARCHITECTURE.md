# Architecture

DefenseClaw is a governance layer for OpenClaw. It orchestrates scanning,
enforcement, and auditing across existing tools without replacing any component.

## System Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           DefenseClaw System                                │
│                                                                              │
│  ┌─────────────────────┐       ┌─────────────────────────────────────────┐  │
│  │   CLI (Python)       │       │   Plugins / Hooks (JS/TS)              │  │
│  │                      │       │                                         │  │
│  │  skill-scanner       │       │  OpenClaw plugin lifecycle hooks        │  │
│  │  mcp-scanner         │       │  registerService, registerCommand       │  │
│  │  aibom               │       │  api.on("gateway_start"), etc.          │  │
│  │  codeguard            │       │  before_tool_call, exec.approval       │  │
│  │  [custom scanners]   │       │                                         │  │
│  │                      │       │  Registers hooks in OpenClaw for:       │  │
│  │  Writes scan results │       │    - skill install/uninstall             │  │
│  │  directly to DB      │       │    - MCP server connect/disconnect      │  │
│  │                      │       │    - tool call interception             │  │
│  └──────────┬───────────┘       └──────────────┬──────────────────────────┘  │
│             │ REST API                          │ REST API                    │
│             │                                   │                            │
│             ▼                                   ▼                            │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                  Orchestrator (Go daemon)                            │    │
│  │                                                                      │    │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌────────────────┐   │    │
│  │  │  REST API   │  │  Audit /   │  │ Policy   │  │  OpenClaw WS   │   │    │
│  │  │  Server     │  │  SIEM      │  │ Engine   │  │  Client        │   │    │
│  │  │            │  │  Emitter   │  │          │  │                │   │    │
│  │  │ Accepts    │  │            │  │ Block /  │  │ Connects via   │   │    │
│  │  │ requests   │  │ Splunk HEC │  │ Allow /  │  │ WS protocol v3 │   │    │
│  │  │ from CLI   │  │ JSON/CSV   │  │ Scan     │  │                │   │    │
│  │  │ & plugins  │  │ export     │  │ gate     │  │ Subscribes to  │   │    │
│  │  └────────────┘  └────────────┘  └──────────┘  │ all events,    │   │    │
│  │                                                 │ sends commands │   │    │
│  │  ┌──────────────────────┐  ┌──────────────┐    └───────┬────────┘   │    │
│  │  │  SQLite DB            │  │  LiteLLM     │            │           │    │
│  │  │                      │  │  Process Mgr │            │           │    │
│  │  │  Audit events        │  │              │            │           │    │
│  │  │  Scan results        │  │  Spawns and  │            │           │    │
│  │  │  Block/allow lists   │  │  supervises  │            │           │    │
│  │  │  Skill inventory     │  │  LiteLLM     │            │           │    │
│  │  └──────────────────────┘  └──────┬───────┘            │           │    │
│  └───────────────────────────────────┼────────────────────┼───────────┘    │
│                                       │                    │                │
│             ┌─────────────────────────┘                    │                │
│             │ child process                                │                │
│             ▼                                              │                │
│  ┌──────────────────────────────────┐                      │                │
│  │  LiteLLM Proxy (port 4000)       │                      │                │
│  │                                  │                      │                │
│  │  ┌────────────────────────────┐  │                      │                │
│  │  │  DefenseClaw Guardrail     │  │                      │                │
│  │  │  (Python module)           │  │                      │                │
│  │  │                            │  │                      │                │
│  │  │  pre_call:  prompt scan    │  │                      │                │
│  │  │  post_call: response scan  │  │                      │                │
│  │  │  mode: observe | action    │  │                      │                │
│  │  └────────────────────────────┘  │                      │                │
│  └──────────┬───────────────────────┘                      │                │
│             │ proxied LLM API calls                        │                │
│             ▼                                              │                │
│  ┌──────────────────────┐    WebSocket (events + RPC)      │                │
│  │  LLM Provider        │◄────────────────────────────────┘                │
│  │  (Anthropic, OpenAI, │                                                  │
│  │   Google, etc.)      │                                                  │
│  └──────────────────────┘                                                  │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                      OpenClaw Gateway                                │    │
│  │                                                                      │    │
│  │   Events emitted:                  Commands accepted:                │    │
│  │     tool_call                        exec.approval.resolve           │    │
│  │     tool_result                      skills.update (enable/disable)  │    │
│  │     exec.approval.requested          config.patch                    │    │
│  │     skill.install / uninstall        [future: mcp.disconnect]        │    │
│  │     mcp.connect / disconnect                                         │    │
│  │                                                                      │    │
│  │   LLM traffic routed through LiteLLM proxy via openclaw.json        │    │
│  │   provider config (baseUrl → http://localhost:4000)                  │    │
│  └──────────────────────────┬───────────────────────────────────────────┘    │
│                              │                                               │
│                              ▼                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                   NVIDIA OpenShell Sandbox                           │    │
│  │                                                                      │    │
│  │   OpenClaw runtime executes inside sandbox                           │    │
│  │   Kernel-level isolation: filesystem, network, process               │    │
│  │   Policy YAML controls permissions                                   │    │
│  │                                                                      │    │
│  │   ┌────────────────────────────────────────────┐                     │    │
│  │   │  OpenClaw Agent Runtime                    │                     │    │
│  │   │    Skills, MCP servers, LLM interactions   │                     │    │
│  │   └────────────────────────────────────────────┘                     │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│                              ┌──────────────────┐                            │
│                              │  SIEM / SOAR      │                            │
│                              │  (Splunk, etc.)   │                            │
│                              └──────────────────┘                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### 1. CLI (Python)

The CLI is the operator-facing tool for running security scans and managing
policy. It shells out to Python scanner CLIs and writes results directly to
the shared SQLite database.

| Responsibility | Detail |
|----------------|--------|
| Run scanners | `skill-scanner`, `mcp-scanner`, `aibom`, CodeGuard, custom plugins |
| Write to DB | Scan results, AIBOM inventory, block/allow list edits |
| Communicate with orchestrator | REST API calls to trigger enforcement actions, emit audit events to SIEM, and apply actions to OpenClaw |
| Output formats | Human-readable (default), JSON (`--json`), table |

### 2. Plugins / Hooks (JS/TS)

Plugins run inside the OpenClaw plugin lifecycle. They register hooks for
OpenClaw events and connect to the orchestrator over REST to report activity
and request enforcement.

| Responsibility | Detail |
|----------------|--------|
| Hook into OpenClaw events | `gateway_start`, skill install/uninstall, MCP connect/disconnect |
| Background services | Filesystem watcher, continuous scan, real-time alerting |
| Slash commands | `/scan`, `/block`, `/allow` — operator actions from chat |
| Communicate with orchestrator | REST API calls to send audit events to SIEM, read/write DB |

### 3. Orchestrator (Go daemon)

The orchestrator (previously "gateway sidecar") is the central daemon that
ties everything together. It is the only component with direct access to all
subsystems.

| Responsibility | Detail |
|----------------|--------|
| REST API server | Accepts requests from CLI and plugins |
| OpenClaw WebSocket client | Connects via protocol v3, device-key auth, challenge-response |
| Event subscription | Subscribes to all OpenClaw gateway events (`tool_call`, `tool_result`, `exec.approval.requested`, etc.) |
| Command dispatch | Sends RPC commands to OpenClaw: `exec.approval.resolve`, `skills.update`, `config.patch` |
| Policy engine | Runs admission gate: block list → allow list → scan → verdict |
| LLM guardrail management | Spawns and supervises LiteLLM proxy as a child process; restarts on crash |
| Audit / SIEM | Logs all events to SQLite, forwards to Splunk HEC (batch or real-time) |
| DB access | Full read/write to SQLite — audit events, scan results, block/allow lists, inventory |

### 4. SQLite Database

Single shared database used by CLI (direct write), orchestrator (read/write),
and plugins (read/write via orchestrator REST API).

| Table | Writers | Readers |
|-------|---------|---------|
| Audit events | CLI, orchestrator | Orchestrator, plugins, TUI, export |
| Scan results | CLI | Orchestrator, plugins, TUI |
| Block/allow lists | CLI | Orchestrator (admission gate) |
| Skill inventory (AIBOM) | CLI | Orchestrator, plugins, TUI |

### 5. LLM Guardrail (LiteLLM + Python module)

The guardrail intercepts all LLM traffic between OpenClaw and the upstream
provider. It runs as a LiteLLM proxy with a custom guardrail module loaded.
The orchestrator manages the LiteLLM process as a supervised child.

| Responsibility | Detail |
|----------------|--------|
| Prompt inspection | Scans every prompt for injection attacks, secrets, PII, data exfiltration patterns before it reaches the LLM |
| Response inspection | Scans every LLM response for leaked secrets, tool call anomalies |
| Observe mode | Logs findings with colored output, never blocks (default, recommended to start) |
| Action mode | Blocks prompts/responses that match security policies by raising exceptions |
| Transparent proxy | OpenClaw sees a standard OpenAI-compatible API; no agent code changes required |

**How it connects:**

1. `defenseclaw setup guardrail` configures the model, mode, and port
2. OpenClaw's `openclaw.json` is patched to route LLM calls through `http://localhost:4000`
3. The orchestrator spawns LiteLLM as a child process with the guardrail module on `PYTHONPATH`
4. LiteLLM proxies requests to the real LLM provider, invoking the guardrail on every call

See `docs/GUARDRAIL.md` for the full data flow.

## Data Flow

### Scan and Enforcement Flow

```
                CLI (scan)                    Plugin (hook)
                    │                              │
                    │ 1. Run scanner                │ 1. OpenClaw event fires
                    │ 2. Write results to DB        │
                    │                              │
                    ▼                              ▼
              ┌──────────────────────────────────────┐
              │          Orchestrator REST API        │
              │                                      │
              │  3. Log audit event                  │
              │  4. Forward to SIEM (if configured)  │
              │  5. Evaluate policy (if action req)  │
              │  6. Send command to OpenClaw via WS   │
              └──────────────────────────────────────┘
                              │
                              ▼
                    OpenClaw Gateway (WS)
                              │
                              ▼
                  Action applied (e.g. skill
                  disabled, approval denied,
                  config patched)
```

### LLM Traffic Inspection Flow

```
  OpenClaw Agent                LiteLLM Proxy               LLM Provider
       │                     (localhost:4000)              (Anthropic, etc.)
       │                            │                            │
       │  1. LLM API request        │                            │
       │  (OpenAI-compatible)       │                            │
       ├───────────────────────────►│                            │
       │                            │                            │
       │                    2. pre_call guardrail                │
       │                       scans prompt for:                 │
       │                       - injection attacks               │
       │                       - secrets / PII                   │
       │                       - exfiltration patterns           │
       │                            │                            │
       │                      [action mode: block if flagged]    │
       │                            │                            │
       │                            │  3. Forward to provider    │
       │                            ├───────────────────────────►│
       │                            │                            │
       │                            │  4. LLM response           │
       │                            │◄───────────────────────────┤
       │                            │                            │
       │                    5. post_call guardrail               │
       │                       scans response for:               │
       │                       - leaked secrets                  │
       │                       - tool call anomalies             │
       │                            │                            │
       │                      [action mode: block if flagged]    │
       │                            │                            │
       │  6. Response returned      │                            │
       │◄───────────────────────────┤                            │
       │                            │                            │
```

### Admission Gate

```
Block list? ──YES──▶ reject, log to DB, audit event to SIEM, alert
     │
     NO
     │
Allow list? ──YES──▶ skip scan, install, log to DB, audit event
     │
     NO
     │
   Scan
     │
  CLEAN ───────────▶ install, log to DB
     │
  HIGH/CRITICAL ───▶ reject, log to DB, audit event to SIEM, alert,
     │                 send skills.update(enabled=false) via orchestrator
  MEDIUM/LOW ──────▶ install with warning, log to DB, audit event
```

## Open Design Questions

### 1. OpenShell Sandbox — Actions & Access Control

OpenClaw runs inside NVIDIA's OpenShell sandbox on DGX Spark. The sandbox
provides kernel-level isolation (filesystem, network, process). DefenseClaw
writes the sandbox policy YAML; OpenShell enforces it.

**Questions to resolve:**

- **Granularity of sandbox policy:** Can individual skills be granted
  different filesystem/network scopes within a single OpenShell session, or is
  the policy session-wide? This determines whether DefenseClaw can enforce
  per-skill least-privilege or only coarse allow/deny at the sandbox level.

- **Runtime policy updates:** Can the OpenShell policy be hot-reloaded while
  OpenClaw is running, or does a policy change require a session restart?
  This affects how quickly a block action takes effect (target: <2 seconds).

- **Network egress control:** Can OpenShell restrict outbound network access
  per-domain or per-port? If so, DefenseClaw can enforce network allowlists
  for MCP servers (e.g., only permit connections to approved API endpoints).

- **Filesystem scope:** Can OpenShell restrict which directories a skill's
  subprocess can read/write? This would allow DefenseClaw to sandbox untrusted
  skills to their own directory tree.

- **Process execution control:** Can OpenShell restrict which binaries a skill
  can spawn? This would let DefenseClaw prevent skills from invoking
  interpreters (`python`, `node`, `bash -c`) outside of approved tool paths.

- **macOS degraded mode:** OpenShell is not available on macOS. What subset of
  access control can be replicated without kernel-level enforcement? Options
  include filesystem watchers + process monitoring (best-effort), or
  accepting that macOS is scan-only with no runtime enforcement.

### 2. Runtime Firewall — Message Inspection (Resolved)

**Decision:** Dual-layer interception using a LiteLLM proxy for LLM traffic
and OpenClaw plugin hooks for tool call monitoring.

**Architecture:**

- **LLM traffic (prompts + completions):** Intercepted by a LiteLLM proxy
  running as a child process of the orchestrator. A custom guardrail Python
  module (`defenseclaw_guardrail.py`) is loaded into LiteLLM and invoked on
  every `pre_call` and `post_call`. OpenClaw's `openclaw.json` is patched
  to route all LLM API calls through `http://localhost:4000` instead of
  directly to the provider. This is transparent to the agent — no code changes.

- **Tool calls:** The orchestrator already receives `tool_call`, `tool_result`,
  and `exec.approval.requested` events via WebSocket. Dangerous command
  detection runs in the `EventRouter`. The OpenClaw plugin provides additional
  `before_tool_call` hooks for pre-execution interception.

- **Two modes:** `observe` (log findings, never block — default) and `action`
  (block flagged prompts/responses by raising exceptions). Mode is set via
  `DEFENSECLAW_GUARDRAIL_MODE` env var, injected by the orchestrator.

- **Detection patterns:** Built-in pattern matching for prompt injection,
  secrets/PII, and data exfiltration. Future: Cisco AI Defense cloud API
  for ML-based detection.

**Why not a pure OpenClaw plugin hook?** OpenClaw's `message_sending` hook
is broken (issue #26422) — outbound messages never fire across any delivery
path. The LiteLLM proxy approach bypasses this entirely by sitting between
OpenClaw and the LLM provider at the network level.

See `docs/GUARDRAIL.md` for the complete data flow and configuration.

## Cross-Platform Behavior

| Capability | DGX Spark (full) | macOS (degraded) |
|------------|-------------------|-------------------|
| CLI scanners | All | All |
| Orchestrator daemon | Full | Full |
| Plugins / hooks | Full | Full |
| Block/allow lists | Full enforcement | Lists maintained, no sandbox enforcement |
| Quarantine | Files moved + sandbox policy | Files moved only |
| OpenShell sandbox | Active | Not available |
| Network enforcement | Via OpenShell | Not enforced |
| LLM guardrail | Full (LiteLLM proxy + guardrail) | Full (LiteLLM proxy + guardrail) |
| Runtime firewall | Full (hook + orchestrator) | Orchestrator-only (no sandbox telemetry) |
| Audit log + SIEM | Full | Full |

## Claw Mode

DefenseClaw supports multiple agent frameworks ("claw modes"). The active mode
is set in `~/.defenseclaw/config.yaml`:

```yaml
claw:
  mode: openclaw          # openclaw | nemoclaw | opencode | claudecode (future)
  home_dir: ""            # override auto-detected home (e.g. ~/.openclaw)
```

All skill and MCP directory resolution, watcher paths, scan targets, and install
candidate lookups derive from the active claw mode. Adding a new framework
requires only a new case in `internal/config/claw.go`.

### OpenClaw Skill Resolution Order

| Priority | Path | Source |
|----------|------|--------|
| 1 | `~/.openclaw/workspace/skills/` | Workspace/project-specific skills |
| 2 | Custom `skills_dir` from `~/.openclaw/openclaw.json` | User-configured custom path |
| 3 | `~/.openclaw/skills/` | Global user-installed skills |

## Component Communication Summary

```
┌─────────┐    REST     ┌──────────────┐    WS (v3)    ┌──────────────┐
│   CLI   │───────────▶│              │──────────────▶│   OpenClaw   │
│ (Python)│            │ Orchestrator │               │   Gateway    │
└─────────┘            │   (Go)       │◀──────────────│              │
                        │              │  events        └──────┬───────┘
┌─────────┐    REST     │              │                       │
│ Plugins │───────────▶│              │───────▶  SIEM          │ LLM API calls
│ (JS/TS) │            │              │                       │ (OpenAI format)
└─────────┘            │              │◀──────▶  SQLite DB    │
                        │              │                       ▼
                        │   spawns     │               ┌──────────────┐
                        │   child ────────────────────▶│   LiteLLM    │
                        └──────────────┘               │   Proxy      │
                                                       │  + Guardrail │
                                                       └──────┬───────┘
                                                              │
                                                              ▼
                                                       LLM Provider
                                                    (Anthropic, OpenAI…)
```
