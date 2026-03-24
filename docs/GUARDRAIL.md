# LLM Guardrail — Data Flow & Architecture

The LLM guardrail intercepts all traffic between OpenClaw and LLM providers.
It uses a LiteLLM proxy with a custom guardrail module to inspect every
prompt and response without requiring any changes to OpenClaw or agent code.

## Why LiteLLM Proxy?

OpenClaw's `message_sending` plugin hook is broken (issue #26422) — outbound
messages never fire, making plugin-only interception impossible for LLM
responses. The LiteLLM proxy approach sits at the network level between
OpenClaw and the LLM provider, completely bypassing this limitation.

LiteLLM also provides a unified OpenAI-compatible API, so OpenClaw doesn't
need to know which upstream provider is being used. The guardrail works
identically for Anthropic, OpenAI, Google, and any other provider LiteLLM
supports.

## Data Flow

### Normal Request (observe mode, clean)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         LiteLLM Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        │  (OpenAI format)           │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  PRE-CALL guardrail    │                  │
        │               │                        │                  │
        │               │  1. Extract messages   │                  │
        │               │  2. Scan for:          │                  │
        │               │     - injection        │                  │
        │               │     - secrets/PII      │                  │
        │               │     - exfiltration     │                  │
        │               │  3. Verdict: CLEAN     │                  │
        │               │  4. Log to stdout      │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │                            │  Forward (translated to      │
        │                            │  Anthropic Messages API)     │
        │                            ├─────────────────────────────►│
        │                            │                              │
        │                            │  Response                    │
        │                            │◄─────────────────────────────┤
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  POST-CALL guardrail   │                  │
        │               │                        │                  │
        │               │  1. Extract content    │                  │
        │               │  2. Extract tool calls │                  │
        │               │  3. Scan response      │                  │
        │               │  4. Verdict: CLEAN     │                  │
        │               │  5. Log to stdout      │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │  Response (OpenAI format)  │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

### Flagged Request (action mode, blocked)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         LiteLLM Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        │  (contains "ignore all     │                              │
        │   previous instructions")  │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  PRE-CALL guardrail    │                  │
        │               │                        │                  │
        │               │  1. Scan messages      │                  │
        │               │  2. MATCH: injection   │                  │
        │               │  3. Verdict: HIGH      │                  │
        │               │  4. Mode = action      │                  │
        │               │  5. Set mock_response   │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │                            │  (request never forwarded)   │
        │                            │                              │
        │  HTTP 200 / mock response  │                              │
        │  "I'm unable to process    │                              │
        │   this request..."         │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

### Flagged Response (observe mode, logged only)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         LiteLLM Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               PRE-CALL: CLEAN (passes)                   │
        │                            │                              │
        │                            ├─────────────────────────────►│
        │                            │◄─────────────────────────────┤
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  POST-CALL guardrail   │                  │
        │               │                        │                  │
        │               │  1. Response contains  │                  │
        │               │     "sk-ant-api03-..." │                  │
        │               │  2. MATCH: secret      │                  │
        │               │  3. Verdict: MEDIUM    │                  │
        │               │  4. Mode = observe     │                  │
        │               │  5. Log warning only   │                  │
        │               │     (do not block)     │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │  Response returned as-is   │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

## Component Ownership

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw Orchestrator (Go)                    │
│                                                                     │
│  Owns:                                                              │
│  ├── LiteLLM child process (start, monitor health, restart)        │
│  ├── Config: guardrail.enabled, mode, port, model                  │
│  ├── Env injection: PYTHONPATH, DEFENSECLAW_GUARDRAIL_MODE         │
│  └── Health tracking: guardrail subsystem state                    │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Inspect LLM content (that's the guardrail module's job)       │
│  └── Talk to the guardrail at runtime (no REST calls between them) │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     LiteLLM Proxy (Python)                          │
│                                                                     │
│  Owns:                                                              │
│  ├── Model routing (litellm_config.yaml)                           │
│  ├── API key management (reads from env var)                       │
│  ├── Protocol translation (OpenAI ↔ Anthropic/Google/etc.)         │
│  └── Guardrail invocation (pre_call + post_call hooks)             │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Decide its own mode (reads DEFENSECLAW_GUARDRAIL_MODE)        │
│  └── Manage its own lifecycle (supervised by orchestrator)          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│              DefenseClaw Guardrail Module (Python)                   │
│              guardrails/defenseclaw_guardrail.py                    │
│                                                                     │
│  Owns:                                                              │
│  ├── Prompt inspection (injection, exfil patterns)                 │
│  ├── Response inspection (secrets, PII)                            │
│  ├── Block/allow decision per mode                                 │
│  └── Structured logging (colored terminal output)                  │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Make any network calls (all local pattern matching)           │
│  ├── Access the database or audit store                            │
│  └── Communicate with the orchestrator at runtime                  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw CLI (Python)                         │
│                                                                     │
│  Owns:                                                              │
│  ├── `defenseclaw init` — installs LiteLLM + copies guardrail      │
│  ├── `defenseclaw setup guardrail` — interactive config wizard     │
│  ├── litellm_config.yaml generation                                │
│  ├── openclaw.json patching (add LiteLLM provider, reroute model)  │
│  └── openclaw.json revert on --disable                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `observe` | Log all findings with severity and matched patterns. Never block. | Initial deployment, SOC monitoring, tuning false positives |
| `action` | Block prompts/responses that match HIGH/CRITICAL patterns. MEDIUM/LOW are logged only. | Production enforcement after tuning |

Mode is set in `~/.defenseclaw/config.yaml` (`guardrail.mode`) and injected
as `DEFENSECLAW_GUARDRAIL_MODE` env var when the orchestrator spawns LiteLLM.
Changing mode requires restarting the sidecar.

## Detection Patterns

### Prompt Inspection (pre-call)

| Category | Patterns | Severity |
|----------|----------|----------|
| Prompt injection | `ignore previous`, `ignore all instructions`, `disregard previous`, `you are now`, `act as`, `pretend you are`, `bypass`, `jailbreak`, `do anything now`, `dan mode` | HIGH |
| Data exfiltration | `/etc/passwd`, `/etc/shadow`, `base64 -d`, `exfiltrate`, `send to my server`, `curl http` | HIGH |
| Secrets in prompt | `sk-`, `sk-ant-`, `api_key=`, `-----begin rsa`, `aws_access_key`, `password=`, `bearer `, `ghp_`, `github_pat_` | MEDIUM |

### Response Inspection (post-call)

| Category | Patterns | Severity |
|----------|----------|----------|
| Leaked secrets | Same secret patterns as above | MEDIUM |
| Tool call logging | Function name + first 200 chars of arguments (logged, not blocked) | INFO |

## File Layout

```
guardrails/
  defenseclaw_guardrail.py          # shipped in repo, copied to ~/.defenseclaw/guardrails/

cli/defenseclaw/
  guardrail.py                      # config generation, openclaw.json patching
  commands/cmd_setup.py             # `setup guardrail` command
  commands/cmd_init.py              # installs litellm, copies guardrail module
  config.py                         # GuardrailConfig dataclass

internal/config/
  config.go                         # GuardrailConfig Go struct
  defaults.go                       # guardrail defaults

internal/gateway/
  litellm.go                        # LiteLLMProcess — child process management
  sidecar.go                        # runGuardrail() goroutine
  health.go                         # guardrail subsystem health tracking

~/.defenseclaw/                     # runtime (generated, not in repo)
  config.yaml                       # guardrail section
  litellm_config.yaml               # generated by setup guardrail
  defenseclaw_guardrail.py          # copied from repo (must be next to litellm_config.yaml)

~/.openclaw/
  openclaw.json                     # patched: litellm provider + model reroute
```

## Setup Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw init                                                │
│                                                                  │
│  1. Install uv (if needed)                                      │
│  2. Install scanners (skill-scanner, mcp-scanner, aibom)        │
│  3. Install litellm[proxy] via uv tool install                  │
│  4. Copy guardrails/defenseclaw_guardrail.py                    │
│     → ~/.defenseclaw/guardrails/                                │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw setup guardrail                                     │
│                                                                  │
│  Interactive wizard:                                             │
│  1. Enable guardrail? → yes                                     │
│  2. Mode? → observe (default) or action                         │
│  3. Port? → 4000 (default)                                      │
│  4. Detect current OpenClaw model (reads openclaw.json)         │
│  5. Route through guardrail? → yes                              │
│  6. Detect API key env var (from model name)                    │
│  7. Verify API key is set in environment                        │
│                                                                  │
│  Generates:                                                      │
│  ├── ~/.defenseclaw/config.yaml (guardrail section)             │
│  ├── ~/.defenseclaw/litellm_config.yaml                         │
│  └── Patches ~/.openclaw/openclaw.json                          │
│      ├── Adds litellm provider (baseUrl=localhost:4000)         │
│      └── Sets primary model to litellm/{model_name}             │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw-gateway  (or: defenseclaw sidecar)                  │
│                                                                  │
│  Starts all subsystems:                                          │
│  1. Gateway WS connection loop                                   │
│  2. Skill/MCP watcher                                           │
│  3. REST API server                                              │
│  4. LiteLLM guardrail (if enabled)                              │
│     ├── Locates litellm binary                                  │
│     ├── Verifies litellm_config.yaml exists                     │
│     ├── Starts litellm process with PYTHONPATH + mode env var   │
│     ├── Polls /health/liveliness until 200                      │
│     └── Restarts on crash (exponential backoff)                 │
└──────────────────────────────────────────────────────────────────┘
```

## Teardown

```
defenseclaw setup guardrail --disable
  1. Restore openclaw.json primary model to original
  2. Remove litellm provider from openclaw.json
  3. Set guardrail.enabled = false in config.yaml
  4. Restart sidecar for changes to take effect
```

## What the Guardrail Does NOT Do

- **No network calls in the hot path** — all inspection is local pattern
  matching. No REST calls to the sidecar, no cloud API calls.
- **No database writes** — the guardrail module logs to stdout only.
  The sidecar's audit store captures guardrail lifecycle events (start,
  healthy, crash) but not individual inspection verdicts.
- **No agent code changes** — OpenClaw sees a standard OpenAI-compatible
  API endpoint. The routing change is in `openclaw.json` config only.
- **No secret storage** — API keys stay in environment variables. The
  `litellm_config.yaml` references `os.environ/ANTHROPIC_API_KEY`, not
  the key itself.

## Future Extensions

- **Cisco AI Defense integration**: Replace or augment local pattern matching
  with ML-based detection via Cisco's cloud API. Would require an async
  call from the guardrail module (or a sidecar REST endpoint that proxies
  to the Cisco API).
- **Per-inspection audit events**: Write each inspection verdict to the
  SQLite audit store for forensic analysis and SIEM forwarding.
- **Streaming inspection**: Implement `async_post_call_streaming_iterator_hook`
  to inspect streaming responses token-by-token.
- **Custom pattern sets**: Load detection patterns from a YAML policy file
  instead of hardcoded lists.
- **Hot mode reload**: Allow switching between observe/action without
  restarting the sidecar (would require re-adding the mode config endpoint
  and having the guardrail poll periodically).
