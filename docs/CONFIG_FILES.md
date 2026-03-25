# Config Files & Environment Variables

How configuration flows between DefenseClaw components. This covers every
file and environment variable the system reads or writes, who creates each
one, and which code path consumes it.

## Visual Overview

```
USER runs: defenseclaw setup guardrail
  │
  ├─ WRITES ──► ~/.defenseclaw/config.yaml        (all settings)
  ├─ WRITES ──► ~/.defenseclaw/litellm_config.yaml (LiteLLM routing + guardrail refs)
  ├─ WRITES ──► ~/.defenseclaw/.env                (API key values, mode 0600)
  └─ COPIES ──► ~/.defenseclaw/defenseclaw_guardrail.py (guardrail module)


GO SIDECAR boots: reads config.yaml once
  │
  ├─ SPAWNS LiteLLM subprocess with:
  │    ├─ CLI arg:  --config ~/.defenseclaw/litellm_config.yaml
  │    ├─ ENV from .env file:  ANTHROPIC_API_KEY=sk-ant-...
  │    ├─ ENV:  PYTHONPATH=~/.defenseclaw
  │    ├─ ENV:  DEFENSECLAW_GUARDRAIL_MODE=observe     ◄─ from config.yaml
  │    ├─ ENV:  DEFENSECLAW_SCANNER_MODE=local          ◄─ from config.yaml
  │    ├─ ENV:  DEFENSECLAW_API_PORT=18790              ◄─ from config.yaml
  │    ├─ ENV:  DEFENSECLAW_DATA_DIR=~/.defenseclaw     ◄─ from config.yaml
  │    └─ ENV:  CISCO_AI_DEFENSE_* (4 vars)             ◄─ from config.yaml
  │
  └─ API server handles PATCH /api/v1/guardrail/config
       └─ WRITES ──► ~/.defenseclaw/guardrail_runtime.json  (mode + scanner_mode)
          (does NOT update config.yaml)


LITELLM PROCESS:
  │
  ├─ Reads litellm_config.yaml (model routing, master key)
  ├─ Reads ANTHROPIC_API_KEY from env (for upstream LLM calls)
  └─ Loads guardrail module (defenseclaw_guardrail.py via PYTHONPATH)
       │
       ├─ __init__: reads DEFENSECLAW_GUARDRAIL_MODE, _SCANNER_MODE from env
       ├─ Every request (_inspect):
       │    ├─ reads guardrail_runtime.json (via DEFENSECLAW_DATA_DIR) ◄─ hot-reload
       │    └─ POSTs to Go sidecar (via DEFENSECLAW_API_PORT) ◄─ telemetry + OPA
       └─ CiscoAIDefenseClient.__init__: reads CISCO_AI_DEFENSE_* from env
```

> **Note on redundancy:** `mode` and `scanner_mode` each travel through
> three channels — config.yaml → env var → runtime JSON. The PATCH endpoint
> only updates the runtime JSON without writing back to config.yaml, so the
> two can drift after a hot-reload.

---

## Files

### `~/.defenseclaw/config.yaml`

Central config file shared by the Go sidecar and the Python CLI. Stores
scanner settings, gateway connection, watcher config, guardrail settings,
skill actions, and everything else.

| | |
|---|---|
| **Created by** | `defenseclaw init`, `defenseclaw setup skill-scanner`, `defenseclaw setup mcp-scanner`, `defenseclaw setup gateway`, `defenseclaw setup guardrail` — all via Python `cfg.save()` (`cli/defenseclaw/config.py:290`) |
| **Read by** | **Python CLI** at startup via `config.load()` (`cli/defenseclaw/config.py:426`). **Go sidecar** at startup via `config.Load()` (`internal/config/config.go:262`, Viper). |
| **NOT read by** | The guardrail module (`defenseclaw_guardrail.py`) — it has no access to this file. |

---

### `~/.defenseclaw/litellm_config.yaml`

Auto-generated LiteLLM proxy configuration. Contains model routing (which
upstream model to call), the LiteLLM master key, the API key env var
reference (`os.environ/ANTHROPIC_API_KEY`), and the three guardrail hooks
(pre\_call, during\_call, post\_call).

| | |
|---|---|
| **Created by** | `defenseclaw setup guardrail` via `generate_litellm_config()` + `write_litellm_config()` (`cli/defenseclaw/guardrail.py:20–86`, called from `cmd_setup.py:637–644`). |
| **Read by** | **LiteLLM subprocess** — the Go sidecar passes `--config ~/.defenseclaw/litellm_config.yaml` as a CLI argument (`internal/gateway/litellm.go:109–111`). LiteLLM uses it for model routing, API key resolution, and guardrail class discovery. |
| **NOT read by** | The Go sidecar or Python CLI at runtime. |

---

### `~/.defenseclaw/.env`

Persists API key **values** for daemon contexts where the user's shell
environment isn't inherited. Written with `mode 0600`.

Example contents:

```
ANTHROPIC_API_KEY=sk-ant-api03-...
```

| | |
|---|---|
| **Created by** | `defenseclaw setup guardrail` via `_write_dotenv()` (`cmd_setup.py:179–184`, called from line 755). |
| **Read by** | **Go sidecar** `buildEnv()` (`internal/gateway/litellm.go:146–158`) via `loadDotEnv()` (line 310). Values are merged into the LiteLLM subprocess env — only keys **not already present** in the inherited environment are added. |
| **Path derivation** | `filepath.Dir(l.cfg.LiteLLMConfig)` + `/.env` — derived from the `litellm_config` path, not from `data_dir`. |

---

### `~/.defenseclaw/guardrail_runtime.json`

Small JSON file for hot-reloading guardrail mode and scanner mode without
restarting LiteLLM. Contains only two fields.

Example contents:

```json
{"mode": "observe", "scanner_mode": "local"}
```

| | |
|---|---|
| **Created by** | **Go sidecar** API server via `writeGuardrailRuntime()` (`internal/gateway/api.go:1051–1063`), called from the `PATCH /api/v1/guardrail/config` handler (line 1023). |
| **Read by** | **Guardrail module** (`defenseclaw_guardrail.py`) via `_read_runtime_config()` (lines 293–308) with a 5-second TTL cache. Called on every LLM request from `_inspect()` (line 371). |
| **Path derivation (writer)** | `filepath.Join(a.scannerCfg.DataDir, "guardrail_runtime.json")` — uses `DataDir` from Go config. |
| **Path derivation (reader)** | `os.environ.get("DEFENSECLAW_DATA_DIR", "~/.defenseclaw")` + `/guardrail_runtime.json` — uses the `DEFENSECLAW_DATA_DIR` env var. |
| **Caveat** | The PATCH handler updates the in-memory Go config but does **not** call `cfg.Save()`, so `config.yaml` drifts out of sync after a PATCH. |

---

### `~/.defenseclaw/defenseclaw_guardrail.py`

The guardrail Python module loaded by LiteLLM. Contains pattern-based local
scanning, Cisco AI Defense integration, verdict caching, and sidecar
telemetry reporting.

| | |
|---|---|
| **Created by** | `defenseclaw setup guardrail` via `install_guardrail_module()` — copies from the repo source or pip package (`cli/defenseclaw/guardrail.py:177–193`, called from `cmd_setup.py:654–660`). |
| **Read by** | **LiteLLM subprocess** — discovered via `PYTHONPATH` which points to `~/.defenseclaw/`. LiteLLM imports it as `defenseclaw_guardrail.DefenseClawGuardrail` based on the refs in `litellm_config.yaml`. |

---

## Environment Variables

All `DEFENSECLAW_*` env vars are set by the Go sidecar in `buildEnv()`
(`internal/gateway/litellm.go:141–213`). They are injected into the
**LiteLLM child process** environment. The Go sidecar reads their source
values from `config.yaml` at boot.

### `DEFENSECLAW_GUARDRAIL_MODE`

| | |
|---|---|
| **Set by** | `litellm.go:187` — `"DEFENSECLAW_GUARDRAIL_MODE=" + l.cfg.Mode` |
| **Source value** | `config.yaml` → `guardrail.mode` (default `"observe"`) |
| **Read by** | `defenseclaw_guardrail.py` `__init__` (line 315) — sets `self.mode` which controls block vs. log behavior. |
| **Overridden at runtime** | By `guardrail_runtime.json` via `_read_runtime_config()` in `_inspect()` (line 372). |

### `DEFENSECLAW_SCANNER_MODE`

| | |
|---|---|
| **Set by** | `litellm.go:189` — `"DEFENSECLAW_SCANNER_MODE=" + l.cfg.ScannerMode` |
| **Source value** | `config.yaml` → `guardrail.scanner_mode` (default `"local"`) |
| **Read by** | `defenseclaw_guardrail.py` `__init__` (line 316) — decides which scanners run (`"local"`, `"remote"`, or `"both"`). Also controls whether `CiscoAIDefenseClient` is instantiated (lines 318–319). |
| **Overridden at runtime** | By `guardrail_runtime.json` via `_inspect()` (lines 375–381). |

### `DEFENSECLAW_API_PORT`

| | |
|---|---|
| **Set by** | `litellm.go:192` — `fmt.Sprintf("DEFENSECLAW_API_PORT=%d", l.apiPort)` |
| **Source value** | `config.yaml` → `gateway.api_port` (default `18790`), passed through `sidecar.go:311`. |
| **Read by** | `defenseclaw_guardrail.py` in two places: `_evaluate_via_sidecar()` (line 427) for OPA policy evaluation POSTs to `http://127.0.0.1:{port}/v1/guardrail/evaluate`, and `_report_to_sidecar()` (line 703) for telemetry POSTs to `http://127.0.0.1:{port}/v1/guardrail/event`. If unset, both silently no-op. |

### `DEFENSECLAW_DATA_DIR`

| | |
|---|---|
| **Set by** | `litellm.go:195` — `"DEFENSECLAW_DATA_DIR=" + l.dataDir` |
| **Source value** | `config.yaml` → `data_dir` (default `~/.defenseclaw`), passed from `sidecar.go:311` via `NewLiteLLMProcess(..., s.cfg.DataDir)`. |
| **Read by** | `defenseclaw_guardrail.py` `_read_runtime_config()` (line 300) — used solely to locate `guardrail_runtime.json`. |

### `PYTHONPATH`

| | |
|---|---|
| **Set by** | `litellm.go:161–168, 186` — prepends `guardrail.guardrail_dir` to any existing `PYTHONPATH`. |
| **Source value** | `config.yaml` → `guardrail.guardrail_dir` (default `~/.defenseclaw`). |
| **Read by** | The Python interpreter — allows `import defenseclaw_guardrail` to find the guardrail module. |

### `CISCO_AI_DEFENSE_ENDPOINT`

| | |
|---|---|
| **Set by** | `litellm.go:200` — only when `scanner_mode` is `"remote"` or `"both"`. |
| **Source value** | `config.yaml` → `guardrail.cisco_ai_defense.endpoint`. |
| **Read by** | `defenseclaw_guardrail.py` `CiscoAIDefenseClient.__init__` (line 130). |

### `CISCO_AI_DEFENSE_API_KEY_ENV`

| | |
|---|---|
| **Set by** | `litellm.go:203`. |
| **Source value** | `config.yaml` → `guardrail.cisco_ai_defense.api_key_env` (default `"CISCO_AI_DEFENSE_API_KEY"`). |
| **Read by** | `defenseclaw_guardrail.py` `CiscoAIDefenseClient.__init__` (line 127) — this is an **indirection**: reads the env var *name* from this variable, then reads the actual API key from that named env var. |

### `CISCO_AI_DEFENSE_TIMEOUT_MS`

| | |
|---|---|
| **Set by** | `litellm.go:206`. |
| **Source value** | `config.yaml` → `guardrail.cisco_ai_defense.timeout_ms` (default `3000`). |
| **Read by** | `defenseclaw_guardrail.py` `CiscoAIDefenseClient.__init__` (line 135). |

### `CISCO_AI_DEFENSE_ENABLED_RULES`

| | |
|---|---|
| **Set by** | `litellm.go:209` — comma-separated list. |
| **Source value** | `config.yaml` → `guardrail.cisco_ai_defense.enabled_rules`. |
| **Read by** | `defenseclaw_guardrail.py` `CiscoAIDefenseClient.__init__` (lines 138–143). |

### API key env vars (e.g., `ANTHROPIC_API_KEY`)

| | |
|---|---|
| **Set by** | Either inherited from the user's shell environment, or loaded from `~/.defenseclaw/.env` by `buildEnv()` (`litellm.go:147–158`). |
| **Read by** | **LiteLLM itself** — resolves `os.environ/ANTHROPIC_API_KEY` from `litellm_config.yaml` to authenticate upstream LLM API calls. Not read by the guardrail module. |
