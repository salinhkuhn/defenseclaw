# DefenseClaw — Getting Started

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.22+ | https://go.dev/dl/ |
| Python | 3.12 | via `uv` |
| uv | latest | https://docs.astral.sh/uv/ |
| Node.js | 18+ | https://nodejs.org/ |
| OCB | latest | `go install go.opentelemetry.io/collector/cmd/builder@latest` |

OCB (OpenTelemetry Collector Builder) is only needed if you want telemetry export to Splunk.

## Quick Start

### 1. Build everything

```bash
make build
```

This builds four components:

| Component | Output |
|-----------|--------|
| Python CLI | `.venv/bin/defenseclaw` |
| Go gateway | `./defenseclaw-gateway` |
| OpenClaw plugin | `extensions/defenseclaw/dist/` |
| OTel collector | `collector/_build/defenseclaw-collector` |

To build individual components: `make gateway`, `make collector`, `make pycli`, `make plugin`.

### 2. Initialize config

```bash
source .venv/bin/activate
defenseclaw init
```

This creates `~/.defenseclaw/config.yaml` with sensible defaults.

### 3. Run

#### Gateway only (no telemetry export)

```bash
./scripts/start.sh
```

The gateway starts on `127.0.0.1:18789` (WebSocket) and `127.0.0.1:18790` (API).

#### Gateway + telemetry to Splunk Observability Cloud

```bash
./scripts/start.sh --enable-telemetry --access-key <SPLUNK_TOKEN>
```

This does three things automatically:
1. Starts the sidecar OTel collector on `localhost:4317`
2. Sets `DEFENSECLAW_OTEL_ENABLED=true` so the gateway enables OpenTelemetry
3. Points the gateway at the local collector (`DEFENSECLAW_OTEL_ENDPOINT=localhost:4317`)

No config file edits required.

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--enable-telemetry` | Start collector + enable OTel in gateway | off |
| `--access-key TOKEN` | Splunk access token (required with `--enable-telemetry`) | — |
| `--realm REALM` | Splunk ingest realm | `us1` |

```bash
# US West realm
./scripts/start.sh --enable-telemetry --access-key <TOKEN> --realm us0

# Default realm (us1)
./scripts/start.sh --enable-telemetry --access-key <TOKEN>
```

Press `Ctrl+C` to stop — both collector and gateway shut down cleanly.

#### Via Make

```bash
make start                                                        # gateway only
make start ARGS="--enable-telemetry --access-key <TOKEN>"         # with telemetry
```

## How Telemetry Works

```
                        Without --enable-telemetry
                        ┌──────────────┐
                        │  DefenseClaw │
                        │   Gateway    │  (OTel disabled, no export)
                        └──────────────┘

                        With --enable-telemetry
┌──────────────┐  OTLP gRPC  ┌───────────────────┐
│  DefenseClaw ├────────────► │ Sidecar Collector │
│   Gateway    │  :4317       │                   │
└──────────────┘              │ traces ─► OTLP ──► Splunk APM
                              │ metrics ► SFx  ──► Splunk IM
                              └───────────────────┘
```

The sidecar collector is needed because Splunk O11y accepts traces via OTLP but requires metrics in the native SignalFx format. The collector handles that conversion transparently.

### What gets exported

| Signal | Pipeline | Destination |
|--------|----------|-------------|
| Traces | `otlp → batch → otlp/splunk` | Splunk APM |
| Metrics | `otlp → batch → signalfx` | Splunk Infrastructure Monitoring |

Metrics include: `defenseclaw.scan.*`, `defenseclaw.tool.*`, `defenseclaw.guardrail.*`, `defenseclaw.alert.*`, `defenseclaw.llm.*`.

### Environment variable overrides

The gateway reads these env vars at startup (set automatically by `start.sh` when `--enable-telemetry` is used):

| Env var | Effect |
|---------|--------|
| `DEFENSECLAW_OTEL_ENABLED` | Enable/disable OTel (`true`/`false`) |
| `DEFENSECLAW_OTEL_ENDPOINT` | OTel collector endpoint |
| `DEFENSECLAW_OTEL_PROTOCOL` | Export protocol (`grpc` or `http`) |

These override the corresponding values in `~/.defenseclaw/config.yaml` without modifying the file.

## Build Individual Components

```bash
make gateway       # Go gateway binary
make collector     # OTel sidecar collector (requires ocb)
make pycli         # Python CLI into .venv
make plugin        # OpenClaw TypeScript plugin
```

## Install

```bash
make install
```

Installs all components:
- Gateway → `~/.local/bin/defenseclaw-gateway`
- Collector → `~/.local/bin/defenseclaw-collector`
- Plugin → `~/.defenseclaw/extensions/defenseclaw/`

## Test

```bash
make test          # all tests (Python + Go)
make gateway-test  # Go tests only
make cli-test      # Python tests only
```

## Clean

```bash
make clean         # removes binaries, venv, collector build output
```

## Project Layout

```
scripts/start.sh              Launcher script (gateway + optional collector)
collector/
  builder-config.yaml          OCB manifest (components to include)
  config.yaml                  Collector runtime config (pipelines, exporters)
  _build/                      Build output (gitignored)
internal/
  config/config.go             Gateway config + env var bindings
  telemetry/                   OTel SDK setup (traces, metrics, logs)
  gateway/                     WebSocket + REST API handlers
```
