# DefenseClaw Sidecar Collector

Minimal OpenTelemetry Collector built with [OCB](https://opentelemetry.io/docs/collector/custom-collector/) that runs as a localhost sidecar alongside the DefenseClaw gateway. It receives OTLP telemetry from the gateway and forwards it to Splunk Observability Cloud.

## Why a sidecar?

Splunk O11y accepts traces via OTLP but requires metrics in the native SignalFx format. The sidecar collector handles that conversion transparently — the gateway sends standard OTLP and the collector takes care of the rest.

```
┌──────────────┐  OTLP (gRPC/HTTP)  ┌────────────────────┐
│  DefenseClaw ├───────────────────► │  Sidecar Collector │
│   Gateway    │   localhost:4317    │                    │
└──────────────┘                     │  traces ──► OTLP ──► Splunk APM
                                     │  metrics ─► SFx  ──► Splunk IM
                                     └────────────────────┘
```

## Components

| Component | Type | Purpose |
|-----------|------|---------|
| `otlp` | receiver | Accepts gRPC (`:4317`) and HTTP (`:4318`) from the gateway |
| `batch` | processor | Batches telemetry (512 items / 5s) before export |
| `otlp/splunk` | exporter | Forwards traces to Splunk APM via OTLP gRPC |
| `signalfx` | exporter | Converts metrics to SignalFx native format |
| `debug` | exporter | Available for troubleshooting (not wired by default) |

## Prerequisites

```bash
go install go.opentelemetry.io/collector/cmd/builder@latest
```

## Build

```bash
make collector
```

This runs OCB against `builder-config.yaml` and produces a binary at `collector/_build/defenseclaw-collector`.

## Run

### With the start script (recommended)

```bash
# Gateway only — no telemetry
./scripts/start.sh

# Gateway + collector
./scripts/start.sh --enable-telemetry --access-key <SPLUNK_TOKEN>

# Non-default realm
./scripts/start.sh --enable-telemetry --access-key <SPLUNK_TOKEN> --realm us0
```

Ctrl+C stops both processes cleanly.

### Standalone

```bash
export SPLUNK_ACCESS_TOKEN=<token>
export SPLUNK_REALM=us1

./collector/_build/defenseclaw-collector --config collector/config.yaml
```

## Configuration

`config.yaml` uses `${env:SPLUNK_ACCESS_TOKEN}` and `${env:SPLUNK_REALM}` for credential injection — no secrets in the file.

### Enable debug exporter

Add `debug` to any pipeline's exporters list in `config.yaml`:

```yaml
service:
  pipelines:
    traces:
      exporters: [otlp/splunk, debug]
```

## Files

| File | Description |
|------|-------------|
| `builder-config.yaml` | OCB manifest — defines which collector components to include |
| `config.yaml` | Collector runtime config — receivers, processors, exporters, pipelines |
| `_build/` | Build output (gitignored) |
