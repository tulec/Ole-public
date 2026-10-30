# Observability

`Ole` now ships a local Prometheus + Grafana stack for the built-in `/metrics`, `/livez`, and `/readyz` endpoints.

## What Gets Scraped

- `ole-server` at `http://ole-server:8080/metrics`
- local Windows `Ole Agent` at `http://host.docker.internal:5858/metrics`

The agent target is expected to be reachable from Docker Desktop on Windows. If the agent is not running yet, the server dashboards still work and Prometheus simply marks the agent target as down.

## Start The Stack

```powershell
docker compose up -d postgres ole-server prometheus grafana
```

Then open:

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`

Default Grafana credentials come from `docker-compose.yml`:

- username: `admin`
- password: `admin`

Override them with `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` if needed.

## Included Dashboards

Provisioned dashboards live in [deploy/monitoring/grafana/dashboards](../deploy/monitoring/grafana/dashboards):

- `Ole Auth Health`
- `Ole Signaling Health`
- `Ole NAT Traversal`
- `Ole Relay Health`
- `Ole DB Health`

## Metric Coverage

Server dashboards now use:

- auth abuse and shared auth-rate-limit snapshots
- control-plane signaling counts for peers, candidates, tunnels, networks, and memberships
- relay throughput, denials, and abuse counters
- database readiness plus `sql.DB` pool stats

Agent dashboards now use:

- STUN configuration and last probe timing
- current NAT type and public-endpoint availability
- direct-attempt, success, failure, and relay-fallback counters
- connection reachability and transport-mode gauges

## Trace Correlation

`Ole` now also propagates lightweight trace headers across control-plane and signaling requests:

- `X-Ole-Trace-Id`
- `X-Ole-Parent-Span-Id`
- `X-Ole-Span-Id`

The local `controlclient` generates a trace for each outbound request, the server copies the trace id and emits its own span id in the response, and the agent keeps recent `controlplane.request.completed` entries in the diagnostics bundle so request failures can be correlated with server logs.

## Files

- Prometheus scrape config: [prometheus.yml](../deploy/monitoring/prometheus/prometheus.yml)
- Grafana provisioning: [prometheus.yml](../deploy/monitoring/grafana/provisioning/datasources/prometheus.yml), [dashboards.yml](../deploy/monitoring/grafana/provisioning/dashboards/dashboards.yml)
