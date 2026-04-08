# Production Deployment Guide

This repository now has two operating modes:

- Demo mode: reliable local SOC demonstration with safe simulators and lite adapters.
- Production mode: fail-closed authentication, manual approval gates, hardened Compose settings, and real-integration boundaries.

Production mode is a secure baseline for an internal SOC platform. Before internet-facing or regulated deployment, add your organization’s identity provider, TLS ingress, secrets manager, centralized logging, backup policy, and change-control process.

## Start Production Mode

1. Copy the template:

```bash
cp .env.production.example .env.production
```

2. Replace every `CHANGE_ME` value with strong secrets from your secret manager.

3. Start with the production overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml --env-file .env.production up -d --build
```

Windows wrapper:

```powershell
.\soc.cmd prod-up
```

4. Put the UI behind an HTTPS reverse proxy or private admin access path. The production overlay binds ports to `127.0.0.1` to avoid accidental LAN exposure.

## Security Controls Added

| Control | Location |
| --- | --- |
| Production startup fails on default API key | `shared/utils/security.py` |
| API key enforcement for service routes | `shared/utils/security.py` |
| Authenticated service-to-service calls | normalizer, orchestrator, executor, simulator, UI |
| Secure response headers | `shared/utils/security.py` |
| UI login backed by SOC API key | `apps/demo-control-ui` |
| Manual approval gate for containment/process actions | `apps/response-executor` |
| Production env template with no usable defaults | `.env.production.example` |
| Localhost-only production port bindings | `docker-compose.production.yml` |
| `no-new-privileges` and dropped Linux capabilities | `docker-compose.production.yml` |

## Real Integration Plan

Replace lite adapters in this order:

1. Wazuh: deploy Wazuh manager/indexer/dashboard and agents. Forward alerts to `normalizer` through `/ingest/wazuh` or a queue consumer.
2. Suricata: run sensors on SPAN/TAP/egress points and stream EVE JSON to `/ingest/suricata`.
3. TheHive: set `THEHIVE_URL` and `THEHIVE_API_KEY`; replace the adapter client implementation with direct TheHive API calls.
4. Cortex: set `CORTEX_URL` and `CORTEX_API_KEY`; map local analyzer results to Cortex job submissions and polling.
5. Shuffle: set `SHUFFLE_URL` and `SHUFFLE_API_KEY`; trigger real workflow webhooks from the response executor.
6. OpenSearch: mirror normalized events and incidents to OpenSearch for long-term search, dashboards, and retention.
7. State database: replace SQLite with Postgres for concurrent writers, backups, and HA.

## Production Response Model

In production, containment actions are skipped unless the request includes `RESPONSE_APPROVAL_TOKEN`.

Actions requiring approval:

- `block_ip`
- `isolate_container`
- `stop_container`
- `kill_process`

Actions allowed without containment approval when policy approves them:

- `create_case`
- `attach_observables`
- `run_cortex_analyzer`
- `run_shuffle_workflow`
- `collect_artifacts`
- `generate_report`

This preserves the agentic triage loop while preventing unattended destructive or high-impact changes.

## Network Security

Production overlay binds service ports to localhost:

- `127.0.0.1:8080` UI
- `127.0.0.1:8001` normalizer
- `127.0.0.1:8002` orchestrator
- `127.0.0.1:8003` response executor
- `127.0.0.1:8004` reports
- `127.0.0.1:8010` adapters

Expose only through:

- a private VPN
- a zero-trust access proxy
- an internal HTTPS reverse proxy with SSO
- Kubernetes ingress with mTLS/service auth

## Hard Requirements Before Real Use

- Replace `.env.production` with orchestrator-managed secrets.
- Use HTTPS and secure cookies for UI access.
- Configure backups for reports and state.
- Send audit records to immutable log storage.
- Keep Docker socket disabled unless you implement strict label-scoped enforcement and review it separately.
- Keep irreversible actions manual-only.
- Test every response workflow in `dry-run` before enabling active enforcement.

