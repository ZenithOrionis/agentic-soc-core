# Security Considerations

This is a defensive demo environment.

Safety defaults:

- No malware.
- No paid APIs.
- No SaaS dependency.
- No host firewall modification.
- No Docker socket mount by default.
- Auto-response actions are reversible and scoped to demo state.
- Simulators use RFC 5737/documentation IPs and local-only names.

If enabling Docker socket enforcement later:

- Keep `DEMO_CONTAINER_LABEL=soc.demo.scope=agentic-soc-core`.
- Restrict actions to containers with that label.
- Avoid host network mode.
- Keep privileged containers off unless running a dedicated sensor lab.

## Production Mode

Production mode adds:

- API-key authentication on all non-health service routes.
- Service-to-service API-key propagation.
- Startup refusal when the default demo API key is used with `ENVIRONMENT=production`.
- Manual approval gates for containment/process/network response actions.
- Localhost-only service port bindings through `docker-compose.production.yml`.
- Dropped Linux capabilities and `no-new-privileges`.
- UI login backed by the SOC API key.

Use [production-deployment.md](production-deployment.md) as the deployment checklist.
