# API Reference

Useful endpoints:

- `GET http://localhost:8001/events`: normalized events.
- `POST http://localhost:8001/ingest/suricata`: ingest Suricata EVE JSON.
- `POST http://localhost:8001/ingest/wazuh`: ingest Wazuh alert JSON.
- `GET http://localhost:8002/incidents`: correlated incidents.
- `POST http://localhost:8002/events`: orchestrator event intake.
- `GET http://localhost:8003/actions`: action records.
- `POST http://localhost:8003/actions`: execute an approved action request.
- `POST http://localhost:8004/reports/{incident_id}/generate`: generate report artifacts.
- `GET http://localhost:8004/reports/{incident_id}/pdf`: download PDF.
- `POST http://localhost:8005/scenarios/{scenario}`: trigger a simulator.
- `POST http://localhost:8010/thehive/cases`: create/update local case.
- `POST http://localhost:8010/cortex/analyze`: run local analyzer.
- `POST http://localhost:8010/shuffle/workflows/{workflow}`: run local workflow.

OpenAPI docs are exposed at `/docs` for each FastAPI service.

In production mode, send:

```text
X-SOC-API-Key: <value from SOC_API_KEY>
```

The only unauthenticated route is `/health`, plus `/login` and `/static` on the UI service.
