# Explainability

The explainability service generates three artifacts per incident:

- `incident-audit.json`: machine-readable incident, event, and action record.
- `incident-report.html`: human-readable report.
- `incident-report.pdf`: stakeholder-friendly PDF.

Reports include:

- Title page.
- Executive summary.
- Incident overview.
- Timeline.
- Detections triggered.
- Observables.
- MITRE ATT&CK mapping.
- Asset/user impact.
- Automated actions and rationale.
- Confidence rationale.
- Raw evidence appendix.
- Rollback instructions.
- Alternative hypotheses.
- Unresolved uncertainty.
- Next steps.

WeasyPrint is used for PDF generation in Docker. If the local renderer cannot load, the service writes a minimal fallback PDF and keeps the complete HTML report.

