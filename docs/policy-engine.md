# Policy Engine

Policy is stored in `shared/policy/policy.yaml`.

Key thresholds:

- Confidence below `0.60`: suppress or queue.
- Confidence `0.60` to `0.89`: enrich, create case, and generate report.
- Confidence `>= 0.90`: low-risk automatic actions can run.
- Confidence `>= 0.92`: medium-risk demo containment can run.
- Irreversible actions require manual approval and are not implemented in the auto path.

Confidence boosts:

- Repeated sightings.
- Suspicious behavior tag combinations.
- Local suspicious or known-bad reputation.
- High source severity.

Confidence reductions:

- Allowlisted assets.
- Allowlisted IP addresses.

The orchestrator stores the selected decision, alternatives considered, confidence rationale, and action list in the incident timeline and audit store.

