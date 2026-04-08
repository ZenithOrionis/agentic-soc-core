# Architecture

AegisCore uses three layers: detection/ingest, triage/response, and explainability/reporting.

```mermaid
flowchart TD
  A["Safe scenario event"] --> B["Normalizer"]
  B --> C["Common event schema"]
  C --> D["SOC Orchestrator"]
  D --> E["Correlation engine"]
  E --> F["Scoring engine"]
  F --> OAI["Ollama analyst decision"]
  OAI --> G["Policy guardrails"]
  G --> H["Response Executor"]
  H --> I["Case, analyzer, workflow adapters"]
  H --> J["Demo firewall/quarantine state"]
  H --> K["Explainability Service"]
  K --> L["JSON, HTML, PDF report"]
```

```mermaid
flowchart LR
  subgraph Docker["Docker host"]
    subgraph M["monitored-segment"]
      E1["workstation-1"]
      E2["server-1"]
      T["threat-simulators"]
    end
    subgraph C["soc-core"]
      N["normalizer"]
      O["soc-orchestrator"]
      R["response-executor"]
      X["explainability-service"]
      U["demo-control-ui"]
      L["integration-adapters"]
    end
    subgraph Q["quarantine-segment"]
      QS["quarantine state / optional isolated containers"]
    end
  end
```

The default mode is intentionally lightweight and deterministic. Full Wazuh/TheHive/Cortex/Shuffle deployments can replace the lite adapters by updating the client URLs and credentials in `.env`.

## Automated Response Flow

```mermaid
flowchart TD
  A["Incident confidence and tags"] --> B["Policy thresholds"]
  B --> C{"Action risk"}
  C -->|"low and confidence high enough"| D["Auto-approve reversible action"]
  C -->|"medium and confidence >= 0.92"| E["Demo containment action"]
  C -->|"irreversible"| F["Manual approval required"]
  D --> G["Response Executor"]
  E --> G
  G --> H["Record command, result, rollback"]
  H --> I["Audit store"]
  H --> J["Report generation"]
```

## Report Generation Flow

```mermaid
flowchart LR
  A["Incident"] --> D["Explainability Service"]
  B["Normalized events"] --> D
  C["Action records"] --> D
  D --> E["Jinja2 HTML"]
  E --> F["WeasyPrint PDF"]
  D --> G["JSON audit bundle"]
  F --> H["reports volume"]
  G --> H
```
