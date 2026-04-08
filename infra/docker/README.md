# Docker Infrastructure Notes

The default demo stack uses lightweight local services so a laptop can run the full end-to-end flow reliably. Optional full sensor/search services are available through Compose profiles:

- `docker compose --profile full-sensors up suricata`
- `docker compose --profile full-search up opensearch`

Full Wazuh, TheHive, Cortex, and Shuffle deployments are intentionally represented by working local adapters in the default stack. The adapters keep the API boundaries and audit trail explicit without requiring a large Cassandra/OpenSearch/Wazuh cluster for a stakeholder demo.

