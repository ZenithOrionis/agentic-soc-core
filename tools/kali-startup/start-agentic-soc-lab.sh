#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$REPO_ROOT/.env.production"
AUDIT_BRIDGE_INSTALLER="$REPO_ROOT/tools/kali-audit-bridge/install-kali-audit-bridge.sh"
STARTUP_LOG_PREFIX="[agentic-soc-startup]"

log() {
  printf '%s %s\n' "$STARTUP_LOG_PREFIX" "$*"
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    log "missing required file: $path"
    exit 1
  fi
}

compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    docker compose "$@"
  fi
}

service_start() {
  local svc="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "$svc"
  else
    service "$svc" start
  fi
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-60}"
  local sleep_seconds="${3:-2}"
  local i
  for ((i=1; i<=attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$sleep_seconds"
  done
  log "timed out waiting for $url"
  return 1
}

env_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1)}' "$ENV_FILE" | tail -n 1
}

ensure_prereqs() {
  require_file "$ENV_FILE"
  require_file "$REPO_ROOT/docker-compose.yml"
  require_file "$REPO_ROOT/docker-compose.production.yml"

  if ! command -v docker >/dev/null 2>&1; then
    log "docker not found"
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    log "curl not found"
    exit 1
  fi
}

ensure_system_services() {
  log "starting docker"
  service_start docker

  log "starting auditd"
  service_start auditd || true
}

bring_up_soc() {
  log "starting SOC stack"
  compose_cmd -f "$REPO_ROOT/docker-compose.yml" -f "$REPO_ROOT/docker-compose.production.yml" --env-file "$ENV_FILE" --profile ai up -d --build
}

ensure_ollama_model() {
  local model
  model="$(env_value OLLAMA_MODEL)"
  if [[ -z "$model" ]]; then
    log "OLLAMA_MODEL not set; skipping model pull"
    return 0
  fi

  log "waiting for ollama health"
  wait_for_http "http://127.0.0.1:11434/api/tags" 90 2

  if docker exec agentic-soc-core-ollama-1 ollama list 2>/dev/null | grep -Fq "$model"; then
    log "ollama model already present: $model"
    return 0
  fi

  log "pulling ollama model: $model"
  docker exec agentic-soc-core-ollama-1 ollama pull "$model"
}

ensure_audit_bridge() {
  if [[ ! -f /etc/systemd/system/agentic-soc-audit-bridge.service ]]; then
    log "installing Kali audit bridge"
    bash "$AUDIT_BRIDGE_INSTALLER"
  else
    log "restarting Kali audit bridge"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart agentic-soc-audit-bridge.service
    else
      service agentic-soc-audit-bridge restart
    fi
  fi
}

wait_for_stack() {
  log "waiting for SOC APIs"
  wait_for_http "http://127.0.0.1:8001/health" 90 2
  wait_for_http "http://127.0.0.1:8002/health" 90 2
  wait_for_http "http://127.0.0.1:8003/health" 90 2
  wait_for_http "http://127.0.0.1:8004/health" 90 2
  wait_for_http "http://127.0.0.1:8080/health" 90 2
}

print_summary() {
  log "startup complete"
  log "UI: http://127.0.0.1:8080/login"
  log "Normalizer: http://127.0.0.1:8001/health"
  log "Orchestrator: http://127.0.0.1:8002/health"
  log "Executor: http://127.0.0.1:8003/health"
  log "Reports: http://127.0.0.1:8004/health"
  log "Ollama: http://127.0.0.1:11434/api/tags"
  log "SOC_API_KEY: $(env_value SOC_API_KEY)"
}

main() {
  cd "$REPO_ROOT"
  ensure_prereqs
  ensure_system_services
  bring_up_soc
  ensure_ollama_model
  ensure_audit_bridge
  wait_for_stack
  print_summary
}

main "$@"
