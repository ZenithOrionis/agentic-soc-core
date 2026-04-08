SHELL := /bin/sh
COMPOSE ?= docker compose
PROJECT ?= agentic-soc-core

.PHONY: up down build logs reset seed test demo-scenario-1 demo-scenario-2 demo-scenario-3 demo-exfil generate-reports screenshots lint format e2e ps prod-up prod-ai-up prod-down ai-up ai-pull attack-list attack-beacon attack-script attack-bruteforce telemetry-beacon telemetry-script telemetry-bruteforce

up:
	$(COMPOSE) up --build -d
	@echo "Demo UI: http://localhost:8080"
	@echo "Normalizer: http://localhost:8001/docs"
	@echo "Orchestrator: http://localhost:8002/docs"
	@echo "TheHive/Cortex/Shuffle lite adapters: http://localhost:8010/docs"

down:
	$(COMPOSE) down

build:
	$(COMPOSE) build

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

prod-up:
	test -f .env.production
	$(COMPOSE) -f docker-compose.yml -f docker-compose.production.yml --env-file .env.production up -d --build

prod-ai-up:
	test -f .env.production
	$(COMPOSE) -f docker-compose.yml -f docker-compose.production.yml --env-file .env.production --profile ai up -d --build

prod-down:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.production.yml --env-file .env.production down

ai-up:
	$(COMPOSE) --profile ai up -d ollama
	$(COMPOSE) --profile ai run --rm ollama-pull

ai-pull:
	$(COMPOSE) --profile ai run --rm ollama-pull

attack-list:
	python tools/demo-attack-runner/attack_runner.py list

attack-beacon:
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/atomic-red-team/Invoke-AgenticAtomicDefault.ps1 -Scenario outbound-beacon

attack-script:
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/atomic-red-team/Invoke-AgenticAtomicDefault.ps1 -Scenario suspicious-script

attack-bruteforce:
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/atomic-red-team/Invoke-AgenticAtomicDefault.ps1 -Scenario bruteforce-success

telemetry-beacon:
	python tools/demo-attack-runner/attack_runner.py run outbound-beacon --mode direct

telemetry-script:
	python tools/demo-attack-runner/attack_runner.py run suspicious-script --mode direct

telemetry-bruteforce:
	python tools/demo-attack-runner/attack_runner.py run bruteforce-success --mode direct

reset:
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up --build -d

seed:
	$(COMPOSE) exec normalizer python /app/infra/scripts/seed_demo_data.py

test:
	PYTHONPATH=. pytest -q tests/unit tests/integration

e2e:
	SOC_E2E=1 PYTHONPATH=. pytest -q tests/e2e

demo-scenario-1:
	curl -fsS -X POST http://localhost:8005/scenarios/outbound-beacon | python -m json.tool

demo-scenario-2:
	curl -fsS -X POST http://localhost:8005/scenarios/suspicious-script | python -m json.tool

demo-scenario-3:
	curl -fsS -X POST http://localhost:8005/scenarios/bruteforce-success | python -m json.tool

demo-exfil:
	curl -fsS -X POST http://localhost:8005/scenarios/exfil-burst | python -m json.tool

generate-reports:
	curl -fsS -X POST http://localhost:8004/reports/generate-all | python -m json.tool

screenshots:
	mkdir -p docs/screenshots
	@echo "Open http://localhost:8080 and save stakeholder screenshots under docs/screenshots/."

lint:
	PYTHONPATH=. ruff check shared apps tests

format:
	PYTHONPATH=. ruff format shared apps tests
