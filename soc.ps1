param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "up",
        "down",
        "build",
        "logs",
        "reset",
        "seed",
        "test",
        "e2e",
        "demo-scenario-1",
        "demo-scenario-2",
        "demo-scenario-3",
        "demo-exfil",
        "generate-reports",
        "screenshots",
        "lint",
        "format",
        "ps",
        "prod-up",
        "prod-ai-up",
        "prod-down",
        "ai-up",
        "ai-pull",
        "attack-list",
        "attack-beacon",
        "attack-script",
        "attack-bruteforce",
        "telemetry-beacon",
        "telemetry-script",
        "telemetry-bruteforce",
        "atomic-beacon",
        "atomic-script",
        "atomic-bruteforce",
        "help"
    )]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CommandArgs)
    $exe = $CommandArgs[0]
    $remaining = @()
    if ($CommandArgs.Count -gt 1) {
        $remaining = $CommandArgs[1..($CommandArgs.Count - 1)]
    }
    & $exe @remaining
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $($CommandArgs -join ' ')"
    }
}

function Invoke-JsonPost {
    param([string]$Url)
    $response = Invoke-RestMethod -Method Post -Uri $Url
    $response | ConvertTo-Json -Depth 30
}

switch ($Command) {
    "up" {
        Invoke-Checked docker compose up --build -d
        Write-Host "Demo UI: http://localhost:8080"
        Write-Host "Normalizer: http://localhost:8001/docs"
        Write-Host "Orchestrator: http://localhost:8002/docs"
        Write-Host "TheHive/Cortex/Shuffle lite adapters: http://localhost:8010/docs"
    }
    "down" { Invoke-Checked docker compose down }
    "build" { Invoke-Checked docker compose build }
    "logs" { Invoke-Checked docker compose logs -f --tail=200 }
    "reset" {
        Invoke-Checked docker compose down -v --remove-orphans
        Invoke-Checked docker compose up --build -d
    }
    "seed" { Invoke-Checked docker compose exec normalizer python /app/infra/scripts/seed_demo_data.py }
    "test" { $env:PYTHONPATH = "."; Invoke-Checked python -m pytest -q tests/unit tests/integration }
    "e2e" { $env:SOC_E2E = "1"; $env:PYTHONPATH = "."; Invoke-Checked python -m pytest -q tests/e2e }
    "demo-scenario-1" { Invoke-JsonPost "http://localhost:8005/scenarios/outbound-beacon" }
    "demo-scenario-2" { Invoke-JsonPost "http://localhost:8005/scenarios/suspicious-script" }
    "demo-scenario-3" { Invoke-JsonPost "http://localhost:8005/scenarios/bruteforce-success" }
    "demo-exfil" { Invoke-JsonPost "http://localhost:8005/scenarios/exfil-burst" }
    "generate-reports" { Invoke-JsonPost "http://localhost:8004/reports/generate-all" }
    "screenshots" {
        New-Item -ItemType Directory -Force -Path "docs/screenshots" | Out-Null
        Write-Host "Open http://localhost:8080 and save stakeholder screenshots under docs/screenshots/."
    }
    "lint" { $env:PYTHONPATH = "."; Invoke-Checked python -m ruff check shared apps tests }
    "format" { $env:PYTHONPATH = "."; Invoke-Checked python -m ruff format shared apps tests }
    "ps" { Invoke-Checked docker compose ps }
    "prod-up" {
        if (-not (Test-Path ".env.production")) {
            throw "Missing .env.production. Copy .env.production.example to .env.production and replace CHANGE_ME values."
        }
        Invoke-Checked docker compose -f docker-compose.yml -f docker-compose.production.yml --env-file .env.production up -d --build
        Write-Host "Production-mode UI: http://127.0.0.1:8080"
        Write-Host "Send X-SOC-API-Key for API access. Do not expose these ports directly to the internet."
    }
    "prod-ai-up" {
        if (-not (Test-Path ".env.production")) {
            throw "Missing .env.production. Copy .env.production.example to .env.production and replace CHANGE_ME values."
        }
        Invoke-Checked docker compose -f docker-compose.yml -f docker-compose.production.yml --env-file .env.production --profile ai up -d --build
        Write-Host "Production-mode UI with Ollama analyst: http://127.0.0.1:8080"
        Write-Host "Ollama API: http://127.0.0.1:11434"
    }
    "prod-down" {
        Invoke-Checked docker compose -f docker-compose.yml -f docker-compose.production.yml --env-file .env.production down
    }
    "ai-up" {
        Invoke-Checked docker compose --profile ai up -d ollama
        Invoke-Checked docker compose --profile ai run --rm ollama-pull
    }
    "ai-pull" {
        Invoke-Checked docker compose --profile ai run --rm ollama-pull
    }
    "attack-list" { Invoke-Checked python .\tools\demo-attack-runner\attack_runner.py list }
    "attack-beacon" { Invoke-Checked powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1 -Scenario outbound-beacon }
    "attack-script" { Invoke-Checked powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1 -Scenario suspicious-script }
    "attack-bruteforce" { Invoke-Checked powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1 -Scenario bruteforce-success }
    "telemetry-beacon" { Invoke-Checked python .\tools\demo-attack-runner\attack_runner.py run outbound-beacon --mode direct }
    "telemetry-script" { Invoke-Checked python .\tools\demo-attack-runner\attack_runner.py run suspicious-script --mode direct }
    "telemetry-bruteforce" { Invoke-Checked python .\tools\demo-attack-runner\attack_runner.py run bruteforce-success --mode direct }
    "atomic-beacon" { Invoke-Checked powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1 -Scenario outbound-beacon }
    "atomic-script" { Invoke-Checked powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1 -Scenario suspicious-script }
    "atomic-bruteforce" { Invoke-Checked powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1 -Scenario bruteforce-success }
    "help" {
        Write-Host "Agentic SOC Core Windows command wrapper"
        Write-Host ""
        Write-Host "Usage:"
        Write-Host "  .\soc.cmd up"
        Write-Host "  .\soc.cmd demo-scenario-1"
        Write-Host "  .\soc.cmd demo-scenario-2"
        Write-Host "  .\soc.cmd demo-scenario-3"
        Write-Host ""
        Write-Host "Commands: up, down, build, logs, reset, seed, test, e2e, demo-scenario-1, demo-scenario-2, demo-scenario-3, demo-exfil, generate-reports, screenshots, lint, format, ps, prod-up, prod-ai-up, prod-down, ai-up, ai-pull, attack-list, attack-beacon, attack-script, attack-bruteforce, telemetry-beacon, telemetry-script, telemetry-bruteforce, atomic-beacon, atomic-script, atomic-bruteforce"
    }
}
