param()

$ErrorActionPreference = "Stop"

function Invoke-DemoAttackRunner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scenario,

        [string]$Mode = "direct",
        [string]$NormalizerUrl = "http://127.0.0.1:8001",
        [string]$SimulatorUrl = "http://127.0.0.1:8005",
        [string]$ApiKey = "",
        [double]$DelaySeconds = 0.1
    )

    $runner = Resolve-Path (Join-Path $PSScriptRoot "..\attack_runner.py")
    $args = @(
        $runner.Path,
        "run",
        $Scenario,
        "--mode",
        $Mode,
        "--normalizer-url",
        $NormalizerUrl,
        "--simulator-url",
        $SimulatorUrl,
        "--delay",
        "$DelaySeconds"
    )

    if ($ApiKey -ne "") {
        $args += @("--api-key", $ApiKey)
    }

    Write-Host "[Agentic SOC Demo Attack Runner] Scenario: $Scenario"
    Write-Host "[Agentic SOC Demo Attack Runner] Mode: $Mode"
    Write-Host "[Agentic SOC Demo Attack Runner] This sends benign demo telemetry only."
    & python @args
    if ($LASTEXITCODE -ne 0) {
        throw "Demo attack runner failed with exit code ${LASTEXITCODE}."
    }
}

