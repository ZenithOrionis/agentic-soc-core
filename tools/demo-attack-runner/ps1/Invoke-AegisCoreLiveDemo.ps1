param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "outbound-beacon",
        "suspicious-script",
        "bruteforce-success",
        "exfil-burst",
        "persistence-like",
        "suspicious-download",
        "reverse-shell-like"
    )]
    [string]$Scenario,

    [string]$NormalizerUrl = "http://127.0.0.1:8001",
    [string]$SimulatorUrl = "http://127.0.0.1:8005",
    [string]$ApiKey = "",
    [double]$DelaySeconds = 0.1
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$atomicRunner = Join-Path $repoRoot "tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1"

Write-Host ""
Write-Host "AegisCore live demo launcher"
Write-Host "Scenario: $Scenario"
Write-Host "Step 1/2: executing the real Atomic test configured in .env.atomic"
Write-Host ""

$pwsh = if (Get-Command pwsh -ErrorAction SilentlyContinue) {
    "pwsh"
} elseif (Get-Command powershell.exe -ErrorAction SilentlyContinue) {
    "powershell.exe"
} else {
    "powershell"
}

& $pwsh -NoProfile -ExecutionPolicy Bypass -File $atomicRunner -Scenario $Scenario
if ($LASTEXITCODE -ne 0) {
    throw "Atomic phase failed with exit code ${LASTEXITCODE}. Telemetry injection was not performed."
}

Write-Host ""
Write-Host "Step 2/2: injecting matching SOC telemetry so the AegisCore dashboard reflects the attack path."
Write-Host ""

. "$PSScriptRoot\_AttackRunnerCommon.ps1"
Invoke-DemoAttackRunner -Scenario $Scenario -Mode "direct" -NormalizerUrl $NormalizerUrl -SimulatorUrl $SimulatorUrl -ApiKey $ApiKey -DelaySeconds $DelaySeconds
