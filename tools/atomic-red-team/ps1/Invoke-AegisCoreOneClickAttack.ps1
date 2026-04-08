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
    [string]$Scenario
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$defaultRunner = Join-Path $repoRoot "tools\atomic-red-team\Invoke-AgenticAtomicDefault.ps1"

Write-Host ""
Write-Host "AegisCore one-click attack launcher"
Write-Host "Scenario: $Scenario"
Write-Host "Using .env.atomic for execution mode, Atomic path, and selected test numbers."
Write-Host ""

& $defaultRunner -Scenario $Scenario
if ($LASTEXITCODE -ne 0) {
    throw "One-click attack execution failed with exit code ${LASTEXITCODE}."
}
