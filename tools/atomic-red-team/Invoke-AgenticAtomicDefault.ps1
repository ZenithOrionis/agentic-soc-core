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

function Import-DotEnv {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return
    }
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#") -or -not $line.Contains("=")) {
            return
        }
        $parts = $line.Split("=", 2)
        [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
    }
}

function Get-ScenarioEnvName {
    param([string]$ScenarioName)
    return "ATOMIC_TESTS_" + $ScenarioName.ToUpperInvariant().Replace("-", "_")
}

function Convert-TestNumbers {
    param([string]$Value)
    if ($Value -eq $null -or $Value.Trim() -eq "") {
        return @()
    }
    return @($Value.Split(",") | ForEach-Object { [int]$_.Trim() })
}

function Get-DefaultAtomicRedTeamPath {
    if ($IsLinux) {
        return "/opt/AtomicRedTeam"
    }
    return "C:\AtomicRedTeam"
}

Import-DotEnv ".env.atomic"

$mode = $env:ATOMIC_DEFAULT_MODE
if ($mode -eq $null -or $mode -eq "") {
    $mode = "Preview"
}

$atomicPath = $env:ATOMIC_RED_TEAM_PATH
if ($atomicPath -eq $null -or $atomicPath -eq "") {
    $atomicPath = Get-DefaultAtomicRedTeamPath
}

$testEnvName = Get-ScenarioEnvName -ScenarioName $Scenario
$testNumbers = Convert-TestNumbers -Value ([System.Environment]::GetEnvironmentVariable($testEnvName, "Process"))

if ($mode -eq "Execute") {
    if ($env:ATOMIC_REAL_ATTACKS_ENABLED -ne "true") {
        throw "ATOMIC_DEFAULT_MODE=Execute requires ATOMIC_REAL_ATTACKS_ENABLED=true in .env.atomic."
    }
    if ($testNumbers.Count -eq 0) {
        throw "Execute mode requires explicit test numbers in $testEnvName inside .env.atomic. Run Preview first and choose a low-impact test."
    }
    & "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario $Scenario -Mode Execute -TestNumbers $testNumbers -IUnderstandRisks -AtomicRedTeamPath $atomicPath
    return
}

if ($mode -eq "CheckPrereqs") {
    & "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario $Scenario -Mode CheckPrereqs -TestNumbers $testNumbers -AtomicRedTeamPath $atomicPath
    return
}

if ($mode -eq "Cleanup") {
    & "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario $Scenario -Mode Cleanup -TestNumbers $testNumbers -AtomicRedTeamPath $atomicPath
    return
}

if ($mode -eq "EmitTelemetry") {
    & "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario $Scenario -Mode EmitTelemetry -AtomicRedTeamPath $atomicPath
    return
}

& "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario $Scenario -Mode Preview -TestNumbers $testNumbers -AtomicRedTeamPath $atomicPath
