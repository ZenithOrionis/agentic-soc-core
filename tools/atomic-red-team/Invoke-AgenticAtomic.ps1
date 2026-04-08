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

    [ValidateSet("EmitTelemetry", "Preview", "CheckPrereqs", "Execute", "Cleanup")]
    [string]$Mode = "Preview",

    [string]$AtomicRedTeamPath = "C:\AtomicRedTeam",
    [string]$AtomicsPath = "",
    [string]$ModulePath = "",

    [int[]]$TestNumbers = @(),
    [switch]$IUnderstandRisks
)

$ErrorActionPreference = "Stop"

$ScenarioMap = @{
    "outbound-beacon" = @{
        Technique = @{
            Default = "T1071.001"
            Linux = "T1071.001"
        }
        Name = @{
            Default = "Application Layer Protocol: Web Protocols"
            Linux = "Application Layer Protocol: Web Protocols"
        }
        SafeFallback = "Run-Telemetry-OutboundBeacon.ps1"
        Guidance = "Pick an atomic that produces benign HTTP/S callback telemetry in your lab."
    }
    "suspicious-script" = @{
        Technique = @{
            Default = "T1059.003"
            Linux = "T1059.004"
        }
        Name = @{
            Default = "Command and Scripting Interpreter: Windows Command Shell"
            Linux = "Command and Scripting Interpreter: Unix Shell"
        }
        SafeFallback = "Run-Telemetry-SuspiciousScript.ps1"
        Guidance = "Pick a benign command-line atomic that does not download or execute untrusted payloads."
    }
    "bruteforce-success" = @{
        Technique = @{
            Default = "T1110"
            Linux = "T1110"
        }
        Name = @{
            Default = "Brute Force"
            Linux = "Brute Force"
        }
        SafeFallback = "Run-Telemetry-BruteforceSuccess.ps1"
        Guidance = "Prefer telemetry emission unless you have a disposable auth target."
    }
    "exfil-burst" = @{
        Technique = @{
            Default = "T1041"
            Linux = "T1041"
        }
        Name = @{
            Default = "Exfiltration Over C2 Channel"
            Linux = "Exfiltration Over C2 Channel"
        }
        SafeFallback = "Run-ExfilBurst.ps1"
        Guidance = "Avoid real data transfer. Use a disposable lab target only."
    }
    "persistence-like" = @{
        Technique = @{
            Default = "T1053.005"
            Linux = "T1053.003"
        }
        Name = @{
            Default = "Scheduled Task/Job: Scheduled Task"
            Linux = "Scheduled Task/Job: Cron"
        }
        SafeFallback = "Run-PersistenceLike.ps1"
        Guidance = "Run cleanup after any scheduled-task atomic."
    }
    "suspicious-download" = @{
        Technique = @{
            Default = "T1105"
            Linux = "T1105"
        }
        Name = @{
            Default = "Ingress Tool Transfer"
            Linux = "Ingress Tool Transfer"
        }
        SafeFallback = "Run-SuspiciousDownload.ps1"
        Guidance = "Do not download untrusted payloads. Use preview/check-prereqs first."
    }
    "reverse-shell-like" = @{
        Technique = @{
            Default = "T1105"
            Linux = "T1105"
        }
        Name = @{
            Default = "Ingress Tool Transfer / Callback-like Network Behavior"
            Linux = "Ingress Tool Transfer / Callback-like Network Behavior"
        }
        SafeFallback = "Run-ReverseShellLike.ps1"
        Guidance = "Use telemetry mode for demos. Do not open real shells."
    }
}

function Resolve-ScenarioValue {
    param(
        [hashtable]$ScenarioDetails,
        [string]$Field
    )

    $fieldValue = $ScenarioDetails[$Field]
    if ($fieldValue -isnot [hashtable]) {
        return $fieldValue
    }

    if ($IsLinux -and $fieldValue.ContainsKey("Linux")) {
        return $fieldValue["Linux"]
    }

    return $fieldValue["Default"]
}

function Resolve-AtomicModule {
    param(
        [string]$ProvidedModulePath,
        [string]$ProvidedAtomicRedTeamPath
    )

    if ($ProvidedModulePath -ne "" -and (Test-Path $ProvidedModulePath)) {
        return (Resolve-Path $ProvidedModulePath).Path
    }

    $candidates = @(
        (Join-Path $ProvidedAtomicRedTeamPath "invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"),
        (Join-Path $ProvidedAtomicRedTeamPath "Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psd1"),
        (Join-Path $ProvidedAtomicRedTeamPath "invoke-atomicredteam\Invoke-AtomicRedTeam.psm1"),
        (Join-Path $ProvidedAtomicRedTeamPath "Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psm1")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    $installed = Get-Module -ListAvailable -Name Invoke-AtomicRedTeam | Select-Object -First 1
    if ($installed) {
        return $installed.Path
    }

    return ""
}

function Resolve-AtomicsPath {
    param(
        [string]$ProvidedAtomicsPath,
        [string]$ProvidedAtomicRedTeamPath
    )

    if ($ProvidedAtomicsPath -ne "" -and (Test-Path $ProvidedAtomicsPath)) {
        return (Resolve-Path $ProvidedAtomicsPath).Path
    }

    $candidate = Join-Path $ProvidedAtomicRedTeamPath "atomics"
    if (Test-Path $candidate) {
        return (Resolve-Path $candidate).Path
    }

    return ""
}

function Invoke-SafeFallbackTelemetry {
    param([string]$FallbackScript)

    $fallbackDir = Join-Path (Split-Path -Parent $PSScriptRoot) "demo-attack-runner/ps1"
    $scriptPath = Resolve-Path (Join-Path $fallbackDir $FallbackScript)
    & $scriptPath.Path
    if ($LASTEXITCODE -ne 0) {
        throw "Safe fallback telemetry failed with exit code ${LASTEXITCODE}."
    }
}

$scenarioInfo = $ScenarioMap[$Scenario]
$technique = Resolve-ScenarioValue -ScenarioDetails $scenarioInfo -Field "Technique"
$techniqueName = Resolve-ScenarioValue -ScenarioDetails $scenarioInfo -Field "Name"

Write-Host ""
Write-Host "Agentic SOC Atomic Red Team bridge"
Write-Host "Scenario: $Scenario"
Write-Host "Technique: $technique - $techniqueName"
Write-Host "Mode: $Mode"
Write-Host "Guidance: $($scenarioInfo.Guidance)"
Write-Host ""

if ($Mode -eq "EmitTelemetry") {
    Write-Host "Using safe SOC telemetry fallback instead of running an Atomic test."
    Invoke-SafeFallbackTelemetry -FallbackScript $scenarioInfo.SafeFallback
    return
}

$module = Resolve-AtomicModule -ProvidedModulePath $ModulePath -ProvidedAtomicRedTeamPath $AtomicRedTeamPath
$atomics = Resolve-AtomicsPath -ProvidedAtomicsPath $AtomicsPath -ProvidedAtomicRedTeamPath $AtomicRedTeamPath

if ($module -eq "" -or $atomics -eq "") {
    Write-Host "Atomic Red Team / Invoke-AtomicRedTeam was not found locally."
    Write-Host "Expected examples:"
    Write-Host "  Module: C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
    Write-Host "  Atomics: C:\AtomicRedTeam\atomics"
    Write-Host ""
    Write-Host "For a safe demo without installing Atomic Red Team, run:"
    Write-Host "  pwsh -NoProfile -ExecutionPolicy Bypass -File ./tools/atomic-red-team/Invoke-AgenticAtomic.ps1 -Scenario $Scenario -Mode EmitTelemetry"
    throw "Atomic Red Team local files not found."
}

Import-Module $module -Force
$params = @{
    AtomicTechnique = $technique
    PathToAtomicsFolder = $atomics
}

if ($TestNumbers.Count -gt 0) {
    $params["TestNumbers"] = $TestNumbers
}

if ($Mode -eq "Preview") {
    Invoke-AtomicTest @params -ShowDetailsBrief
    return
}

if ($Mode -eq "CheckPrereqs") {
    Invoke-AtomicTest @params -CheckPrereqs
    return
}

if ($Mode -eq "Cleanup") {
    Invoke-AtomicTest @params -Cleanup
    return
}

if ($Mode -eq "Execute") {
    if (-not $IUnderstandRisks) {
        throw "Refusing to execute Atomic tests without -IUnderstandRisks. Preview and check prerequisites first."
    }
    if ($TestNumbers.Count -eq 0) {
        throw "Refusing to execute every test for $technique. Provide explicit -TestNumbers."
    }
    Write-Host "Executing selected Atomic Red Team test numbers only: $($TestNumbers -join ', ')"
    Invoke-AtomicTest @params
    return
}
