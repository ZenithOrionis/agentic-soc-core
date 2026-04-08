param(
    [int]$Port = 8105,
    [string]$Host = "127.0.0.1",
    [switch]$AllowRemote,
    [string]$Token = ""
)

$ErrorActionPreference = "Stop"

if ($AllowRemote -and $Token -eq "") {
    $bytes = New-Object byte[] 18
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $Token = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$runner = Join-Path $repoRoot "tools\adversary-lab\adversary_lab_console.py"

if ($AllowRemote) {
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
        $lanIp = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object {
                $_.IPAddress -notlike "127.*" -and
                $_.IPAddress -notlike "169.254.*" -and
                $_.PrefixOrigin -ne "WellKnown"
            } |
            Select-Object -First 1 -ExpandProperty IPAddress)
    }
    if (-not $lanIp) {
        $lanIp = "YOUR-LAB-IP"
    }
    Write-Host ""
    Write-Host "AegisCore Adversary Lab"
    Write-Host "Remote lab mode enabled."
    Write-Host "Open this URL on an authorized device inside your lab:"
    Write-Host "http://${lanIp}:${Port}/?token=${Token}"
    Write-Host ""
}
else {
    Write-Host ""
    Write-Host "AegisCore Adversary Lab"
    Write-Host "Open http://${Host}:${Port} in your browser."
    Write-Host ""
}

$args = @($runner, "--host", $Host, "--port", $Port.ToString())
if ($AllowRemote) {
    $args += @("--allow-remote", "--token", $Token)
}

python @args
