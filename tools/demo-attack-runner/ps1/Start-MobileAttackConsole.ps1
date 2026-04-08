param(
    [int]$Port = 8099,
    [string]$NormalizerUrl = "http://127.0.0.1:8001",
    [string]$ApiKey = "",
    [string]$Token = "",
    [ValidateSet("telemetry", "atomic")]
    [string]$Backend = "telemetry"
)

$ErrorActionPreference = "Stop"

if ($Token -eq "") {
    $bytes = New-Object byte[] 18
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $Token = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

if ($ApiKey -eq "" -and (Test-Path ".env.production")) {
    $line = Select-String -Path ".env.production" -Pattern "^SOC_API_KEY=" | Select-Object -First 1
    if ($line) {
        $ApiKey = $line.ToString().Split("=", 2)[1]
    }
}

if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
    $lanIp = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.PrefixOrigin -ne "WellKnown"
        } |
        Select-Object -First 1 -ExpandProperty IPAddress)
} else {
    $lanIp = (hostname -I 2>$null).Trim().Split(" ") |
        Where-Object { $_ -and $_ -notlike "127.*" -and $_ -notlike "169.254.*" } |
        Select-Object -First 1
}

if (-not $lanIp) {
    $lanIp = "YOUR-LAPTOP-IP"
}

$url = "http://${lanIp}:${Port}/?token=${Token}"
Write-Host ""
Write-Host "Agentic SOC Mobile Demo Attack Console"
Write-Host "Open this URL on your phone while connected to the same Wi-Fi:"
Write-Host $url
Write-Host ""
Write-Host "Backend: $Backend"
if ($Backend -eq "atomic") {
    Write-Host "Atomic mode uses .env.atomic. Execute requires ATOMIC_REAL_ATTACKS_ENABLED=true and explicit test numbers."
} else {
    Write-Host "Telemetry mode only sends benign demo telemetry to the SOC normalizer."
}
Write-Host "Press Ctrl+C here to stop the phone console."
Write-Host ""

$runner = Join-Path (Get-Location) "tools/demo-attack-runner/mobile_attack_console.py"
python $runner --host 0.0.0.0 --port $Port --normalizer-url $NormalizerUrl --api-key $ApiKey --token $Token --backend $Backend
