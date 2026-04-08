param(
    [string]$Mode = "direct",
    [string]$NormalizerUrl = "http://127.0.0.1:8001",
    [string]$SimulatorUrl = "http://127.0.0.1:8005",
    [string]$ApiKey = "",
    [double]$DelaySeconds = 0.1
)

. "$PSScriptRoot\_AttackRunnerCommon.ps1"
Invoke-DemoAttackRunner -Scenario "persistence-like" -Mode $Mode -NormalizerUrl $NormalizerUrl -SimulatorUrl $SimulatorUrl -ApiKey $ApiKey -DelaySeconds $DelaySeconds

