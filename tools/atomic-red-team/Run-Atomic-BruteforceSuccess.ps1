param(
    [string]$Mode = "Preview",
    [int[]]$TestNumbers = @(),
    [switch]$IUnderstandRisks
)

& "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario "bruteforce-success" -Mode $Mode -TestNumbers $TestNumbers -IUnderstandRisks:$IUnderstandRisks

