param(
    [string]$Mode = "Preview",
    [int[]]$TestNumbers = @(),
    [switch]$IUnderstandRisks
)

& "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario "reverse-shell-like" -Mode $Mode -TestNumbers $TestNumbers -IUnderstandRisks:$IUnderstandRisks

