param(
    [string]$Mode = "Preview",
    [int[]]$TestNumbers = @(),
    [switch]$IUnderstandRisks
)

& "$PSScriptRoot\Invoke-AgenticAtomic.ps1" -Scenario "outbound-beacon" -Mode $Mode -TestNumbers $TestNumbers -IUnderstandRisks:$IUnderstandRisks

