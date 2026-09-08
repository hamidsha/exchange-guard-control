[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$SourceDirectory = $PSScriptRoot,
    [string]$InstallDirectory = 'C:\ProgramData\ExchangeGuardAgent',
    [string]$TaskName = 'Exchange Guard Control Agent',
    [int]$EveryMinutes = 2
)

$ErrorActionPreference = 'Stop'
if ($EveryMinutes -lt 1 -or $EveryMinutes -gt 60) { throw 'EveryMinutes must be between 1 and 60.' }
$scriptSource = Join-Path $SourceDirectory 'ExchangeGuard-Agent.ps1'
$configSource = Join-Path $SourceDirectory 'agent-config.json'
if (-not (Test-Path $scriptSource)) { throw "Missing $scriptSource" }
if (-not (Test-Path $configSource)) { throw "Create agent-config.json from the example before installation." }

if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Install Exchange Guard agent and scheduled task')) {
    New-Item -Path $InstallDirectory -ItemType Directory -Force | Out-Null
    Copy-Item $scriptSource (Join-Path $InstallDirectory 'ExchangeGuard-Agent.ps1') -Force
    Copy-Item $configSource (Join-Path $InstallDirectory 'agent-config.json') -Force
    & icacls.exe $InstallDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null

    $exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\ProgramData\ExchangeGuardAgent\ExchangeGuard-Agent.ps1" -ConfigPath "C:\ProgramData\ExchangeGuardAgent\agent-config.json"'
    $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) -RepetitionDuration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Signed Exchange Guard control-plane connector. Executes only fixed allowlisted Exchange operations.' -Force | Out-Null
    Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State
}
