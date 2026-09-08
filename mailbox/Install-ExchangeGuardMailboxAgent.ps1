[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BaseUrl,
    [Parameter(Mandatory=$true)][string]$SharedSecret,
    [Parameter(Mandatory=$true)][string]$ExchangePowerShellUri,
    [Parameter(Mandatory=$true)][string]$RunAsUser,
    [string]$NodeId = 'mailbox-01',
    [string]$InstallPath = 'C:\ProgramData\ExchangeGuardMailboxAgent',
    [string]$TaskName = 'Exchange Guard Mailbox Agent',
    [int]$IntervalMinutes = 5,
    [switch]$AllowHttpForTesting
)

$ErrorActionPreference = 'Stop'
if (-not $BaseUrl.StartsWith('https://') -and -not $AllowHttpForTesting) { throw 'BaseUrl must use HTTPS.' }
if ($SharedSecret.Length -lt 32) { throw 'SharedSecret must be at least 32 characters.' }
New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ExchangeGuard-MailboxAgent.ps1') -Destination (Join-Path $InstallPath 'ExchangeGuard-MailboxAgent.ps1') -Force
$config = [ordered]@{BaseUrl=$BaseUrl.TrimEnd('/');NodeId=$NodeId;SharedSecret=$SharedSecret;ExchangePowerShellUri=$ExchangePowerShellUri;AllowHttpForTesting=[bool]$AllowHttpForTesting;SyncInventoryEveryRun=$false}
$config | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $InstallPath 'agent-config.json') -Encoding UTF8
$acl = Get-Acl $InstallPath
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($RunAsUser,'Modify','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $InstallPath -AclObject $acl
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $InstallPath 'ExchangeGuard-MailboxAgent.ps1'))
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes ([Math]::Max(1,$IntervalMinutes)))
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$credential = Get-Credential -UserName $RunAsUser -Message 'Enter the Exchange Guard service-account password'
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -User $credential.UserName -Password $plainPassword -RunLevel Highest -Settings $settings -Description 'Signed Exchange mailbox inventory and throttling-policy management agent' -Force | Out-Null
} finally {
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $plainPassword = $null
}
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed and started: $TaskName"
