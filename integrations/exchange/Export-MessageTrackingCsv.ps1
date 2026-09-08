[CmdletBinding()]
param(
    [string[]]$Servers = @($env:COMPUTERNAME),
    [datetime]$Start = (Get-Date).AddMinutes(-20),
    [datetime]$End = (Get-Date),
    [string]$OutputDirectory = 'C:\ExchangeGuardTrackingExport',
    [int]$ResultSize = 50000
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($End -le $Start) {
    throw 'End must be later than Start.'
}

if ($ResultSize -lt 1 -or $ResultSize -gt 1000000) {
    throw 'ResultSize must be between 1 and 1000000.'
}

if (-not (Get-Command Get-MessageTrackingLog -ErrorAction SilentlyContinue)) {
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
}

if (-not (Get-Command Get-MessageTrackingLog -ErrorAction SilentlyContinue)) {
    throw 'Run this script in Exchange Management Shell.'
}

New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

function Get-EventHash {
    param([string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $sha.Dispose()
    }
}

$rows = foreach ($Server in $Servers) {
    Get-MessageTrackingLog `
        -Server $Server `
        -Start $Start `
        -End $End `
        -ResultSize $ResultSize |
        ForEach-Object {
            $recipients = @($_.Recipients) -join ';'
            $recipientStatus = @($_.RecipientStatus) -join ';'
            $timestamp = ([datetime]$_.Timestamp).ToString('yyyy-MM-dd HH:mm:ss.ffffff')
            $hashInput = @(
                $Server,
                $timestamp,
                [string]$_.EventId,
                [string]$_.Source,
                [string]$_.InternalMessageId,
                [string]$_.MessageId,
                [string]$_.NetworkMessageId,
                [string]$_.Sender,
                $recipients
            ) -join '|'

            [ordered]@{
                EventHash = Get-EventHash $hashInput
                Timestamp = $timestamp
                ClientIp = [string]$_.ClientIp
                ClientHostname = [string]$_.ClientHostname
                ConnectorId = [string]$_.ConnectorId
                Source = [string]$_.Source
                EventId = [string]$_.EventId
                InternalMessageId = [string]$_.InternalMessageId
                MessageId = [string]$_.MessageId
                NetworkMessageId = [string]$_.NetworkMessageId
                Recipients = $recipients
                RecipientStatus = $recipientStatus
                TotalBytes = [long]$_.TotalBytes
                RecipientCount = [int]$_.RecipientCount
                MessageSubject = [string]$_.MessageSubject
                Sender = [string]$_.Sender
                ReturnPath = [string]$_.ReturnPath
                Directionality = [string]$_.Directionality
                OriginalClientIp = [string]$_.OriginalClientIp
                TransportTrafficType = [string]$_.TransportTrafficType
            }
        }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$path = Join-Path $OutputDirectory "message-tracking-$stamp.csv"
$rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8

[pscustomobject]@{
    Path = $path
    Rows = @($rows).Count
    Start = $Start
    End = $End
    Servers = $Servers -join ','
}
