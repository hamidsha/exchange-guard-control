[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BaseUrl,
    [Parameter(Mandatory=$true)][string]$NodeId,
    [Parameter(Mandatory=$true)][string]$JsonPath,
    [switch]$AllowHttpForTesting
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $BaseUrl.StartsWith('https://') -and -not $AllowHttpForTesting) {
    throw 'BaseUrl must use HTTPS.'
}
if (-not (Test-Path -LiteralPath $JsonPath -PathType Leaf)) {
    throw "Metadata file not found: $JsonPath"
}

$SecretSecure = Read-Host 'MAILBOX_NODE_SECRET' -AsSecureString
$SecretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretSecure)

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return -join ($Bytes | ForEach-Object {$_.ToString('x2')})
}

try {
    $SharedSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($SecretPointer)
    if ($SharedSecret.Length -lt 32) {
        throw 'Shared secret must be at least 32 characters.'
    }

    $InputPayload = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
    $InputItems = @($InputPayload.items)
    if ($InputItems.Count -lt 1 -or $InputItems.Count -gt 1000) {
        throw 'The payload must contain between 1 and 1000 items.'
    }

    $SafeItems = foreach ($Item in $InputItems) {
        $Sender = ([string]$Item.sender).Trim().ToLowerInvariant()
        if ($Sender -notmatch '^[^@\s]+@[^@\s]+$') {
            throw "Invalid sender: $Sender"
        }

        $Attachments = @($Item.attachments)
        if ($Attachments.Count -gt 50) {
            throw "Too many attachments for sender $Sender"
        }

        $SafeAttachments = foreach ($Attachment in $Attachments) {
            $Filename = ([string]$Attachment.filename).Replace('\','/').Split('/')[-1]
            if ([string]::IsNullOrWhiteSpace($Filename)) {
                continue
            }
            [ordered]@{
                filename = $Filename
                content_type = [string]$Attachment.content_type
                size_bytes = [Math]::Max(0, [long]$Attachment.size_bytes)
            }
        }

        [ordered]@{
            sender = $Sender
            message_id = [string]$Item.message_id
            network_message_id = [string]$Item.network_message_id
            event_key = [string]$Item.event_key
            attachments = @($SafeAttachments)
        }
    }

    $Path = '/api/agent/v1/outbound/attachments'
    $Method = 'POST'
    $Body = @{items=@($SafeItems)} | ConvertTo-Json -Depth 8 -Compress
    $Utf8 = New-Object System.Text.UTF8Encoding($false)
    $BodyBytes = $Utf8.GetBytes($Body)

    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $BodyHash = ConvertTo-HexString ($Sha.ComputeHash($BodyBytes))
    }
    finally {
        $Sha.Dispose()
    }

    $Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $Nonce = [Guid]::NewGuid().ToString('N')
    $Canonical = "{0}`n{1}`n{2}`n{3}`n{4}" -f $Method,$Path,$Timestamp,$Nonce,$BodyHash

    $Hmac = New-Object System.Security.Cryptography.HMACSHA256
    $Hmac.Key = $Utf8.GetBytes($SharedSecret)
    try {
        $Signature = ConvertTo-HexString ($Hmac.ComputeHash($Utf8.GetBytes($Canonical)))
    }
    finally {
        $Hmac.Dispose()
    }

    $Headers = @{
        'X-Node-ID' = $NodeId
        'X-Timestamp' = $Timestamp
        'X-Nonce' = $Nonce
        'X-Signature' = $Signature
    }

    $Response = Invoke-RestMethod `
        -Method Post `
        -Uri ($BaseUrl.TrimEnd('/') + $Path) `
        -Headers $Headers `
        -Body $BodyBytes `
        -ContentType 'application/json; charset=utf-8' `
        -UseBasicParsing `
        -TimeoutSec 120

    $Response | Format-List
}
finally {
    if ($SecretPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($SecretPointer)
    }
    $SharedSecret = $null
    $SecretSecure = $null
}

