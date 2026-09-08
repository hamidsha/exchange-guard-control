[CmdletBinding()]
param([string]$ConfigPath = 'C:\ProgramData\ExchangeGuardMailboxAgent\agent-config.json')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:AgentVersion = '0.4.0'
$script:ExchangeSession = $null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-AgentLog {
    param([string]$Message, [string]$Level = 'INFO')
    $path = Join-Path (Split-Path -Parent $ConfigPath) 'agent.log'
    Add-Content -LiteralPath $path -Encoding UTF8 -Value ('{0} [{1}] {2}' -f [DateTime]::UtcNow.ToString('o'), $Level, $Message)
}

function ConvertTo-HexString { param([byte[]]$Bytes) return -join ($Bytes | ForEach-Object { $_.ToString('x2') }) }

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    try { return ConvertTo-HexString ($sha.ComputeHash($Bytes)) } finally { $sha.Dispose() }
}

function Invoke-GuardApi {
    param([ValidateSet('GET','POST')][string]$Method, [string]$Path, $BodyObject = $null)
    $uri = ([string]$script:Config.BaseUrl).TrimEnd('/') + $Path
    $body = if ($Method -eq 'POST') { if ($null -eq $BodyObject) { '{}' } else { $BodyObject | ConvertTo-Json -Depth 20 -Compress } } else { '' }
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($body)
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $nonce = [Guid]::NewGuid().ToString('N')
    $canonical = "{0}`n{1}`n{2}`n{3}`n{4}" -f $Method, $Path, $timestamp, $nonce, (Get-Sha256Hex $bodyBytes)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([string]$script:Config.SharedSecret)
    try { $signature = ConvertTo-HexString ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))) } finally { $hmac.Dispose() }
    $headers = @{'X-Node-ID'=[string]$script:Config.NodeId;'X-Timestamp'=$timestamp;'X-Nonce'=$nonce;'X-Signature'=$signature}
    if ($Method -eq 'GET') { return Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 60 }
    return Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 300
}

function Import-ExchangeCommands {
    if (Get-Command Get-Mailbox -ErrorAction SilentlyContinue) { return }
    $uri = [string]$script:Config.ExchangePowerShellUri
    if ([string]::IsNullOrWhiteSpace($uri)) { throw 'ExchangePowerShellUri is required.' }
    $script:ExchangeSession = New-PSSession `
        -ConfigurationName Microsoft.Exchange `
        -ConnectionUri $uri `
        -Authentication Kerberos `
        -ErrorAction Stop
    Import-PSSession `
        -Session $script:ExchangeSession `
        -DisableNameChecking `
        -AllowClobber `
        -ErrorAction Stop | Out-Null
    if (-not (Get-Command Get-Mailbox -ErrorAction SilentlyContinue)) { throw 'RBAC did not expose Get-Mailbox to the service account.' }
}

function Close-ExchangeSession {
    if ($script:ExchangeSession) {
        Remove-PSSession -Session $script:ExchangeSession -ErrorAction SilentlyContinue
        $script:ExchangeSession = $null
    }
}

function Convert-PolicyName {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text
}

function Send-MailboxInventory {
    Import-ExchangeCommands
    $mailboxes = @(
        Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox |
            ForEach-Object {
                [ordered]@{
                    primary_smtp_address = ([string]$_.PrimarySmtpAddress).ToLowerInvariant()
                    display_name = [string]$_.DisplayName
                    alias = [string]$_.Alias
                    sam_account_name = [string]$_.SamAccountName
                    recipient_type = [string]$_.RecipientTypeDetails
                    organizational_unit = [string]$_.OrganizationalUnit
                    throttling_policy = Convert-PolicyName $_.ThrottlingPolicy
                }
            }
    )
    $policies = @(
        Get-ThrottlingPolicy |
            ForEach-Object {
                [ordered]@{
                    name = [string]$_.Name
                    scope = [string]$_.ThrottlingPolicyScope
                    recipient_rate_limit = [string]$_.RecipientRateLimit
                }
            }
    )
    $response = Invoke-GuardApi -Method POST -Path '/api/agent/v1/mailboxes/snapshot' -BodyObject @{mailboxes=$mailboxes;policies=$policies;captured_at_utc=[DateTime]::UtcNow.ToString('o')}
    return @{mailboxes=$mailboxes.Count;policies=$policies.Count;accepted=$response.ok}
}

function Set-MailboxPolicyBatch {
    param($Payload)
    $assignments = @($Payload.assignments)
    if ($assignments.Count -lt 1 -or $assignments.Count -gt 100) { throw 'A policy batch must contain between 1 and 100 assignments.' }
    $results = @()
    foreach ($item in $assignments) {
        $address = ([string]$item.primary_smtp_address).Trim().ToLowerInvariant()
        $policyName = Convert-PolicyName $item.policy_name
        try {
            if ($address -notmatch '^[^@\s]+@[^@\s]+$') { throw "Invalid SMTP address: $address" }
            $mailbox = Get-Mailbox -Identity $address
            $previous = Convert-PolicyName $mailbox.ThrottlingPolicy
            if ($policyName) {
                $policy = Get-ThrottlingPolicy -Identity $policyName
                if ([string]$policy.ThrottlingPolicyScope -ne 'Regular') { throw "Only Regular policies can be assigned to a mailbox: $($policy.ThrottlingPolicyScope)" }
                Set-Mailbox -Identity $address -ThrottlingPolicy $policyName
            } else {
                Set-Mailbox -Identity $address -ThrottlingPolicy $null
            }
            $actual = Convert-PolicyName (Get-Mailbox -Identity $address).ThrottlingPolicy
            $results += [ordered]@{primary_smtp_address=$address;success=$true;previous_policy=$previous;policy_name=$actual;error=$null}
        } catch {
            $results += [ordered]@{primary_smtp_address=$address;success=$false;previous_policy=$null;policy_name=$policyName;error=$_.Exception.Message}
        }
    }
    return @{results=$results;succeeded=@($results | Where-Object {$_.success}).Count;failed=@($results | Where-Object {-not $_.success}).Count}
}

function Upsert-ThrottlingPolicy {
    param($Payload)
    $name = ([string]$Payload.name).Trim()
    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9_. -]{0,255}$') { throw 'Invalid throttling policy name.' }
    $limitText = [string]$Payload.recipient_rate_limit
    $limit = if ($limitText -ieq 'Unlimited') { 'Unlimited' } else { [int]$limitText }
    if ($limit -ne 'Unlimited' -and ($limit -lt 1 -or $limit -gt 100000)) { throw 'RecipientRateLimit must be 1..100000 or Unlimited.' }
    $existing = Get-ThrottlingPolicy | Where-Object { [string]$_.Name -eq $name } | Select-Object -First 1
    if ($existing) {
        if ([string]$existing.ThrottlingPolicyScope -ne 'Regular') { throw 'Only Regular throttling policies can be changed remotely.' }
        $previous = [string]$existing.RecipientRateLimit
        Set-ThrottlingPolicy -Identity $name -RecipientRateLimit $limit
        $created = $false
    } else {
        New-ThrottlingPolicy -Name $name -ThrottlingPolicyScope Regular -RecipientRateLimit $limit | Out-Null
        $previous = $null
        $created = $true
    }
    $actual = Get-ThrottlingPolicy -Identity $name
    return @{name=$name;created=$created;previous_limit=$previous;recipient_rate_limit=[string]$actual.RecipientRateLimit;scope=[string]$actual.ThrottlingPolicyScope}
}

function Assert-MailboxAddress {
    param([string]$Address)
    $value = $Address.Trim().ToLowerInvariant()
    if ($value -notmatch '^[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,63}$') { throw "Invalid SMTP address: $value" }
    return $value
}

function Quarantine-Mailbox {
    param($Payload)
    $address = Assert-MailboxAddress ([string]$Payload.primary_smtp_address)
    $group = ([string]$Payload.blocked_group).Trim()
    if ([string]::IsNullOrWhiteSpace($group)) { throw 'Blocked outbound group is required.' }
    $cas = Get-CASMailbox -Identity $address
    $previousEws = [bool]$cas.EwsEnabled
    $ewsChanged = $false
    try {
        Set-CASMailbox -Identity $address -EwsEnabled $false
        $ewsChanged = $true
        $members = @(Get-DistributionGroupMember -Identity $group -ResultSize Unlimited)
        $alreadyMember = @($members | Where-Object { ([string]$_.PrimarySmtpAddress).ToLowerInvariant() -eq $address }).Count -gt 0
        if (-not $alreadyMember) { Add-DistributionGroupMember -Identity $group -Member $address }
        return @{primary_smtp_address=$address;blocked_group=$group;previous_ews_enabled=$previousEws;ews_enabled=$false;group_member=$true}
    } catch {
        if ($ewsChanged) { Set-CASMailbox -Identity $address -EwsEnabled $previousEws }
        throw
    }
}

function Release-Mailbox {
    param($Payload)
    $address = Assert-MailboxAddress ([string]$Payload.primary_smtp_address)
    $group = ([string]$Payload.blocked_group).Trim()
    $members = @(Get-DistributionGroupMember -Identity $group -ResultSize Unlimited)
    $isMember = @($members | Where-Object { ([string]$_.PrimarySmtpAddress).ToLowerInvariant() -eq $address }).Count -gt 0
    if ($isMember) { Remove-DistributionGroupMember -Identity $group -Member $address -Confirm:$false }
    $restoreEws = if ($null -eq $Payload.restore_ews_enabled) { $true } else { [bool]$Payload.restore_ews_enabled }
    Set-CASMailbox -Identity $address -EwsEnabled $restoreEws
    return @{primary_smtp_address=$address;blocked_group=$group;ews_enabled=$restoreEws;group_member=$false}
}

function Execute-Command {
    param($Command)
    Import-ExchangeCommands
    switch ([string]$Command.type) {
        'SyncMailboxInventory' { return Send-MailboxInventory }
        'SetMailboxPolicies' { return Set-MailboxPolicyBatch -Payload $Command.payload }
        'UpsertThrottlingPolicy' { return Upsert-ThrottlingPolicy -Payload $Command.payload }
        'QuarantineMailbox' { return Quarantine-Mailbox -Payload $Command.payload }
        'ReleaseMailbox' { return Release-Mailbox -Payload $Command.payload }
        default { throw "Unsupported mailbox command type: $($Command.type)" }
    }
}

function Process-Commands {
    $response = Invoke-GuardApi -Method GET -Path '/api/agent/v1/commands'
    foreach ($command in @($response.commands)) {
        $success = $false; $result = $null; $errorText = $null
        try { $result = Execute-Command $command; $success = $true; Write-AgentLog "Command $($command.id) $($command.type) succeeded" }
        catch { $errorText = $_.Exception.Message; Write-AgentLog "Command $($command.id) $($command.type) failed: $errorText" 'ERROR' }
        Invoke-GuardApi -Method POST -Path ("/api/agent/v1/commands/{0}/result" -f $command.id) -BodyObject @{success=$success;result=$result;error=$errorText} | Out-Null
    }
}

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Agent config not found: $ConfigPath" }
    $script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$script:Config.BaseUrl)) { throw 'BaseUrl is required.' }
    if (-not ([string]$script:Config.BaseUrl).StartsWith('https://') -and -not [bool]$script:Config.AllowHttpForTesting) { throw 'BaseUrl must use HTTPS unless AllowHttpForTesting is true.' }
    Invoke-GuardApi -Method POST -Path '/api/agent/v1/heartbeat' -BodyObject @{agent_type='mailbox-management';agent_version=$script:AgentVersion;hostname=$env:COMPUTERNAME;timestamp_utc=[DateTime]::UtcNow.ToString('o')} | Out-Null
    Process-Commands
    if ([bool]$script:Config.SyncInventoryEveryRun) { Send-MailboxInventory | Out-Null }
    Close-ExchangeSession
    Write-AgentLog 'Run completed successfully.'
    exit 0
} catch {
    Close-ExchangeSession
    Write-AgentLog ("Run failed: {0}`r`n{1}" -f $_.Exception.Message, $_.ScriptStackTrace) 'ERROR'
    exit 1
}
