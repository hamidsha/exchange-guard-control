[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\ExchangeGuardAgent\agent-config.json'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:AgentVersion = '0.4.1'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-AgentLog {
    param([string]$Message, [string]$Level = 'INFO')
    $dir = Split-Path -Parent $ConfigPath
    $path = Join-Path $dir 'agent.log'
    $line = '{0} [{1}] {2}' -f ([DateTime]::UtcNow.ToString('o')), $Level, $Message
    Add-Content -LiteralPath $path -Value $line -Encoding UTF8
}

function Get-PropertyValue {
    param($Object, [string[]]$Names)
    foreach ($name in $Names) {
        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) { return $property.Value }
    }
    return $null
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    try { return ConvertTo-HexString ($sha.ComputeHash($Bytes)) } finally { $sha.Dispose() }
}

function Invoke-GuardApi {
    param(
        [ValidateSet('GET','POST')][string]$Method,
        [string]$Path,
        $BodyObject = $null
    )
    $baseUrl = [string]$script:Config.BaseUrl
    $uri = $baseUrl.TrimEnd('/') + $Path
    $body = ''
    if ($Method -eq 'POST') {
        $body = if ($null -eq $BodyObject) { '{}' } else { $BodyObject | ConvertTo-Json -Depth 20 -Compress }
    }
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($body)
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $nonce = [Guid]::NewGuid().ToString('N')
    $bodyHash = Get-Sha256Hex $bodyBytes
    $canonical = "{0}`n{1}`n{2}`n{3}`n{4}" -f $Method, $Path, $timestamp, $nonce, $bodyHash
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes([string]$script:Config.SharedSecret)
    try { $signature = ConvertTo-HexString ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))) } finally { $hmac.Dispose() }
    $headers = @{
        'X-Node-ID' = [string]$script:Config.NodeId
        'X-Timestamp' = $timestamp
        'X-Nonce' = $nonce
        'X-Signature' = $signature
    }
    if ($Method -eq 'GET') {
        return Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 30
    }
    return Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 30
}

function Import-ExchangeCommands {
    if (Get-Command Get-SenderFilterConfig -ErrorAction SilentlyContinue) { return }
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
    if (-not (Get-Command Get-SenderFilterConfig -ErrorAction SilentlyContinue)) {
        throw 'Exchange PowerShell cmdlets are not available.'
    }
}

function Normalize-Domain {
    param([string]$Domain)
    $value = $Domain.Trim().ToLowerInvariant().TrimEnd('.')
    if ($value -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$') {
        throw "Invalid domain: $Domain"
    }
    return $value
}

function Normalize-Ip {
    param([string]$Ip)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) { throw "Invalid IP address: $Ip" }
    return $parsed.ToString()
}

function Normalize-MailboxAddress {
    param([string]$Address)
    $value = $Address.Trim().ToLowerInvariant()
    if ($value -notmatch '^[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,63}$') { throw "Invalid SMTP address: $value" }
    return $value
}

function Remove-SenderQueueMessages {
    param([string]$Address)
    $sender = Normalize-MailboxAddress $Address
    $found = 0
    $removed = 0
    $skipped = 0
    for ($pass = 1; $pass -le 3; $pass++) {
        $messages = @(Get-Message -Filter "FromAddress -eq '$sender'" -ResultSize Unlimited)
        $found += $messages.Count
        foreach ($message in $messages) {
            try {
                if ([string]$message.Status -eq 'Active') { $skipped++; continue }
                Remove-Message -Identity $message.Identity -WithNDR $false -Confirm:$false
                $removed++
            } catch { $skipped++ }
        }
        if ($messages.Count -eq 0) { break }
        Start-Sleep -Seconds 2
    }
    return @{primary_smtp_address=$sender;found=$found;removed=$removed;skipped=$skipped;with_ndr=$false}
}


function Assert-IpSafeForBlock {
    param([string]$Ip)
    if ([bool]$script:Config.AllowPrivateIpBlocks) { return }
    $address = [System.Net.IPAddress]::Parse($Ip)
    if ([System.Net.IPAddress]::IsLoopback($address)) { throw "Refusing to block loopback address: $Ip" }
    if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $address.GetAddressBytes()
        $unsafe = (
            $b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and $b[1] -eq 168) -or
            $b[0] -ge 224
        )
        if ($unsafe) { throw "Refusing to block private, local, multicast, or reserved address: $Ip" }
    } else {
        $text = $address.ToString().ToLowerInvariant()
        if ($text -eq '::' -or $text -eq '::1' -or $text.StartsWith('fe80:') -or $text.StartsWith('fc') -or $text.StartsWith('fd') -or $text.StartsWith('ff')) {
            throw "Refusing to block private, local, multicast, or reserved IPv6 address: $Ip"
        }
    }
}

function Get-LocalAllowlist {
    $path = [string]$script:Config.AdaptiveBlockerConfigPath
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
        return @{ Ips=@(); Domains=@() }
    }
    $cfg = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $ips = @()
    $domains = @()
    $p = $cfg.PSObject.Properties['AllowlistedIPs']; if ($null -ne $p) { $ips = @($p.Value) }
    $p = $cfg.PSObject.Properties['AllowlistedDomains']; if ($null -ne $p) { $domains = @($p.Value) }
    return @{ Ips=$ips; Domains=$domains }
}

function Sync-Allowlist {
    $remote = Invoke-GuardApi -Method GET -Path '/api/agent/v1/allowlist'
    $path = [string]$script:Config.AdaptiveBlockerConfigPath
    if ([string]::IsNullOrWhiteSpace($path)) { throw 'AdaptiveBlockerConfigPath or standalone state path is required.' }
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
    if (Test-Path -LiteralPath $path) {
        $cfg = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    } else {
        $cfg = New-Object PSObject
    }
    if ($null -eq $cfg.PSObject.Properties['AllowlistedIPs']) { $cfg | Add-Member -NotePropertyName AllowlistedIPs -NotePropertyValue @() }
    if ($null -eq $cfg.PSObject.Properties['AllowlistedDomains']) { $cfg | Add-Member -NotePropertyName AllowlistedDomains -NotePropertyValue @() }
    $cfg.AllowlistedIPs = @($remote.ips)
    $cfg.AllowlistedDomains = @($remote.domains)
    $tmp = "$path.tmp"
    $cfg | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
    return @{ allowlisted_ips=@($remote.ips).Count; allowlisted_domains=@($remote.domains).Count }
}


function Update-Thresholds {
    param($Payload)
    $path = [string]$script:Config.AdaptiveBlockerConfigPath
    $scriptPath = [string]$script:Config.AdaptiveBlockerScriptPath
    if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path -LiteralPath $scriptPath)) {
        throw 'Adaptive analyzer integration is not configured on this Edge node.'
    }
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
        throw "Adaptive blocker config not found: $path"
    }
    $cfg = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $allowed = @(
        'LookbackMinutes','MinMessages','MinUniqueRecipients','MinTopSubjectRatio',
        'MinDomainDominanceRatio','MinScl','MinSclSamples','MinSclEvidenceRatio',
        'RequiredConsecutiveHits','BlockHours','MaxBlocksPerRun'
    )
    $changed = [ordered]@{}
    foreach ($name in $allowed) {
        $incoming = $Payload.PSObject.Properties[$name]
        if ($null -eq $incoming) { continue }
        $existing = $cfg.PSObject.Properties[$name]
        if ($null -eq $existing) {
            $cfg | Add-Member -NotePropertyName $name -NotePropertyValue $incoming.Value
        } else {
            $existing.Value = $incoming.Value
        }
        $changed[$name] = $incoming.Value
    }
    $tmp = "$path.tmp"
    $backup = "$path.before-web-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item -LiteralPath $path -Destination $backup -Force
    $cfg | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
    return @{ changed=$changed; backup=$backup }
}

function Get-IpEntryAddress {
    param($Entry)
    $value = Get-PropertyValue -Object $Entry -Names @('IPAddress','IPRange','Identity')
    if ($null -eq $value) { return [string]$Entry }
    return [string]$value
}

function Get-CurrentSnapshot {
    Import-ExchangeCommands
    $ipBlocks = @()
    foreach ($entry in @(Get-IPBlockListEntry -ErrorAction SilentlyContinue)) {
        $ipBlocks += [ordered]@{
            address = Get-IpEntryAddress $entry
            identity = [string](Get-PropertyValue $entry @('Identity'))
            expiration_time = [string](Get-PropertyValue $entry @('ExpirationTime'))
            has_expired = [bool](Get-PropertyValue $entry @('HasExpired'))
            comment = [string](Get-PropertyValue $entry @('Comment'))
        }
    }
    $sender = Get-SenderFilterConfig
    $exact = @((Get-PropertyValue $sender @('BlockedDomains')) | ForEach-Object { [string]$_ })
    $subs = @((Get-PropertyValue $sender @('BlockedDomainsAndSubdomains')) | ForEach-Object { [string]$_ })
    $allow = Get-LocalAllowlist
    return [ordered]@{
        active_ip_blocks = $ipBlocks
        blocked_domains = $exact
        blocked_domains_and_subdomains = $subs
        allowlisted_ips = @($allow.Ips)
        allowlisted_domains = @($allow.Domains)
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
    }
}

function Send-Events {
    $path = [string]$script:Config.EventsPath
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
        return @{ sent=0 }
    }
    $events = @()
    foreach ($line in @(Get-Content -LiteralPath $path -Tail ([int]$script:Config.MaxEventLines))) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $events += ($line | ConvertFrom-Json) } catch { Write-AgentLog "Skipping invalid event JSON: $($_.Exception.Message)" 'WARN' }
    }
    if ($events.Count -eq 0) { return @{ sent=0 } }
    $response = Invoke-GuardApi -Method POST -Path '/api/agent/v1/events' -BodyObject @{ events=$events }
    return @{ sent=$events.Count; inserted=$response.inserted }
}

function Send-Heartbeat {
    $taskName = [string]$script:Config.AdaptiveBlockerTaskName
    $task = $null
    $taskInfo = $null
    $mode = 'Standalone'
    if (-not [string]::IsNullOrWhiteSpace($taskName)) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $mode = 'Unknown'
        if ($task -and $task.Actions) {
            $args = [string]$task.Actions[0].Arguments
            if ($args -match '-Mode\s+Enforce') { $mode='Enforce' } elseif ($args -match '-Mode\s+Audit') { $mode='Audit' }
        }
    }
    $hash = $null
    $scriptPath = [string]$script:Config.AdaptiveBlockerScriptPath
    if (-not [string]::IsNullOrWhiteSpace($scriptPath) -and (Test-Path -LiteralPath $scriptPath)) {
        $hash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash
    }
    $payload = [ordered]@{
        agent_version = $script:AgentVersion
        hostname = $env:COMPUTERNAME
        mode = $mode
        task_state = if ([string]::IsNullOrWhiteSpace($taskName)) { 'NotConfigured' } elseif ($task) { [string]$task.State } else { 'Missing' }
        last_task_result = if ($taskInfo) { $taskInfo.LastTaskResult } else { $null }
        last_run_time = if ($taskInfo) { [string]$taskInfo.LastRunTime } else { $null }
        next_run_time = if ($taskInfo) { [string]$taskInfo.NextRunTime } else { $null }
        analyzer_sha256 = $hash
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
    }
    Invoke-GuardApi -Method POST -Path '/api/agent/v1/heartbeat' -BodyObject $payload | Out-Null
}

function Assert-NotAllowlisted {
    param([string]$Ip, [string]$Domain)
    $allow = Get-LocalAllowlist
    if ($Ip -and (@($allow.Ips) -contains $Ip)) { throw "IP is allowlisted: $Ip" }
    if ($Domain -and (@($allow.Domains) -contains $Domain)) { throw "Domain is allowlisted: $Domain" }
}

function Set-AnalyzerMode {
    param([ValidateSet('Audit','Enforce')][string]$Mode)
    if ($Mode -eq 'Enforce' -and -not [bool]$script:Config.AllowEnforceModeSwitch) {
        throw 'Remote Enforce mode switching is disabled in agent-config.json.'
    }
    $taskName = [string]$script:Config.AdaptiveBlockerTaskName
    if ([string]::IsNullOrWhiteSpace($taskName)) {
        throw 'Adaptive analyzer integration is not configured on this Edge node.'
    }
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $oldArgs = [string]$task.Actions[0].Arguments
    if ($oldArgs -match '-Mode\s+(Audit|Enforce)') {
        $newArgs = $oldArgs -replace '-Mode\s+(Audit|Enforce)', "-Mode $Mode"
    } else {
        $newArgs = "$oldArgs -Mode $Mode"
    }
    $newAction = New-ScheduledTaskAction -Execute ([string]$task.Actions[0].Execute) -Argument $newArgs
    Set-ScheduledTask -TaskName $taskName -Action $newAction | Out-Null
    return @{ previous_arguments=$oldArgs; new_arguments=$newArgs }
}

function Execute-Command {
    param($Command)
    Import-ExchangeCommands
    $type = [string]$Command.type
    $payload = $Command.payload
    switch ($type) {
        'BlockIp' {
            $ip = Normalize-Ip ([string]$payload.ip)
            Assert-NotAllowlisted -Ip $ip -Domain $null
            Assert-IpSafeForBlock -Ip $ip
            $hours = [Math]::Max(1, [Math]::Min(8760, [int]$payload.duration_hours))
            $expires = (Get-Date).AddHours($hours)
            $comment = "ExchangeGuard $($Command.id): $([string]$payload.reason)"
            Add-IPBlockListEntry -IPAddress $ip -ExpirationTime $expires -Comment $comment -Confirm:$false
            return @{ ip=$ip; expiration_time=[string]$expires; comment=$comment }
        }
        'UnblockIp' {
            $ip = Normalize-Ip ([string]$payload.ip)
            $removed = 0
            foreach ($entry in @(Get-IPBlockListEntry -ErrorAction SilentlyContinue)) {
                if ((Get-IpEntryAddress $entry) -eq $ip) {
                    $identity = Get-PropertyValue $entry @('Identity')
                    if ($null -eq $identity) { throw "Block entry identity missing for $ip" }
                    Remove-IPBlockListEntry -Identity $identity -Confirm:$false
                    $removed++
                }
            }
            return @{ ip=$ip; removed=$removed }
        }
        'BlockDomainExact' {
            $domain = Normalize-Domain ([string]$payload.domain)
            Assert-NotAllowlisted -Ip $null -Domain $domain
            Set-SenderFilterConfig -BlockedDomains @{Add=$domain}
            return @{ domain=$domain; scope='exact' }
        }
        'BlockDomainAndSubdomains' {
            $domain = Normalize-Domain ([string]$payload.domain)
            Assert-NotAllowlisted -Ip $null -Domain $domain
            Set-SenderFilterConfig -BlockedDomainsAndSubdomains @{Add=$domain}
            return @{ domain=$domain; scope='domain_and_subdomains' }
        }
        'UnblockDomainExact' {
            $domain = Normalize-Domain ([string]$payload.domain)
            Set-SenderFilterConfig -BlockedDomains @{Remove=$domain}
            return @{ domain=$domain; scope='exact'; removed=$true }
        }
        'UnblockDomainAndSubdomains' {
            $domain = Normalize-Domain ([string]$payload.domain)
            Set-SenderFilterConfig -BlockedDomainsAndSubdomains @{Remove=$domain}
            return @{ domain=$domain; scope='domain_and_subdomains'; removed=$true }
        }
        'SyncAllowlist' { return Sync-Allowlist }
        'UpdateThresholds' { return Update-Thresholds -Payload $payload }
        'SetEnforcementMode' { return Set-AnalyzerMode -Mode ([string]$payload.mode) }
        'PurgeSenderQueue' { return Remove-SenderQueueMessages -Address ([string]$payload.primary_smtp_address) }
        default { throw "Unsupported command type: $type" }
    }
}

function Process-Commands {
    $response = Invoke-GuardApi -Method GET -Path '/api/agent/v1/commands'
    foreach ($command in @($response.commands)) {
        $success = $false
        $result = $null
        $errorText = $null
        try {
            $result = Execute-Command $command
            $success = $true
            Write-AgentLog "Command $($command.id) $($command.type) succeeded"
        } catch {
            $errorText = $_.Exception.Message
            Write-AgentLog "Command $($command.id) $($command.type) failed: $errorText" 'ERROR'
        }
        Invoke-GuardApi -Method POST -Path ("/api/agent/v1/commands/{0}/result" -f $command.id) -BodyObject @{
            success = $success
            result = $result
            error = $errorText
        } | Out-Null
    }
}

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Agent config not found: $ConfigPath" }
    $script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$script:Config.BaseUrl)) { throw 'BaseUrl is required.' }
    if (-not ([string]$script:Config.BaseUrl).StartsWith('https://') -and -not [bool]$script:Config.AllowHttpForTesting) {
        throw 'BaseUrl must use HTTPS unless AllowHttpForTesting is explicitly true.'
    }
    Send-Heartbeat
    Send-Events | Out-Null
    $snapshot = Get-CurrentSnapshot
    Invoke-GuardApi -Method POST -Path '/api/agent/v1/snapshot' -BodyObject $snapshot | Out-Null
    Process-Commands
    Write-AgentLog 'Run completed successfully.'
    exit 0
} catch {
    Write-AgentLog ("Run failed: {0}`r`n{1}" -f $_.Exception.Message, $_.ScriptStackTrace) 'ERROR'
    exit 1
}
