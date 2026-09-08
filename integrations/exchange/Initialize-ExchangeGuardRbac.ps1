[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$DomainDnsName,
    [Parameter(Mandatory=$true)][string]$BlockedGroupAddress,
    [string]$ServiceSamAccountName = 'svc_ExGuardMailbox',
    [string]$ServiceDisplayName = 'Exchange Guard Mailbox Service',
    [string]$BlockedGroupName = 'Blocked-Outbound-Senders',
    [string]$BlockedGroupAlias = 'Blocked-Outbound-Senders',
    [string]$BlockedGroupSamAccountName = 'BlockedOutbound',
    [string]$TransportRuleName = 'SECURITY - Block compromised senders',
    [string]$RoleGroupName = 'Exchange Guard Policy Operators',
    [switch]$PasswordNeverExpires
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptCmdlet = $PSCmdlet

if ($ServiceSamAccountName -notmatch '^[A-Za-z0-9._-]{1,20}$') {
    throw 'ServiceSamAccountName must be 1 to 20 safe characters.'
}
if ($BlockedGroupSamAccountName -notmatch '^[A-Za-z0-9._-]{1,20}$') {
    throw 'BlockedGroupSamAccountName must be 1 to 20 safe characters.'
}
if ($BlockedGroupAddress -notmatch '^[^@\s]+@[^@\s]+$') {
    throw 'BlockedGroupAddress must be a valid SMTP address.'
}

Import-Module ActiveDirectory

foreach ($RequiredCommand in @(
    'Get-ManagementRole',
    'New-ManagementRole',
    'Get-ManagementRoleEntry',
    'Set-ManagementRoleEntry',
    'Remove-ManagementRoleEntry',
    'Get-RoleGroup',
    'New-RoleGroup',
    'Get-RoleGroupMember',
    'Add-RoleGroupMember',
    'Get-ManagementRoleAssignment',
    'New-ManagementRoleAssignment',
    'Get-DistributionGroup',
    'New-DistributionGroup',
    'Set-DistributionGroup',
    'Get-TransportRule',
    'New-TransportRule',
    'Set-TransportRule',
    'Enable-TransportRule'
)) {
    if (-not (Get-Command $RequiredCommand -ErrorAction SilentlyContinue)) {
        throw "Missing Exchange command: $RequiredCommand. Run in Exchange Management Shell."
    }
}

if ($WhatIfPreference) {
    Write-Host 'Exchange Guard RBAC plan:' -ForegroundColor Cyan
    Write-Host "  Service account: $ServiceSamAccountName@$DomainDnsName"
    Write-Host "  Role group: $RoleGroupName"
    Write-Host '  Child roles: mailbox policy, throttling policy, CAS and block-group membership'
    Write-Host "  Block group: $BlockedGroupAddress ($BlockedGroupSamAccountName)"
    Write-Host "  Transport rule: $TransportRuleName"
    return
}

$ServiceUpn = '{0}@{1}' -f $ServiceSamAccountName,$DomainDnsName
$ServiceUser = Get-ADUser -Identity $ServiceSamAccountName -ErrorAction SilentlyContinue

if ($null -eq $ServiceUser) {
    if ($PSCmdlet.ShouldProcess($ServiceSamAccountName, 'Create AD service account')) {
        $ServicePassword = Read-Host "Strong password for $ServiceSamAccountName" -AsSecureString
        New-ADUser `
            -Name $ServiceDisplayName `
            -DisplayName $ServiceDisplayName `
            -SamAccountName $ServiceSamAccountName `
            -UserPrincipalName $ServiceUpn `
            -Path (Get-ADDomain).UsersContainer `
            -AccountPassword $ServicePassword `
            -Enabled $true `
            -PasswordNeverExpires ([bool]$PasswordNeverExpires) `
            -CannotChangePassword $true `
            -Description 'Runs the signed Exchange Guard mailbox policy agent'
    }
    $ServiceUser = Get-ADUser -Identity $ServiceSamAccountName
}

function Set-RestrictedExchangeRole {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Parent,
        [Parameter(Mandatory=$true)][hashtable]$Entries
    )

    $Role = Get-ManagementRole -Identity $Name -ErrorAction SilentlyContinue
    if ($null -eq $Role) {
        if ($ScriptCmdlet.ShouldProcess($Name, "Create child role from $Parent")) {
            New-ManagementRole -Name $Name -Parent $Parent | Out-Null
        }
    }

    $AllowedNames = @($Entries.Keys)
    Get-ManagementRoleEntry "${Name}\*" |
        Where-Object {$_.Name -notin $AllowedNames} |
        ForEach-Object {
            if ($ScriptCmdlet.ShouldProcess($_.Identity, 'Remove unneeded role entry')) {
                Remove-ManagementRoleEntry -Identity $_.Identity -Confirm:$false
            }
        }

    foreach ($EntryName in $AllowedNames) {
        $Parameters = @($Entries[$EntryName])
        $Identity = "${Name}\${EntryName}"
        if ($ScriptCmdlet.ShouldProcess($Identity, "Restrict parameters to $($Parameters -join ', ')")) {
            Set-ManagementRoleEntry -Identity $Identity -Parameters $Parameters
        }
    }
}

$MailboxRole = 'Exchange Guard Mailbox Policy Assignment'
$PolicyRole = 'Exchange Guard Throttling Policy Management'
$CasRole = 'Exchange Guard CAS Control'
$GroupRole = 'Exchange Guard Block Group'

Set-RestrictedExchangeRole `
    -Name $MailboxRole `
    -Parent 'Mail Recipients' `
    -Entries @{
        'Get-Mailbox' = @('Identity','ResultSize','RecipientTypeDetails')
        'Set-Mailbox' = @('Identity','ThrottlingPolicy')
    }

Set-RestrictedExchangeRole `
    -Name $PolicyRole `
    -Parent 'Recipient Policies' `
    -Entries @{
        'Get-ThrottlingPolicy' = @('Identity')
        'Set-ThrottlingPolicy' = @('Identity','RecipientRateLimit')
        'New-ThrottlingPolicy' = @('Name','ThrottlingPolicyScope','RecipientRateLimit')
    }

Set-RestrictedExchangeRole `
    -Name $CasRole `
    -Parent 'Mail Recipients' `
    -Entries @{
        'Get-CASMailbox' = @('Identity')
        'Set-CASMailbox' = @('Identity','EwsEnabled')
    }

Set-RestrictedExchangeRole `
    -Name $GroupRole `
    -Parent 'Distribution Groups' `
    -Entries @{
        'Get-DistributionGroupMember' = @('Identity','ResultSize')
        'Add-DistributionGroupMember' = @('Identity','Member')
        'Remove-DistributionGroupMember' = @('Identity','Member','Confirm')
    }

$RequiredRoles = @($MailboxRole,$PolicyRole,$CasRole,$GroupRole)
$RoleGroup = Get-RoleGroup -Identity $RoleGroupName -ErrorAction SilentlyContinue
if ($null -eq $RoleGroup) {
    if ($PSCmdlet.ShouldProcess($RoleGroupName, 'Create role group')) {
        New-RoleGroup `
            -Name $RoleGroupName `
            -Roles $RequiredRoles `
            -Members $ServiceSamAccountName `
            -Description 'Least-privilege operators for Exchange Guard mailbox controls' |
            Out-Null
    }
}
else {
    $ExistingMember = Get-RoleGroupMember -Identity $RoleGroupName |
        Where-Object {$_.SamAccountName -eq $ServiceSamAccountName} |
        Select-Object -First 1
    if ($null -eq $ExistingMember -and $PSCmdlet.ShouldProcess($RoleGroupName, "Add $ServiceSamAccountName")) {
        Add-RoleGroupMember -Identity $RoleGroupName -Member $ServiceSamAccountName
    }

    foreach ($RequiredRole in $RequiredRoles) {
        $Assignment = Get-ManagementRoleAssignment -RoleAssignee $RoleGroupName |
            Where-Object {$_.Role -eq $RequiredRole -and $_.Enabled} |
            Select-Object -First 1
        if ($null -eq $Assignment -and $PSCmdlet.ShouldProcess($RoleGroupName, "Assign $RequiredRole")) {
            New-ManagementRoleAssignment -Role $RequiredRole -SecurityGroup $RoleGroupName | Out-Null
        }
    }
}

$BlockedGroup = Get-DistributionGroup -Identity $BlockedGroupAddress -ErrorAction SilentlyContinue
if ($null -eq $BlockedGroup) {
    if ($PSCmdlet.ShouldProcess($BlockedGroupAddress, 'Create mail-enabled security group')) {
        New-DistributionGroup `
            -Name $BlockedGroupName `
            -DisplayName $BlockedGroupName `
            -Alias $BlockedGroupAlias `
            -SamAccountName $BlockedGroupSamAccountName `
            -PrimarySmtpAddress $BlockedGroupAddress `
            -Type Security |
            Out-Null
    }
}

if ($PSCmdlet.ShouldProcess($BlockedGroupAddress, 'Set manager and safe visibility settings')) {
    Set-DistributionGroup `
        -Identity $BlockedGroupAddress `
        -ManagedBy $ServiceSamAccountName `
        -BypassSecurityGroupManagerCheck

    Set-DistributionGroup `
        -Identity $BlockedGroupAddress `
        -HiddenFromAddressListsEnabled $true `
        -RequireSenderAuthenticationEnabled $true
}

$Rule = Get-TransportRule -Identity $TransportRuleName -ErrorAction SilentlyContinue
if ($null -eq $Rule) {
    if ($PSCmdlet.ShouldProcess($TransportRuleName, 'Create blocking transport rule')) {
        New-TransportRule `
            -Name $TransportRuleName `
            -FromMemberOf $BlockedGroupAddress `
            -DeleteMessage $true `
            -StopRuleProcessing $true `
            -Priority 0 `
            -Mode Enforce |
            Out-Null
    }
}
else {
    if ($PSCmdlet.ShouldProcess($TransportRuleName, 'Verify and enable blocking transport rule')) {
        Set-TransportRule `
            -Identity $TransportRuleName `
            -FromMemberOf $BlockedGroupAddress `
            -DeleteMessage $true `
            -StopRuleProcessing $true `
            -Priority 0 `
            -Mode Enforce
        Enable-TransportRule -Identity $TransportRuleName
    }
}

Write-Host ''
Write-Host 'Exchange Guard RBAC configuration complete.' -ForegroundColor Green
Write-Host "Service account: $ServiceSamAccountName"
Write-Host "Role group: $RoleGroupName"
Write-Host "Blocked group: $BlockedGroupAddress"
Write-Host "Transport rule: $TransportRuleName"
Write-Warning "Grant Log on as a batch job to the service account through local or domain policy before installing the mailbox task."
