# Exchange RBAC and mailbox agent

The mailbox agent must run under a dedicated domain account with narrow Exchange permissions. Do not run it as Domain Admin, Organization Management, LocalSystem or a personal administrator.

## What the mailbox agent is allowed to do

| Function | Allowed Exchange operation |
|---|---|
| Inventory | Read UserMailbox identity and assigned throttling policy |
| Policy inventory | Read throttling policies |
| Policy assignment | Set only `ThrottlingPolicy` on a mailbox |
| Policy management | Create or change only Regular policies and `RecipientRateLimit` |
| Quarantine | Read/set only `EwsEnabled`, and add the mailbox to one blocking group |
| Release | Remove the mailbox from that group and restore EWS state |

Queue purge is performed by the Edge agent under LocalSystem on Edge. The web server never receives arbitrary PowerShell text.

## Automated setup

Review the script before use. Run it once from elevated Exchange Management Shell with an account in Organization Management:

```powershell
Set-Location 'C:\Temp\exchange-guard-control\integrations\exchange'

.\Initialize-ExchangeGuardRbac.ps1 `
    -DomainDnsName 'example.com' `
    -BlockedGroupAddress 'Blocked-Outbound-Senders@example.com'
```

The defaults deliberately keep both `sAMAccountName` values within the 20-character Active Directory limit:

- Service account: `svc_ExGuardMailbox`
- Block-group account: `BlockedOutbound`

The account follows the domain password-expiration policy by default. If your approved service-account standard instead uses a non-expiring password with separate rotation controls, pass `-PasswordNeverExpires` explicitly and document the rotation procedure.

Use `-WhatIf` first if the environment has naming conflicts:

```powershell
.\Initialize-ExchangeGuardRbac.ps1 `
    -DomainDnsName 'example.com' `
    -BlockedGroupAddress 'Blocked-Outbound-Senders@example.com' `
    -WhatIf
```

The script creates or verifies:

- the service account;
- four child RBAC roles;
- the `Exchange Guard Policy Operators` role group;
- an empty mail-enabled Universal security group;
- a priority-zero transport rule that deletes messages from group members.

## Required Windows user right

The mailbox Scheduled Task uses a password logon. Grant the service account **Log on as a batch job** on the mailbox server through domain Group Policy or Local Security Policy. Confirm that **Deny log on as a batch job** does not apply.

Verify the effective local policy:

```powershell
$Account = New-Object System.Security.Principal.NTAccount(
    'EXAMPLE',
    'svc_ExGuardMailbox'
)

$Sid = $Account.Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

$PolicyFile = 'C:\Temp\ExchangeGuard-UserRights.cfg'

secedit.exe /export `
    /cfg $PolicyFile `
    /areas USER_RIGHTS

Select-String `
    -Path $PolicyFile `
    -Pattern '^SeBatchLogonRight','^SeDenyBatchLogonRight'

Write-Host "Service account SID: $Sid"
```

Manage this right through your normal GPO process; do not silently rewrite domain security policy from an application installer.

## Validate least privilege

Open a remote Exchange session using the service account:

```powershell
$Credential = Get-Credential `
    -UserName 'EXAMPLE\svc_ExGuardMailbox' `
    -Message 'Exchange Guard service-account password'

$Session = New-PSSession `
    -ConfigurationName Microsoft.Exchange `
    -ConnectionUri 'http://exchange.example.com/PowerShell/' `
    -Authentication Kerberos `
    -Credential $Credential

$Module = Import-PSSession `
    -Session $Session `
    -DisableNameChecking `
    -Prefix EG
```

Expected commands:

```powershell
Get-Command `
    Get-EGMailbox,Set-EGMailbox, `
    Get-EGThrottlingPolicy,Set-EGThrottlingPolicy,New-EGThrottlingPolicy, `
    Get-EGCASMailbox,Set-EGCASMailbox, `
    Get-EGDistributionGroupMember,Add-EGDistributionGroupMember,Remove-EGDistributionGroupMember |
    Select-Object Name,CommandType |
    Format-Table -AutoSize
```

Confirm dangerous `Set-Mailbox` parameters are absent:

```powershell
$Parameters = @((Get-Command Set-EGMailbox).Parameters.Keys)

[pscustomobject]@{
    ThrottlingPolicyAllowed = $Parameters -contains 'ThrottlingPolicy'
    ForwardingAddressAllowed = $Parameters -contains 'ForwardingAddress'
    ForwardingSmtpAllowed = $Parameters -contains 'ForwardingSmtpAddress'
    DatabaseAllowed = $Parameters -contains 'Database'
    EmailAddressesAllowed = $Parameters -contains 'EmailAddresses'
    SendOnBehalfAllowed = $Parameters -contains 'GrantSendOnBehalfTo'
} | Format-List
```

Expected result: only `ThrottlingPolicyAllowed` is `True`.

Clean up the test session:

```powershell
Remove-PSSession $Session
Remove-Module $Module.Name -Force -ErrorAction SilentlyContinue
```

## Validate the quarantine control

The blocking group must start empty:

```powershell
$GroupAddress = 'Blocked-Outbound-Senders@example.com'
$RuleName = 'SECURITY - Block compromised senders'

Get-DistributionGroup $GroupAddress |
    Format-List Name,PrimarySmtpAddress,GroupType,ManagedBy,HiddenFromAddressListsEnabled

Get-DistributionGroupMember $GroupAddress -ResultSize Unlimited |
    Format-Table Name,PrimarySmtpAddress -AutoSize

Get-TransportRule $RuleName |
    Format-List Name,State,Mode,Priority,FromMemberOf,DeleteMessage,StopRuleProcessing
```

Expected rule state:

- `Enabled`
- `Enforce`
- sender condition is the exact block group
- `DeleteMessage` is `True`
- `StopRuleProcessing` is `True`

## Install and test the mailbox agent

Follow step 8 in [Installation](INSTALL.md). After a successful task run, use **Sync from Exchange** in the web UI.

For large organizations, sync is asynchronous. The agent accepts one command, reads all UserMailbox objects, posts one snapshot and exits. Do not refresh or queue repeated sync commands while one is pending.

## Understanding quarantine

When an operator confirms quarantine, the control plane queues coordinated fixed commands:

1. The mailbox agent disables EWS for the mailbox.
2. It adds the mailbox to the blocking security group.
3. The transport rule deletes new messages from group members.
4. The Edge agent purges queued messages matching that sender.
5. Results and errors are stored in Commands, Incidents and Audit.

Quarantine does not reset an AD password, revoke already issued credentials, disable every Exchange protocol or investigate the endpoint. Treat it as containment, not complete incident response.

Release removes group membership and restores the recorded EWS state. Review the account and reset credentials before release.
