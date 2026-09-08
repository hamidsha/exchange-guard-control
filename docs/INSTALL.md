# Installation

This guide installs a clean Exchange Guard Control deployment. It does not assume any domain name, IP range, server name or existing monitoring database.

## 1. Prerequisites

Control plane:

- A supported Linux distribution.
- Docker Engine and Docker Compose v2.
- At least 2 CPU cores, 2 GB RAM and 10 GB free disk for a small installation.
- An internal DNS name and a trusted TLS certificate for production.
- Network access from the Exchange agents to the HTTPS control-plane URL.

Exchange integration:

- An on-premises Exchange organization exposing the documented Management Shell cmdlets. Development was performed against Exchange 2019; validate other versions, including Subscription Edition, in a lab before production use.
- Exchange Management Shell on the Windows hosts running the agents.
- A dedicated domain service account for the mailbox agent.
- Permission to create Exchange RBAC roles, a mail-enabled security group and a transport rule.

Optional traffic analytics:

- A MySQL-compatible database populated with Exchange message-tracking events, or the optional bundled MySQL service.
- A process that exports and imports new message-tracking rows. A reference CSV path is included in this repository.

## 2. Download and create secrets

Clone the repository or extract a release archive:

```bash
git clone https://github.com/YOUR_ACCOUNT/exchange-guard-control.git
cd exchange-guard-control
chmod +x scripts/*.sh
./scripts/generate-env.sh
```

The script creates two local files:

- `.env`: runtime configuration and secrets.
- `bootstrap-secrets.txt`: the initial web password and agent shared secrets.

Both files are mode `0600` and ignored by Git. Never commit, paste into an issue, or include them in a support bundle.

## 3. Configure organization values

Edit `.env`:

```bash
nano .env
```

At minimum, replace these example values:

```dotenv
TRUSTED_HOSTS=exchange-guard.example.internal
ORGANIZATION_DOMAINS=example.com,example.net
BLOCKED_OUTBOUND_GROUP=Blocked-Outbound-Senders@example.com
```

Obtain authoritative organization domains from Exchange Management Shell:

```powershell
Get-AcceptedDomain |
    Where-Object {$_.DomainType -in @('Authoritative','InternalRelay')} |
    Sort-Object DomainName |
    Select-Object Name,DomainName,DomainType,Default |
    Format-Table -AutoSize
```

Use only domains actually owned and handled by the organization. Do not add public recipient domains such as `gmail.com` merely because they appear on a mailbox proxy address.

Keep these enforcement features disabled during initial installation:

```dotenv
OUTBOUND_MONITOR_ENABLED=false
INBOUND_SPOOF_MONITOR_ENABLED=false
INBOUND_AUTO_BLOCK_OUTSIDE_ALLOWED_COUNTRIES=false
TELEGRAM_ENABLED=false
```

## 4. Start the base control plane

Validate and start PostgreSQL plus the web application:

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
```

Expected health response:

```json
{"status":"ok"}
```

Inspect startup logs if health does not become ready:

```bash
docker compose logs --tail=200 web db
```

## 5. Publish through HTTPS

The default web binding is loopback-only. Put Nginx, HAProxy or another internal reverse proxy in front of it. An Nginx example is included at `nginx.example.conf`.

Copy and edit the example:

```bash
sudo cp nginx.example.conf /etc/nginx/conf.d/exchange-guard.conf
sudo nginx -t
sudo systemctl reload nginx
```

Then set:

```dotenv
SECURE_COOKIES=true
TRUSTED_HOSTS=exchange-guard.example.internal
```

Recreate only the web container after `.env` changes:

```bash
docker compose up -d --no-deps --force-recreate web
```

The Exchange Windows hosts must trust the certificate chain. Do not bypass certificate validation in production.

## 6. First login

Open the HTTPS URL and sign in with the credentials in `bootstrap-secrets.txt`.

`ADMIN_PASSWORD` is a bootstrap value: it creates the initial administrator only when the user does not yet exist in PostgreSQL. Changing that environment variable later does not reset an existing account.

After verifying login, move the secrets into your normal password-management process. Keep the local files restricted to root.

## 7. Install the Edge agent

Copy the `edge` directory to the Exchange Edge server. In an elevated PowerShell session:

```powershell
Set-Location 'C:\Temp\exchange-guard-control\edge'

Copy-Item `
    -LiteralPath '.\agent-config.example.json' `
    -Destination '.\agent-config.json'

notepad.exe '.\agent-config.json'
```

Set:

- `BaseUrl` to the HTTPS control-plane URL.
- `NodeId` to the value of `BOOTSTRAP_NODE_ID`.
- `SharedSecret` to `BOOTSTRAP_NODE_SECRET`.
- `AllowHttpForTesting` to `false` in production.

The example is already in standalone mode. Leave the adaptive-analyzer fields empty unless you operate a compatible analyzer.

Install and test:

```powershell
.\Install-ExchangeGuardAgent.ps1 -EveryMinutes 2

Start-ScheduledTask -TaskName 'Exchange Guard Control Agent'
Start-Sleep -Seconds 20

Get-ScheduledTaskInfo `
    -TaskName 'Exchange Guard Control Agent' |
    Format-List LastRunTime,LastTaskResult,NextRunTime

Get-Content `
    'C:\ProgramData\ExchangeGuardAgent\agent.log' `
    -Tail 30
```

`LastTaskResult` should be `0`. The node should appear on the Nodes page shortly afterward.

## 8. Install the mailbox agent

First create the least-privilege Exchange roles and block group described in [Exchange RBAC](EXCHANGE-RBAC.md). Then copy the `mailbox` directory to one Exchange mailbox server.

Install from elevated Exchange Management Shell:

```powershell
$Secret = Read-Host 'MAILBOX_NODE_SECRET' -AsSecureString
$Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)

try {
    $PlainSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)

    Set-Location 'C:\Temp\exchange-guard-control\mailbox'

    .\Install-ExchangeGuardMailboxAgent.ps1 `
        -BaseUrl 'https://exchange-guard.example.internal' `
        -NodeId 'mailbox-01' `
        -SharedSecret $PlainSecret `
        -ExchangePowerShellUri 'http://exchange.example.com/PowerShell/' `
        -RunAsUser 'EXAMPLE\svc_ExGuardMailbox' `
        -IntervalMinutes 5
}
finally {
    if ($Pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
    }
    $PlainSecret = $null
    $Secret = $null
}
```

The installer prompts separately for the Windows service-account password used by Task Scheduler.

Verify:

```powershell
Start-ScheduledTask -TaskName 'Exchange Guard Mailbox Agent'
Start-Sleep -Seconds 30

Get-ScheduledTaskInfo `
    -TaskName 'Exchange Guard Mailbox Agent' |
    Format-List LastRunTime,LastTaskResult,NextRunTime

Get-Content `
    'C:\ProgramData\ExchangeGuardMailboxAgent\agent.log' `
    -Tail 30
```

On the Mailboxes page, choose **Sync from Exchange** once. A successful inventory command populates mailbox and Regular throttling-policy records in PostgreSQL.

## 9. Optional message-tracking analytics

Do not enable outbound or spoofing scans until the tracking table contains current data. Follow [Data ingestion](DATA-INGESTION.md), verify timestamps, then enable the monitors in `.env` and recreate the web container.

## 10. Production safety checklist

- HTTPS is enabled and trusted by both Windows agents.
- Port 8787 is not exposed to untrusted networks.
- `.env` and `bootstrap-secrets.txt` are not tracked by Git.
- Both node secrets are different, random and at least 32 characters.
- Mailbox RBAC exposes only the documented commands and parameters.
- The quarantine group exists, is empty initially and has the blocking transport rule.
- All legitimate relay and application IPs are allowlisted before country automation.
- Tracking timestamps are current and interpreted consistently.
- Auto-block remains disabled until audit-only results have been reviewed.
- A PostgreSQL backup has been tested.
