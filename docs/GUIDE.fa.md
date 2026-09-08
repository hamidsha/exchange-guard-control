# راهنمای نصب و ورود داده

این راهنما مسیر عملی نصب نسخهٔ عمومی Exchange Guard Control را توضیح می‌دهد. داخل این بسته هیچ دامنه، IP، نام سرور، رمز، Log یا دیتابیس واقعی وجود ندارد.

## ۱. نصب پایه روی Linux

پیش‌نیازها: Docker Engine، Docker Compose v2، حداقل ۲ هسته CPU، حدود ۲ گیگابایت RAM و یک نام DNS داخلی با TLS معتبر برای محیط عملیاتی.

```bash
git clone https://github.com/hamidsha/exchange-guard-control.git
cd exchange-guard-control
chmod +x scripts/*.sh
./scripts/generate-env.sh
```

این اسکریپت `.env` و `bootstrap-secrets.txt` را با Permission برابر `600` می‌سازد. هیچ‌کدام را Commit نکنید.

فایل `.env` را ویرایش کنید:

```bash
nano .env
```

حداقل این مقادیر را عوض کنید:

```dotenv
TRUSTED_HOSTS=exchange-guard.example.internal
ORGANIZATION_DOMAINS=example.com,example.net
BLOCKED_OUTBOUND_GROUP=Blocked-Outbound-Senders@example.com
```

دامنه‌های داخلی را از Exchange بگیرید:

```powershell
Get-AcceptedDomain |
    Where-Object {$_.DomainType -in @('Authoritative','InternalRelay')} |
    Sort-Object DomainName |
    Select-Object Name,DomainName,DomainType,Default |
    Format-Table -AutoSize
```

سپس سرویس پایه را اجرا کنید:

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
```

در پاسخ باید `{"status":"ok"}` ببینید. برای Production حتماً Nginx یا Reverse Proxy دیگری با HTTPS جلوی سرویس بگذارید، سپس `SECURE_COOKIES=true` کنید.

## ۲. Agent سرور Edge

پوشهٔ `edge` را روی Edge کپی کنید. فایل نمونه را به `agent-config.json` تبدیل و مقادیر `BaseUrl`، `NodeId` و `SharedSecret` را از `.env` تنظیم کنید.

```powershell
Set-Location 'C:\Temp\exchange-guard-control\edge'

Copy-Item `
    '.\agent-config.example.json' `
    '.\agent-config.json'

notepad.exe '.\agent-config.json'

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

نتیجهٔ موفق Task برابر `0` است. حالت Standalone برای Block/Unblock دستی کافی است؛ صفحهٔ Candidate بدون Analyzer جداگانه داده‌ای ندارد.

## ۳. Agent مدیریت Mailbox

ابتدا RBAC و گروه Block را بسازید:

```powershell
Set-Location 'C:\Temp\exchange-guard-control\integrations\exchange'

.\Initialize-ExchangeGuardRbac.ps1 `
    -DomainDnsName 'example.com' `
    -BlockedGroupAddress 'Blocked-Outbound-Senders@example.com'
```

نام پیش‌فرض سرویس `svc_ExGuardMailbox` است و محدودیت ۲۰ کاراکتری `sAMAccountName` را رعایت می‌کند. از طریق GPO یا Local Security Policy مجوز **Log on as a batch job** را به همین حساب بدهید.

بعد Agent را طبق بخش ۸ فایل [INSTALL.md](INSTALL.md) نصب کنید. از داخل Web یک بار **Sync from Exchange** بزنید. برای چند هزار Mailbox، Sync دستی مناسب‌تر از Sync کامل در هر اجرای پنج‌دقیقه‌ای است.

## ۴. دیتای Message Tracking

بخش‌های Outbound، Spoofing و Reputation ترافیکی فقط وقتی کار می‌کنند که جدول MySQL به نام `GetMessageTrackingLog` دیتای تازه داشته باشد.

ساده‌ترین حالت، MySQL همراه پروژه است:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  up -d --build
```

روی Exchange Management Shell خروجی CSV بگیرید:

```powershell
Set-Location 'C:\Temp\exchange-guard-control\integrations\exchange'

.\Export-MessageTrackingCsv.ps1 `
    -Servers @('EDGE01') `
    -Start (Get-Date).AddMinutes(-20) `
    -End (Get-Date) `
    -OutputDirectory 'C:\ExchangeGuardTrackingExport' `
    -ResultSize 100000
```

CSV را با روش امن به Linux منتقل و Import کنید:

```bash
mkdir -p import
chmod 700 import

docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  run --rm \
  -v "$PWD/import:/import:ro" \
  web \
  python /srv/app/integrations/mysql/import_tracking_csv.py \
  /import/message-tracking-YYYYMMDD-HHMMSS.csv
```

Exporter را می‌توانید هر ۵ تا ۱۵ دقیقه اجرا کنید و ۲۰ دقیقه Overlap بدهید؛ `EventHash` جلوی ثبت رکورد تکراری را می‌گیرد. تأخیر نمایش در Web برابر زمان Collector به‌علاوهٔ فاصلهٔ Scan است.

برای ارسال خروجی، معیار صحیح روی Edge معمولاً این است:

```text
EventId = SENDEXTERNAL
Directionality = Originating
Sender domain = یکی از دامنه‌های سازمان
Recipient domain = خارج از دامنه‌های سازمان
```

رویدادهای DAG مثل `SUBMIT`، `TRANSFER` و HA نباید دوباره به‌عنوان تحویل خارجی شمرده شوند.

بعد از اطمینان از تازه بودن داده، این دو گزینه را فعال کنید:

```dotenv
OUTBOUND_MONITOR_ENABLED=true
INBOUND_SPOOF_MONITOR_ENABLED=true
```

و Web را Recreate کنید:

```bash
docker compose up -d --no-deps --force-recreate web
```

## ۵. Auto-block کشوری

در نسخهٔ عمومی هیچ کشور پیش‌فرضی وجود ندارد و Auto-block خاموش است. ابتدا تمام Relayها، وب‌سایت‌ها و IPهای مجاز را در Allowlist قرار دهید. سپس کدهای دوحرفی کشورهای مجاز را مشخص کنید:

```dotenv
INBOUND_AUTO_BLOCK_ALLOWED_COUNTRIES=US,CA,GB
INBOUND_AUTO_BLOCK_OUTSIDE_ALLOWED_COUNTRIES=true
```

اگر فهرست کشورها خالی باشد، حتی با روشن‌شدن اشتباهی گزینهٔ Auto-block هیچ IPای خودکار Block نمی‌شود.

## ۶. تلگرام و پروکسی

```bash
./scripts/discover-telegram-ids.sh
./scripts/configure-telegram.sh
docker compose up -d --no-deps --force-recreate web
```

پروکسی‌های `http://`، `https://`، `socks5://` و `socks5h://` پشتیبانی می‌شوند. Token و مشخصات Proxy داخل `.env` محرمانه‌اند.

## ۷. Attachment

Message Tracking نام فایل‌های پیوست را نگه نمی‌دارد. بنابراین وضعیت `Not collected` خطا نیست. برای نمایش Attachment باید یک Collector مجاز جداگانه فقط Metadata لازم را به Endpoint امضاشده بفرستد. این پروژه Body یا محتوای Mailbox را جمع‌آوری نمی‌کند.

## ۸. Backup و Update

قبل از هر Update:

```bash
./scripts/backup.sh
cp .env ".env.before-upgrade-$(date +%Y%m%d-%H%M%S)"
chmod 600 .env.before-upgrade-*
```

بعد از جایگزینی Source:

```bash
docker compose config --quiet
docker compose build
docker compose up -d
curl -fsS http://127.0.0.1:8787/healthz
docker compose logs --tail=150 web
```

هیچ‌وقت برای Update معمولی `docker compose down -v` نزنید؛ گزینهٔ `-v` دیتابیس را حذف می‌کند.

جزئیات بیشتر در [Installation](INSTALL.md)، [Data ingestion](DATA-INGESTION.md)، [RBAC](EXCHANGE-RBAC.md) و [Operations](OPERATIONS.md) آمده است.

