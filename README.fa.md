# Exchange Guard Control

Exchange Guard Control یک کنترل‌پلین Self-hosted برای Exchange On-premises است. این پروژه مدیریت Block/Allowlist روی Edge، موجودی Mailboxها، تخصیص Throttling Policy، قرنطینه حساب، پایش ارسال خروجی، کشف جعل دامنه داخلی، GeoIP، هشدار Telegram و Audit کامل را در یک رابط وب جمع می‌کند.

> این پروژه Community است و وابستگی یا پشتیبانی رسمی از طرف Microsoft ندارد. تمام عملیات Enforce را ابتدا در محیط آزمایش یا Maintenance Window بررسی کنید.

## مدل ارتباطی

- Web روی Linux و داخل Docker اجرا می‌شود.
- PostgreSQL وضعیت عملیاتی، Commandها و Audit را نگهداری می‌کند.
- Agentهای Windows با HMAC درخواست‌ها را امضا می‌کنند و فقط Commandهای از پیش تعریف‌شده را Pull می‌کنند.
- Web هیچ WinRM، SSH یا PowerShell دلخواهی روی Exchange اجرا نمی‌کند.
- MySQL مربوط به Message Tracking اختیاری است؛ بدون آن بخش‌های Outbound، Spoofing و Reputation ترافیکی غیرفعال می‌مانند.

## نصب سریع

```bash
git clone https://github.com/hamidsha/exchange-guard-control.git
cd exchange-guard-control
./scripts/generate-env.sh
```

سپس `.env` را ویرایش کنید و حداقل این موارد را مطابق سازمان خود قرار دهید:

```dotenv
TRUSTED_HOSTS=exchange-guard.example.internal
ORGANIZATION_DOMAINS=example.com,example.net
BLOCKED_OUTBOUND_GROUP=Blocked-Outbound-Senders@example.com
```

اجرای پایه:

```bash
docker compose config
docker compose build
docker compose up -d
curl -fsS http://127.0.0.1:8787/healthz
```

رمز Admin و Secretهای Agent در `bootstrap-secrets.txt` ایجاد می‌شوند. این فایل و `.env` در `.gitignore` هستند و نباید Commit شوند.

## نکات مهم

- حالت پیش‌فرض Auto-block خاموش است.
- مانیتورهای وابسته به Message Tracking تا زمان تنظیم MySQL خاموش‌اند.
- دامنه‌های `ORGANIZATION_DOMAINS` باید از خروجی `Get-AcceptedDomain` استخراج شوند.
- IP تمام Relayها، وب‌سایت‌ها و سرویس‌های مجاز باید قبل از Auto-block در Allowlist ثبت شود.
- Attachment از Message Tracking قابل استخراج نیست و بدون Collector مجاز با وضعیت `Not collected` نمایش داده می‌شود.
- Edge Agent می‌تواند بدون Adaptive Analyzer برای Block/Unblock دستی اجرا شود؛ بخش Candidate به Analyzer جداگانه نیاز دارد.

راهنمای کامل در فایل‌های زیر است:

- [راهنمای کامل فارسی](docs/GUIDE.fa.md)
- [نصب](docs/INSTALL.md)
- [تنظیمات](docs/CONFIGURATION.md)
- [RBAC اکسچنج](docs/EXCHANGE-RBAC.md)
- [ورود اطلاعات](docs/DATA-INGESTION.md)
- [ورود اختیاری Metadata پیوست‌ها](docs/ATTACHMENTS.md)
- [تلگرام و پروکسی](docs/TELEGRAM.md)
- [Backup و Rollback](docs/OPERATIONS.md)
- [امنیت](SECURITY.md)

مجوز انتشار پروژه [MIT](LICENSE) است.
