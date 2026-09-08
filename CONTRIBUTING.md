# Contributing

Contributions are welcome through issues and pull requests.

## Before opening an issue

- Read the installation, configuration and operations documentation.
- Remove or replace all real domains, IP addresses, mailbox addresses, hostnames and organization names.
- Never paste `.env`, bot tokens, API keys, node secrets, proxy credentials, database dumps or full message-tracking exports.
- Include the application version, Exchange version, operating-system version and a minimal redacted error.

## Development setup

```bash
cp .env.example .env
```

Replace every `CHANGE_ME` value, keep all monitors disabled and start a local stack:

```bash
docker compose config --quiet
docker compose up -d --build
curl -fsS http://127.0.0.1:8787/healthz
```

For bundled tracking MySQL:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  up -d --build
```

## Pull-request expectations

- Keep command execution allowlisted; never add arbitrary PowerShell execution.
- Preserve HMAC request authentication and replay protection.
- Add conservative, disabled-by-default behavior for new enforcement features.
- Do not weaken IP, domain, CSRF, host or TLS validation.
- Update documentation and `.env.example` for configuration changes.
- Avoid collecting message bodies or credentials.
- Include a rollback path for schema or enforcement changes.
- Verify that existing user data and unrelated working-tree changes are not included.

## Style and basic checks

```bash
python -m compileall -q app integrations/mysql tests
bash -n scripts/*.sh
docker compose config --quiet
docker compose run --rm --no-deps \
  -e DATABASE_URL=sqlite+pysqlite:////tmp/exchange-guard-smoke.sqlite \
  -e ADMIN_USERNAME=smoke-admin \
  -e ADMIN_PASSWORD=smoke-password \
  -e TRUSTED_HOSTS=testserver,localhost,127.0.0.1 \
  web python -m tests.smoke_test
```

Parse all `.ps1` files with Windows PowerShell 5.1 before submitting. Exercise agent changes against a lab Exchange organization using a least-privilege account.
