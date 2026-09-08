# Operations, backup and rollback

## Health checks

Application health:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
docker compose logs --tail=100 web db
```

Agent health is visible on the Nodes page. On Windows:

```powershell
Get-ScheduledTaskInfo `
    -TaskName 'Exchange Guard Control Agent' |
    Format-List LastRunTime,LastTaskResult,NextRunTime

Get-ScheduledTaskInfo `
    -TaskName 'Exchange Guard Mailbox Agent' |
    Format-List LastRunTime,LastTaskResult,NextRunTime
```

A completed task should normally report result `0`. Read the corresponding `agent.log` before rerunning or changing permissions.

## Back up PostgreSQL

Use the included script from the repository root:

```bash
chmod +x scripts/backup.sh
./scripts/backup.sh
ls -lh backups/
```

Backups contain operational history and may contain email addresses, IP addresses and audit metadata. Store them as sensitive data and never commit them.

For an independent custom-format backup:

```bash
docker compose exec -T db sh -lc '
pg_dump \
  --format=custom \
  --no-owner \
  --no-privileges \
  --username="$POSTGRES_USER" \
  --dbname="$POSTGRES_DB"
' > exchange-guard-postgres.dump

chmod 600 exchange-guard-postgres.dump
```

Validate the archive catalog:

```bash
docker compose exec -T db pg_restore --list < exchange-guard-postgres.dump | head -n 30
```

## Back up configuration

Back up these files separately with secret-aware storage:

- `.env`
- reverse-proxy configuration and certificates
- installed Edge and mailbox agent JSON files
- any external collector schedule or credentials

The repository source itself should come from a tagged Git commit or signed release artifact, not from an untracked live-container copy.

## Tracking database backup

Tracking data is independent of PostgreSQL. With bundled MySQL:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  exec -T tracking-db sh -lc '
mysqldump \
  --single-transaction \
  --user="$MYSQL_USER" \
  --password="$MYSQL_PASSWORD" \
  "$MYSQL_DATABASE"
' | gzip > exchange-guard-tracking.sql.gz
```

Large message-tracking tables should also have a retention policy. Retention is intentionally not automated by the application because requirements differ by organization.

## Upgrade procedure

Before an upgrade:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
./scripts/backup.sh
cp .env ".env.before-upgrade-$(date +%Y%m%d-%H%M%S)"
chmod 600 .env.before-upgrade-*
```

Fetch or extract the new source while preserving your `.env`, then:

```bash
docker compose config --quiet
docker compose build --pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
docker compose logs --tail=150 web
```

The application creates missing PostgreSQL tables during startup. Always read release notes before upgrading across versions.

Update Windows agent files only after the control plane is healthy. Preserve each installed `agent-config.json`, replace the `.ps1` file, validate syntax and run the task once manually.

## Rollback

Keep the previous source tree or container image tag and the pre-upgrade PostgreSQL backup. To roll back application code:

1. Stop only the web service.
2. Restore the previous source/image.
3. Rebuild and start web.
4. Check health and logs.

Do not run `docker compose down -v` during a routine rollback; `-v` deletes named database volumes.

Database rollback may discard newer commands and audit records. Perform it only when a schema incompatibility requires it and after taking another copy of the current database.

## Restore PostgreSQL into an empty database

Stop web first:

```bash
docker compose stop web
```

For a custom-format archive, recreate the target database through your normal PostgreSQL procedure, then run:

```bash
docker compose exec -T db sh -lc '
pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  --username="$POSTGRES_USER" \
  --dbname="$POSTGRES_DB"
' < exchange-guard-postgres.dump
```

Start and verify:

```bash
docker compose start web
curl -fsS http://127.0.0.1:8787/healthz
docker compose logs --tail=100 web
```

Test restores in a separate environment before relying on them for recovery.

## Common problems

### MySQL connection says localhost refused

Inside a container, `localhost` is the container itself. Use a reachable MySQL DNS/IP, the bundled tracking compose override, or the socket override.

### Unix socket exists on the host but scans fail

If the MySQL service recreated its socket after the container started, force-recreate web with `docker-compose.mysql-socket.yml` so the mount follows the current inode.

### Mailbox task never starts

Check Task Scheduler Operational events for logon error `2147943785`. Confirm the password and grant **Log on as a batch job**; ensure no deny policy overrides it.

### Mailbox sync fails on `ErrorAction`

Do not add common parameters such as `ErrorAction` to restricted remote commands unless required. The bundled agent avoids passing `ErrorAction` to Exchange cmdlets whose custom RBAC entries do not expose it.

### Outbound message appears late

Latency equals collector interval plus scan interval. A conservative 5–15 minute collection interval and 15-minute application scan avoid unnecessary Exchange load. Confirm `MAX(Timestamp)` in MySQL before troubleshooting the UI.

### Attachment status is `Not collected`

This is expected unless an authorized attachment-metadata collector has been integrated. Message-tracking logs do not expose attachment names.

## Safe decommissioning

Before removing anything, export audit history and take database backups. Disable scheduled tasks first, then remove the Windows agents. Remove Exchange RBAC roles, role group, transport rule and blocking group only after verifying no incident still depends on them.

Deleting Docker volumes permanently removes application state. Never include volume deletion in an unattended uninstall command.

