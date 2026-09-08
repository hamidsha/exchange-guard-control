# Data ingestion

Exchange Guard has three independent data paths. PostgreSQL is internal application state; agent snapshots and message-tracking data come from Exchange.

## Data-flow summary

| Dataset | Producer | Destination | Update model |
|---|---|---|---|
| Edge heartbeat, blocks and allowlist state | `ExchangeGuard-Agent.ps1` | Control-plane API / PostgreSQL | Every Edge task run |
| Mailboxes and throttling policies | `ExchangeGuard-MailboxAgent.ps1` | Control-plane API / PostgreSQL | On demand, or every run if explicitly enabled |
| Message-tracking events | Your collector or included CSV tools | MySQL `GetMessageTrackingLog` | Recommended every 5–15 minutes |
| Candidate JSONL | Optional compatible adaptive analyzer | Edge agent event upload | Optional |
| Attachment metadata | Optional authorized custom collector | Signed attachment API | Optional |

Do not manually import application tables into PostgreSQL. They are created and maintained by the web application.

## 1. Edge snapshots

The Edge agent posts:

- node heartbeat and agent version;
- current IP block-list entries;
- sender-filter blocked domains;
- local allowlist state;
- command execution results;
- optional analyzer JSONL events.

In standalone mode, the agent uses `standalone-state.json` and does not require an external adaptive analyzer. The Candidate workflow stays empty unless a compatible analyzer writes the configured JSONL event file.

## 2. Mailbox inventory

The mailbox agent reads only the Exchange fields needed by the UI:

- primary SMTP address;
- display name, alias and `SamAccountName`;
- recipient type and organizational unit;
- assigned throttling policy;
- Regular throttling-policy names and `RecipientRateLimit` values.

Inventory is normally triggered with **Sync from Exchange**. To request a snapshot on every scheduled run, set `SyncInventoryEveryRun` to `true` in the installed mailbox-agent JSON. For several thousand mailboxes, on-demand sync is usually preferable because policy assignments continue to run without reloading the full inventory every five minutes.

## 3. Message-tracking MySQL schema

The exact compatible schema is in `integrations/mysql/schema.sql`. The table name is:

```text
GetMessageTrackingLog
```

Fields used by the application include:

- `Timestamp`, `EventId`, `Directionality`, `Source`, `ConnectorId`;
- `Sender`, `Recipients`, `RecipientCount`;
- `MessageId`, `NetworkMessageId`, `InternalMessageId`;
- `ClientIp`, `OriginalClientIp`, `ClientHostname`;
- `MessageSubject`, `RecipientStatus`, `TransportTrafficType`.

`EventHash` is a unique SHA-256 key used by the included importer to make overlapping CSV imports idempotent.

### Option A: bundled tracking MySQL

This is the easiest clean installation:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  config --quiet

docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  up -d --build
```

The schema is initialized when the `exchange_guard_tracking_db` volume is first created.

Verify the table:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  exec -T tracking-db sh -lc \
  'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SHOW TABLES;"'
```

### Option B: external MySQL over TCP

Create the schema on the external server, then grant the application account `SELECT`, `INSERT` and `UPDATE` only as required by your import process. Set a hostname or IP reachable from the Docker network:

```dotenv
EXCHANGE_MYSQL_HOST=mysql-monitoring.example.internal
EXCHANGE_MYSQL_PORT=3306
EXCHANGE_MYSQL_SOCKET=
EXCHANGE_MYSQL_DATABASE=exchange_monitoring
EXCHANGE_MYSQL_USER=exchange_guard_tracking
EXCHANGE_MYSQL_PASSWORD=replace-with-a-secret
```

If the importer uses the same account, it needs `INSERT`; the web scanner itself is read-only.

### Option C: existing Linux Unix socket

Set:

```dotenv
EXCHANGE_MYSQL_SOCKET=/var/run/mysqld/mysqld.sock
```

Start with the socket mount override:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.mysql-socket.yml \
  up -d --build
```

The host socket must exist before the web container is created. If MySQL restarts and replaces the socket inode, recreate the web container so the bind mount follows the new socket:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.mysql-socket.yml \
  up -d --no-deps --force-recreate web
```

## 4. Export tracking events from Exchange

Run `integrations/exchange/Export-MessageTrackingCsv.ps1` in Exchange Management Shell. Prefer collecting the final Edge event for outbound delivery and the Edge receive/fail events needed for spoof detection.

Example for one Edge server with a 20-minute overlap:

```powershell
Set-Location 'C:\Temp\exchange-guard-control\integrations\exchange'

.\Export-MessageTrackingCsv.ps1 `
    -Servers @('EDGE01') `
    -Start (Get-Date).AddMinutes(-20) `
    -End (Get-Date) `
    -OutputDirectory 'C:\ExchangeGuardTrackingExport' `
    -ResultSize 100000
```

For DAG diagnostics or broader retention, provide multiple server names:

```powershell
.\Export-MessageTrackingCsv.ps1 `
    -Servers @('EDGE01','MBX01','MBX02','MBX03') `
    -Start (Get-Date).AddHours(-1) `
    -End (Get-Date)
```

The exporter creates one CSV and reports its path and row count. It does not transmit the file. Transfer it to Linux using your approved secure file-transfer method.

For outbound counting, Edge `SENDEXTERNAL` + `Originating` is the canonical final-delivery event. DAG `SUBMIT`, `SEND`, `TRANSFER`, HA and agent events are useful for investigation but must not be treated as separate external deliveries.

## 5. Import the CSV

Create a local import directory and copy the exported file there:

```bash
mkdir -p import
chmod 700 import
```

With bundled MySQL:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tracking-mysql.yml \
  run --rm \
  -v "$PWD/import:/import:ro" \
  web \
  python /srv/app/integrations/mysql/import_tracking_csv.py \
  /import/message-tracking-YYYYMMDD-HHMMSS.csv
```

With an external TCP database, use the base compose file:

```bash
docker compose run --rm \
  -v "$PWD/import:/import:ro" \
  web \
  python /srv/app/integrations/mysql/import_tracking_csv.py \
  /import/message-tracking-YYYYMMDD-HHMMSS.csv
```

The importer reports rows read and rows inserted. Reimporting an overlapping file is safe because duplicate `EventHash` values are ignored.

## 6. Verify freshness and semantics

Run inside the web container:

```bash
docker compose exec -T web python - <<'PY'
from app.reputation import _mysql_connection

with _mysql_connection() as connection:
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT
                COUNT(*) AS total_rows,
                MIN(Timestamp) AS oldest_event,
                MAX(Timestamp) AS newest_event
            FROM GetMessageTrackingLog
        """)
        print(cursor.fetchone())

        cursor.execute("""
            SELECT EventId, Directionality, COUNT(*) AS rows_seen
            FROM GetMessageTrackingLog
            WHERE Timestamp >= DATE_SUB(
                (SELECT MAX(Timestamp) FROM GetMessageTrackingLog),
                INTERVAL 24 HOUR
            )
            GROUP BY EventId, Directionality
            ORDER BY rows_seen DESC
            LIMIT 20
        """)
        for row in cursor.fetchall():
            print(row)
PY
```

Confirm that `newest_event` advances after each collection run. A successful dashboard scan cannot discover a message that has not yet reached this table.

## 7. Enable scanners

After verification:

```dotenv
OUTBOUND_MONITOR_ENABLED=true
INBOUND_SPOOF_MONITOR_ENABLED=true
```

Apply:

```bash
docker compose up -d --no-deps --force-recreate web
```

For bundled MySQL, always include the same override files used to start the deployment.

The default scan interval is 15 minutes. Manual **Scan now** runs only against rows already present in MySQL; it does not force Exchange to export new events.

## 8. Scheduling the pipeline

A common low-load schedule is:

1. Every 10 minutes, export the last 20 minutes from Edge.
2. Securely transfer the CSV to Linux.
3. Run the idempotent importer.
4. Keep the application's 15-minute scan interval.
5. Delete or archive imported CSVs according to policy.

The overlap protects against clock and transfer delays. `EventHash` prevents duplicate inserts.

The repository intentionally does not bundle a credentialed cross-server copy job. Transport and credential storage differ by organization and should follow local security policy.

## 9. Attachment metadata

Exchange message-tracking logs do not include attachment names or attachment hashes. Therefore the UI displays **Not collected** unless a separate authorized collector posts metadata to:

```text
POST /api/agent/v1/outbound/attachments
```

That request must use the same signed-agent authentication model. Collect only metadata needed for security analysis, never message bodies, and document retention and access. Attachment absence means “not collected,” not “message had no attachment.”

## 10. Privacy and retention

Tracking rows can contain SMTP addresses, subject lines, client IPs and delivery status. Before production use:

- limit database access to operators who require it;
- encrypt backups and transport channels;
- choose a documented retention period;
- consider omitting `MessageSubject` if it is not necessary;
- never publish production exports or database dumps with the source repository.

