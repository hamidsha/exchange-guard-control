#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
mkdir -p backups
stamp="$(date +%Y%m%d-%H%M%S)"
docker compose exec -T db sh -lc '
pg_dump \
  --no-owner \
  --no-privileges \
  --username="$POSTGRES_USER" \
  --dbname="$POSTGRES_DB"
' | gzip > "backups/exchange_guard-${stamp}.sql.gz"
chmod 600 "backups/exchange_guard-${stamp}.sql.gz"
echo "Created backups/exchange_guard-${stamp}.sql.gz"
