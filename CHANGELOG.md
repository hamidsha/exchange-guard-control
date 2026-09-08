# Changelog

All notable public changes are documented here.

## 0.10.2-public.1

- Created a clean, infrastructure-neutral public distribution.
- Removed deployment secrets, databases, logs, backups and organization-specific upgrade notes.
- Disabled traffic monitors and automatic enforcement by default.
- Replaced country-specific auto-block defaults with an explicit allowed-country policy and an empty-list fail-safe.
- Added standalone Edge-agent defaults for manual IP/domain control without a private analyzer dependency.
- Added optional bundled MySQL and Unix-socket compose overrides.
- Added a compatible message-tracking schema, Exchange CSV exporter and idempotent CSV importer.
- Added least-privilege Exchange RBAC bootstrap tooling.
- Added full installation, configuration, ingestion, Telegram, proxy, backup, rollback and publication documentation.

