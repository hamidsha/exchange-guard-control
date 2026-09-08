# Security model

## Reporting a vulnerability

Use the repository's private GitHub Security Advisory flow when available. Do not open a public issue containing an exploitable vulnerability, production address, credential, message-tracking export or database content.

Include the affected version, a minimal sanitized reproduction, expected impact and any suggested mitigation. Maintainers should acknowledge reports before requesting production diagnostics.

## Deployment model

- Web container binds to `127.0.0.1:8787` by default.
- HTTPS termination is expected at an internal reverse proxy.
- Agent authentication uses HMAC-SHA256 over method, path, timestamp, nonce and body hash.
- Agent accepts only fixed command types; arbitrary PowerShell is not supported.
- UI uses signed server-side session cookies, SameSite=Lax and CSRF tokens.
- Passwords use Argon2.
- PostgreSQL is not published to the host network.
- Web container runs as non-root, read-only, drops all Linux capabilities and has no-new-privileges.
- Domain and IP inputs are validated before commands are queued and again on Edge.
- Allowlist is checked centrally and on Edge.
- Enforce mode requires both a typed web confirmation and `AllowEnforceModeSwitch=true` on Edge.
- Telegram callbacks are accepted only from configured numeric user IDs and the configured chat ID.
- Telegram quarantine callback data contains only a random, expiring, single-use alert token; it never accepts a mailbox address or PowerShell text from Telegram.
- The Telegram bot token remains in the root-owned `.env` file and is never stored in PostgreSQL or application audit details.
- Telegram ignores ambient proxy environment variables and uses only the explicitly configured `TELEGRAM_PROXY_URL`.
- GeoIP sends only the detected public source IP to the configured HTTPS provider, uses the explicit GeoIP/Telegram proxy, and ignores ambient proxy variables.
- Automatic country blocking never acts on failed/unknown GeoIP results, FAIL-only traffic, private addresses or centrally trusted IPs.
- Keep the web interface on a management VLAN and restrict ingress to administrator subnets.
- Use a trusted internal/organizational CA. Do not disable TLS validation in the Agent.

## Explicit non-goals

- The project does not accept arbitrary PowerShell commands from the web application.
- It does not collect message bodies or mailbox credentials.
- It does not replace Exchange patching, endpoint response, MFA, credential rotation or a secure email gateway.
- GeoIP and reputation results are decision support, not proof of abuse.
