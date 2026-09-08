# Public release checklist

Run this checklist before pushing a fork or publishing a release archive.

## Source hygiene

- [ ] `.env` is absent from Git.
- [ ] `bootstrap-secrets.txt` is absent from Git.
- [ ] No database dump, CSV export, log, backup or screenshot is included.
- [ ] No private IP, public production IP, real domain, mailbox address, username, hostname or organization name remains.
- [ ] No bot token, API key, password, cookie secret, node secret or proxy credential remains.
- [ ] Git history was created from the sanitized directory, not copied from a private repository containing secrets.

List every file that would be committed:

```bash
git init
git add --dry-run .
```

Search common sensitive file types and private-network patterns:

```bash
find . -type f \
  \( -name '.env' -o -name '*.log' -o -name '*.dump' -o \
     -name '*.sql.gz' -o -name '*.csv' -o -name '*.tar.gz' -o \
     -name 'bootstrap-secrets.txt' \) -print

rg -n --hidden \
  --glob '!.git/**' \
  --glob '!PUBLICATION-CHECKLIST.md' \
  '(10\.[0-9]{1,3}\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|[0-9]{6,12}:[A-Za-z0-9_-]{25,})' .
```

Review every match manually. Documentation may intentionally contain reserved example domains such as `example.com` and non-routable examples.

If a real secret was ever committed, deleting the file in a later commit is not enough. Rotate the secret and either publish from this clean tree with new history or correctly rewrite the old history.

## Functional checks

- [ ] `docker compose config --quiet` succeeds with a generated `.env`.
- [ ] `docker compose build` succeeds.
- [ ] Base stack becomes healthy.
- [ ] Optional bundled tracking MySQL becomes healthy.
- [ ] Python source compiles.
- [ ] Shell scripts pass `bash -n`.
- [ ] PowerShell scripts parse with Windows PowerShell 5.1.
- [ ] A fresh PostgreSQL volume creates all application tables.
- [ ] A fresh tracking MySQL volume creates `GetMessageTrackingLog`.
- [ ] Login works using generated bootstrap credentials.
- [ ] Auto-block and message-tracking monitors are disabled on a fresh install.
- [ ] Edge standalone mode posts a heartbeat and snapshot.
- [ ] Mailbox RBAC validation exposes only documented parameters.

## Documentation checks

- [ ] Replace `YOUR_ACCOUNT` in README files.
- [ ] Add repository description, topics and a release tag.
- [ ] Confirm the chosen license and copyright holder.
- [ ] Document tested Exchange and Windows versions.
- [ ] Explain that this is not a Microsoft-supported product.
- [ ] Explain optional components and the `Not collected` attachment state.
- [ ] Link to the security reporting policy.

## Suggested first publication

From the sanitized project directory:

```bash
git init -b main
git add .
git status --short
git commit -m 'Initial public release'
git remote add origin git@github.com:YOUR_ACCOUNT/exchange-guard-control.git
git push -u origin main
```

Create the first release from a clean tag:

```bash
git tag -s v0.10.2-public.1 -m 'Exchange Guard Control public release'
git push origin v0.10.2-public.1
```

Use an unsigned tag if your organization does not yet operate signing keys, but document the release hash.

