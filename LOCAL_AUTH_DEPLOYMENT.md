# Compliance Dashboard Local Authentication Deployment

## Security behavior

- Local passwords are hashed with Argon2id.
- The browser receives an opaque session token in an HttpOnly cookie. Only its SHA-256 hash is stored in PostgreSQL.
- Sessions expire after 12 hours by default and can be revoked immediately.
- Five failed attempts cause a 15-minute account lock by default.
- Administrators have read/write access. Auditor and viewer accounts are read-only.
- The health endpoint and separately token-authenticated collector ingestion endpoints remain available without an interactive session.
- New and reset accounts must change their temporary password at first login unless the CLI override is deliberately used.
- Authentication events are stored in `auth_audit_events`.

## Apply the update

Run the included installer from the extracted package. It checks the captured source baseline and refuses to overwrite files that changed after the source bundle was created.

```bash
sudo bash install.sh /opt/ai-vulnerability-management
```

The installer creates a timestamped backup under the project's `deployment-backups` directory before changing files.

## Configure the existing HTTP deployment

Until TLS is installed, add the following to `/opt/ai-vulnerability-management/.env`:

```dotenv
AUTH_PROVIDER=local
AUTH_SESSION_HOURS=12
AUTH_COOKIE_NAME=compliance_session
AUTH_COOKIE_SECURE=false
AUTH_COOKIE_SAMESITE=strict
AUTH_MAX_FAILED_ATTEMPTS=5
AUTH_LOCKOUT_MINUTES=15
AUTH_CORS_ORIGINS=http://192.168.1.246:3000
AUTH_SERVICE_PATHS=/api/health,/api/iam/db-ingest,/api/windows-agent/ingest
```

`AUTH_COOKIE_SECURE=false` is temporary and is required only because the current dashboard is served over HTTP. Change it to `true` when the dashboard is placed behind TLS. Use exact origins; do not restore wildcard CORS.

## Build and update the schema

```bash
cd /opt/ai-vulnerability-management || exit 1

sudo docker compose build backend frontend
sudo bash scripts/apply_schema_updates.sh
sudo docker compose up -d backend worker frontend
```

## Create the first administrator

This command prompts for the temporary password without placing it in shell history or process arguments:

```bash
cd /opt/ai-vulnerability-management || exit 1

sudo docker compose run --rm --no-deps backend \
  python -m app.cli.manage_local_user create \
  --username rgoldberg \
  --display-name "Ryan Goldberg" \
  --role admin
```

At least 14 characters are required. The user must change this temporary password after the first successful login.

## Validate

```bash
cd /opt/ai-vulnerability-management || exit 1

curl -sS -o /dev/null -w 'health=%{http_code}\n' \
  http://127.0.0.1:8000/api/health

curl -sS -o /dev/null -w 'protected=%{http_code}\n' \
  http://127.0.0.1:8000/api/assets/

sudo docker compose run --rm --no-deps \
  -v "$PWD/backend/tests:/app/tests:ro" \
  backend \
  python /app/tests/auth_smoke.py

sudo docker compose ps
sudo docker compose logs --tail=100 backend frontend
```

Expected HTTP results are `health=200` and `protected=401`. Open `http://192.168.1.246:3000`, sign in, change the temporary password, and confirm that the dashboard loads.

## Account administration

List accounts:

```bash
sudo docker compose run --rm --no-deps backend \
  python -m app.cli.manage_local_user list
```

Disable an account and revoke its sessions:

```bash
sudo docker compose run --rm --no-deps backend \
  python -m app.cli.manage_local_user disable --username USERNAME
```

Enable an account:

```bash
sudo docker compose run --rm --no-deps backend \
  python -m app.cli.manage_local_user enable --username USERNAME
```

Reset a password and revoke all active sessions:

```bash
sudo docker compose run --rm --no-deps backend \
  python -m app.cli.manage_local_user reset-password --username USERNAME
```

## Keycloak migration boundary

The authorization boundary is the authenticated user attached to each request. A future Keycloak provider can validate an OpenID Connect session and populate the same user identity and role information. The dashboard API authorization rules and React authentication gate can remain in place while the local login form is replaced by a Keycloak redirect flow.
