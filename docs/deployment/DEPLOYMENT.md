# Database IAM Frontend Integration

This release deploys the centralized PostgreSQL IAM collector, adds a five-minute scheduled collection interval, provides a manual collection action, and displays database users and roles in the IAM tab.

## Security model

- The collector only runs catalog `SELECT` statements.
- Every PostgreSQL connection is forced into a read-only transaction.
- The collector runs as an unprivileged container user.
- Database passwords are resolved from environment variables and are not stored in `sources.json`.
- The collector service is internal to the Docker network and does not publish a host port.
- Backend errors returned to browsers do not contain connection strings or credentials.
- Scheduled and manual collections cannot overlap.

The database account supplied to the collector must also be a dedicated read-only PostgreSQL login without superuser, role-management, database-creation, replication, or bypass-RLS privileges.

## Configure a source

Edit `/opt/ai-vulnerability-management/iam-db-collector/config/sources.json`. Each source follows this structure:

```json
[
  {
    "id": "production-postgres",
    "name": "Production PostgreSQL",
    "type": "postgres",
    "host": "database.example.internal",
    "port": 5432,
    "database": "application_database",
    "username": "compliance_iam_reader",
    "password_env": "IAM_DB_PRODUCTION_PASSWORD",
    "sslmode": "require",
    "connect_timeout": 10,
    "enabled": true,
    "interval_minutes": 5
  }
]
```

Add the password variable referenced by `password_env` to `/opt/ai-vulnerability-management/.env`. Do not put the password in `sources.json`.

## Deploy

```bash
cd /opt/ai-vulnerability-management

sudo mkdir -p deployment-backups

sudo tar -czf \
  "deployment-backups/db-iam-predeploy-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" \
  backend \
  frontend \
  iam-db-collector \
  docker-compose.yml

sudo unzip -o \
  /path/to/iam-db-frontend-integration.zip \
  -d /opt/ai-vulnerability-management

sudo docker compose config --quiet

sudo docker compose build \
  backend \
  frontend \
  iam-db-collector

sudo docker compose up -d \
  --force-recreate \
  backend \
  worker \
  frontend \
  iam-db-collector
```

## Verify

```bash
cd /opt/ai-vulnerability-management

sudo docker compose ps

sudo docker compose logs \
  --since=10m \
  --tail=200 \
  iam-db-collector \
  backend

curl --fail --silent --show-error \
  http://127.0.0.1:8000/api/iam/db-collector/status \
  | python3 -m json.tool

curl --fail --silent --show-error \
  --request POST \
  http://127.0.0.1:8000/api/iam/db-collect \
  | python3 -m json.tool

curl --fail --silent --show-error \
  http://127.0.0.1:8000/api/iam/db-access \
  | python3 -m json.tool
```

After verification, reload the frontend with a hard refresh. The Database Users and Roles table appears after User Group Assignment Matrix and before IAM User Evidence Details.

## Operational behavior

- Enabled sources collect every five minutes.
- The scheduler checks for due work every 30 seconds.
- Failed scheduled collections retry on the next scheduler check.
- The Collect Database IAM Now button runs every enabled source immediately.
- A source must have `enabled` set to `true` before scheduled or manual collection includes it.
