#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"; APP_USER="${APP_USER:-aivuln}"; SECRET_DIR="${SECRET_DIR:-/root/aivuln-secrets}"; DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"; POSTGRES_DB="${POSTGRES_DB:-aivuln}"; POSTGRES_USER="${POSTGRES_USER:-aivuln}"
mkdir -p "$SECRET_DIR"; chmod 700 "$SECRET_DIR"
for s in postgres_password jwt_secret encryption_key jenkins_webhook_secret; do [[ -f "$SECRET_DIR/$s" ]] || openssl rand -hex 32 > "$SECRET_DIR/$s"; done
POSTGRES_PASSWORD="$(cat "$SECRET_DIR/postgres_password")"; JWT_SECRET="$(cat "$SECRET_DIR/jwt_secret")"; ENCRYPTION_KEY="$(cat "$SECRET_DIR/encryption_key")"; JENKINS_WEBHOOK_SECRET="$(cat "$SECRET_DIR/jenkins_webhook_secret")"
SERVER_IP="$(hostname -I | awk '{print $1}')"
cat > "$APP_ROOT/.env" <<EOF
APP_ENV=production
DATABASE_URL=postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${DB_CONTAINER}:5432/${POSTGRES_DB}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_URL=redis://redis:6379/0
JWT_SECRET=${JWT_SECRET}
ENCRYPTION_KEY=${ENCRYPTION_KEY}
EVIDENCE_ROOT=/app/evidence
REMOTE_EXEC_ENABLED=true
REMOTE_EXEC_USER=compliance-agent
REMOTE_EXEC_KEY=/home/aivuln/.ssh/aivuln_remote_exec
REMOTE_EXEC_TIMEOUT_SECONDS=120
REMOTE_EXEC_REQUIRE_APPROVAL=true
REMOTE_EXEC_ALLOW_ARBITRARY_COMMANDS=false
JENKINS_WEBHOOK_SECRET=${JENKINS_WEBHOOK_SECRET}
AI_ENABLED=false
AI_PROVIDER=ollama
AI_MODEL=llama3.2:3b
AI_BASE_URL=http://host.docker.internal:11434
AI_TEMPERATURE=0.1
AI_MAX_TOKENS=1500
ALLOW_DOCKER_IMAGE_REBUILDS=false
ALLOW_AUTO_NGINX_CHANGES=false
ALLOW_PACKAGE_UPDATES=true
REQUIRE_APPROVAL_FOR_CONFIG_CHANGES=true
REQUIRE_APPROVAL_FOR_SERVICE_RELOADS=true
REQUIRE_APPROVAL_FOR_PRODUCTION=true
PUBLIC_BACKEND_URL=http://${SERVER_IP}:8000
PUBLIC_FRONTEND_URL=http://${SERVER_IP}:3000
EOF
chmod 600 "$APP_ROOT/.env"; chown "$APP_USER:$APP_USER" "$APP_ROOT/.env"
