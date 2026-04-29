#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"
APP_USER="${APP_USER:-aivuln}"
DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"
POSTGRES_DB="${POSTGRES_DB:-aivuln}"
POSTGRES_USER="${POSTGRES_USER:-aivuln}"
SECRET_DIR="${SECRET_DIR:-/root/aivuln-secrets}"
AI_MODEL="${AI_MODEL:-llama3.2:3b}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root or with sudo."
  exit 1
fi

mkdir -p "${SECRET_DIR}"
chmod 700 "${SECRET_DIR}"

for secret in postgres_password jwt_secret encryption_key jenkins_webhook_secret; do
  if [[ ! -f "${SECRET_DIR}/${secret}" ]]; then
    case "$secret" in
      postgres_password) openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32 > "${SECRET_DIR}/${secret}" ;;
      jwt_secret) openssl rand -hex 64 > "${SECRET_DIR}/${secret}" ;;
      encryption_key) openssl rand -hex 32 > "${SECRET_DIR}/${secret}" ;;
      jenkins_webhook_secret) openssl rand -hex 32 > "${SECRET_DIR}/${secret}" ;;
    esac
  fi
done

POSTGRES_PASSWORD="$(cat "${SECRET_DIR}/postgres_password")"
JWT_SECRET="$(cat "${SECRET_DIR}/jwt_secret")"
ENCRYPTION_KEY="$(cat "${SECRET_DIR}/encryption_key")"
JENKINS_WEBHOOK_SECRET="$(cat "${SECRET_DIR}/jenkins_webhook_secret")"
SERVER_IP="$(hostname -I | awk '{print $1}')"

cat > "${APP_ROOT}/.env" <<EOF
APP_ENV=production
APP_HOST=0.0.0.0
APP_PORT=8000
FRONTEND_PORT=3000

POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DATABASE_URL=postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${DB_CONTAINER}:5432/${POSTGRES_DB}

REDIS_URL=redis://redis:6379/0

JWT_SECRET=${JWT_SECRET}
ENCRYPTION_KEY=${ENCRYPTION_KEY}

OIDC_ENABLED=false
OIDC_ISSUER_URL=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
OIDC_REDIRECT_URI=

EVIDENCE_ROOT=/app/evidence
MAX_UPLOAD_MB=100

REMOTE_EXEC_ENABLED=true
REMOTE_EXEC_USER=compliance-agent
REMOTE_EXEC_KEY=/home/aivuln/.ssh/aivuln_remote_exec
REMOTE_EXEC_TIMEOUT_SECONDS=120
REMOTE_EXEC_REQUIRE_APPROVAL=true
REMOTE_EXEC_ALLOW_ARBITRARY_COMMANDS=false

JENKINS_ENABLED=false
JENKINS_BASE_URL=
JENKINS_API_TOKEN=
JENKINS_WEBHOOK_SECRET=${JENKINS_WEBHOOK_SECRET}

AI_ENABLED=false
AI_PROVIDER=ollama
AI_MODEL=${AI_MODEL}
AI_BASE_URL=http://host.docker.internal:11434
AI_TEMPERATURE=0.1
AI_MAX_TOKENS=1500
AI_REQUIRE_JSON=true
AI_ALLOW_ACTION_EXECUTION=false
AI_ALLOW_APPROVAL=false
AI_STRICT_CONTEXT_ONLY=true

ALLOW_DOCKER_IMAGE_REBUILDS=false
ALLOW_AUTO_NGINX_CHANGES=false
ALLOW_PACKAGE_UPDATES=true
REQUIRE_APPROVAL_FOR_CONFIG_CHANGES=true
REQUIRE_APPROVAL_FOR_SERVICE_RELOADS=true
REQUIRE_APPROVAL_FOR_PRODUCTION=true
DEFAULT_PRODUCTION_MODE=read_only
DEFAULT_NONPROD_MODE=approval_required

PUBLIC_BACKEND_URL=http://${SERVER_IP}:8000
PUBLIC_FRONTEND_URL=http://${SERVER_IP}:3000
EOF

chmod 600 "${APP_ROOT}/.env"
chown "${APP_USER}:${APP_USER}" "${APP_ROOT}/.env"
echo "[+] App environment configured."
