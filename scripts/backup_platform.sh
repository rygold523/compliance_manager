#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"
DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"
POSTGRES_DB="${POSTGRES_DB:-aivuln}"
POSTGRES_USER="${POSTGRES_USER:-aivuln}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/lib/ai-vulnerability-management/backups}"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root or with sudo."
  exit 1
fi

mkdir -p "${BACKUP_DIR}"

docker exec "${DB_CONTAINER}" pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" > "${BACKUP_DIR}/postgres.sql"
rsync -a /var/lib/ai-vulnerability-management/evidence/ "${BACKUP_DIR}/evidence/" 2>/dev/null || true
rsync -a "${APP_ROOT}/controls/" "${BACKUP_DIR}/controls/" 2>/dev/null || true
rsync -a "${APP_ROOT}/framework_mappings/" "${BACKUP_DIR}/framework_mappings/" 2>/dev/null || true
rsync -a "${APP_ROOT}/inventory/" "${BACKUP_DIR}/inventory/" 2>/dev/null || true

echo "[+] Backup completed: ${BACKUP_DIR}"
