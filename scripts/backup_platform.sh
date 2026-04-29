#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"; DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"; POSTGRES_DB="${POSTGRES_DB:-aivuln}"; POSTGRES_USER="${POSTGRES_USER:-aivuln}"; BACKUP_ROOT="${BACKUP_ROOT:-/var/lib/ai-vulnerability-management/backups}"
TS="$(date +%Y%m%d_%H%M%S)"; DIR="$BACKUP_ROOT/$TS"; mkdir -p "$DIR"
docker exec "$DB_CONTAINER" pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "$DIR/postgres.sql"
rsync -a /var/lib/ai-vulnerability-management/evidence/ "$DIR/evidence/" 2>/dev/null || true
rsync -a "$APP_ROOT/controls/" "$DIR/controls/" 2>/dev/null || true
rsync -a "$APP_ROOT/framework_mappings/" "$DIR/framework_mappings/" 2>/dev/null || true
rsync -a "$APP_ROOT/inventory/" "$DIR/inventory/" 2>/dev/null || true
echo "Backup completed: $DIR"
