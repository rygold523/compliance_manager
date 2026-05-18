#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Saving current broken diff..."
mkdir -p /opt/rollback_backups
git diff > "/opt/rollback_backups/broken_pdf_report_patch_$(date +%Y%m%d_%H%M%S).diff" || true

echo "[+] Rolling back PDF patch from active files..."
git restore backend/requirements.txt backend/app/api/reports.py frontend/src/main.jsx

echo "[+] Rebuilding backend and frontend..."
sudo docker compose build backend frontend
sudo docker compose up -d backend frontend

echo "[+] Backend logs:"
sudo docker logs --tail=120 aivuln-backend || true

echo "[+] Testing core API..."
curl -s http://localhost:8000/health || true
echo
curl -s http://localhost:8000/api/compliance/score | jq 'keys' || true

echo "[+] Rollback complete. Hard refresh browser with Ctrl+F5."
