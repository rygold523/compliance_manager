#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root or with sudo."
  exit 1
fi

cd "${APP_ROOT}"
docker compose down --remove-orphans || true
docker compose up -d --build
echo "[+] Stack deployed."
