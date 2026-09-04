#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"; SERVER_IP="$(hostname -I | awk '{print $1}')"
cp "$APP_ROOT/docker-compose.yml" "$APP_ROOT/docker-compose.yml.bak" 2>/dev/null || true
sed -i "s|VITE_API_BASE_URL: .*|VITE_API_BASE_URL: http://${SERVER_IP}:8000|" "$APP_ROOT/docker-compose.yml" || true
