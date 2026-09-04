#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"
cd "$APP_ROOT"; docker compose down --remove-orphans || true; docker compose up -d --build
