#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Searching frontend structure..."

find frontend/src -maxdepth 3 -type f | sort

echo
echo "[+] Checking likely router/sidebar files..."

grep -R "react-router-dom\|Routes\|Route\|Sidebar\|nav\|menu" -n frontend/src || true

echo
echo "[+] This script is diagnostic first."
echo "[+] Send the output back before we patch routing, so we do not break the existing UI."
