#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"
REPO_URL="${REPO_URL:-https://github.com/rygold523/compliance_manager.git}"

"${SCRIPT_DIR}/install_host.sh"

if [[ ! -d "${APP_ROOT}/.git" ]]; then
  rm -rf "${APP_ROOT}"
  git clone "${REPO_URL}" "${APP_ROOT}"
else
  git -C "${APP_ROOT}" pull --ff-only || true
fi

"${SCRIPT_DIR}/install_postgres_container.sh"
"${SCRIPT_DIR}/configure_app_env.sh"
"${SCRIPT_DIR}/configure_ollama.sh"
"${SCRIPT_DIR}/configure_compose.sh"
"${SCRIPT_DIR}/deploy_stack.sh"
"${SCRIPT_DIR}/apply_schema_updates.sh"
"${SCRIPT_DIR}/validate_stack.sh"
