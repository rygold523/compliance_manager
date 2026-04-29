#!/usr/bin/env bash
set -euo pipefail

BACKEND_HOST_PORT="${BACKEND_HOST_PORT:-8000}"
FRONTEND_HOST_PORT="${FRONTEND_HOST_PORT:-3000}"
DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"
APP_USER="${APP_USER:-aivuln}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root or with sudo."
  exit 1
fi

SERVER_IP="$(hostname -I | awk '{print $1}')"

docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

curl -fsS "http://127.0.0.1:${BACKEND_HOST_PORT}/api/health"
echo

curl -fsSI "http://127.0.0.1:${FRONTEND_HOST_PORT}" | head -5 || true
docker exec aivuln-backend getent hosts "${DB_CONTAINER}" || true

curl -fsS "http://127.0.0.1:${BACKEND_HOST_PORT}/api/collectors/" >/dev/null && echo "Collectors OK"
curl -fsS "http://127.0.0.1:${BACKEND_HOST_PORT}/api/compliance/score" >/dev/null && echo "Compliance score OK"

echo "Frontend: http://${SERVER_IP}:${FRONTEND_HOST_PORT}"
echo "Backend:  http://${SERVER_IP}:${BACKEND_HOST_PORT}/docs"
echo "Agent SSH public key:"
cat "/home/${APP_USER}/.ssh/aivuln_remote_exec.pub"
