#!/usr/bin/env bash
set -euo pipefail
SERVER_IP="$(hostname -I | awk '{print $1}')"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -fsS http://127.0.0.1:8000/api/health; echo
curl -fsS http://127.0.0.1:8000/api/collectors/ >/dev/null && echo "Collectors OK"
curl -fsS http://127.0.0.1:8000/api/compliance/score >/dev/null && echo "Compliance score OK"
echo "Frontend: http://${SERVER_IP}:3000"
echo "Backend: http://${SERVER_IP}:8000/docs"
echo "Agent SSH public key:"; cat /home/aivuln/.ssh/aivuln_remote_exec.pub
