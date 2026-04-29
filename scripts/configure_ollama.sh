#!/usr/bin/env bash
set -euo pipefail
AI_MODEL="${AI_MODEL:-llama3.2:3b}"
command -v ollama >/dev/null 2>&1 || curl -fsSL https://ollama.com/install.sh | sh
mkdir -p /etc/systemd/system/ollama.service.d
cat >/etc/systemd/system/ollama.service.d/override.conf <<EOF
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF
systemctl daemon-reload; systemctl enable ollama; systemctl restart ollama
for i in {1..30}; do curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && ollama pull "$AI_MODEL" || true
