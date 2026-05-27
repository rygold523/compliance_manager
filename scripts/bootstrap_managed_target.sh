#!/usr/bin/env bash
set -euo pipefail

COMPLIANCE_AGENT_USER="${COMPLIANCE_AGENT_USER:-compliance-agent}"
COLLECTOR_DIR="${COLLECTOR_DIR:-/usr/local/lib/compliance/collectors}"

echo "[+] Bootstrapping managed Linux target..."

if ! id "${COMPLIANCE_AGENT_USER}" >/dev/null 2>&1; then
  sudo useradd -m -s /bin/sh "${COMPLIANCE_AGENT_USER}"
fi

sudo mkdir -p "/home/${COMPLIANCE_AGENT_USER}/.ssh"
sudo chmod 700 "/home/${COMPLIANCE_AGENT_USER}/.ssh"

if [ -n "${DASHBOARD_SSH_PUBLIC_KEY:-}" ]; then
  echo "${DASHBOARD_SSH_PUBLIC_KEY}" | sudo tee "/home/${COMPLIANCE_AGENT_USER}/.ssh/authorized_keys" >/dev/null
  sudo chmod 600 "/home/${COMPLIANCE_AGENT_USER}/.ssh/authorized_keys"
fi

sudo chown -R "${COMPLIANCE_AGENT_USER}:${COMPLIANCE_AGENT_USER}" "/home/${COMPLIANCE_AGENT_USER}/.ssh"

sudo mkdir -p "${COLLECTOR_DIR}"
sudo chown -R root:root /usr/local/lib/compliance
sudo chmod -R 755 /usr/local/lib/compliance

cat <<EOF | sudo tee /etc/sudoers.d/compliance-agent >/dev/null
${COMPLIANCE_AGENT_USER} ALL=(ALL) NOPASSWD: /usr/local/lib/compliance/collectors/*
EOF

sudo chmod 440 /etc/sudoers.d/compliance-agent

echo "[+] Managed target bootstrap complete."
