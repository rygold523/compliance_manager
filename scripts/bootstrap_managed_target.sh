#!/usr/bin/env bash
set -euo pipefail

COMPLIANCE_AGENT_USER="${COMPLIANCE_AGENT_USER:-compliance-agent}"
COLLECTOR_DIR="${COLLECTOR_DIR:-/usr/local/lib/compliance/collectors}"
DASHBOARD_SSH_PUBLIC_KEY="${DASHBOARD_SSH_PUBLIC_KEY:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DISPATCHER_SOURCE="${SCRIPT_DIR}/compliance_agent_command.py"

if [[ -z "${DASHBOARD_SSH_PUBLIC_KEY}" ]]; then
  echo "DASHBOARD_SSH_PUBLIC_KEY is required." >&2
  exit 1
fi

if [[ ! -f "${DISPATCHER_SOURCE}" ]]; then
  echo "Missing dispatcher: ${DISPATCHER_SOURCE}" >&2
  exit 1
fi

echo "[+] Bootstrapping managed Linux target..."

if ! id "${COMPLIANCE_AGENT_USER}" >/dev/null 2>&1; then
  sudo useradd -m -s /bin/sh "${COMPLIANCE_AGENT_USER}"
fi

sudo mkdir -p "/home/${COMPLIANCE_AGENT_USER}/.ssh"
echo "${DASHBOARD_SSH_PUBLIC_KEY}" | sudo tee "/home/${COMPLIANCE_AGENT_USER}/.ssh/authorized_keys" >/dev/null
sudo chown -R "${COMPLIANCE_AGENT_USER}:${COMPLIANCE_AGENT_USER}" "/home/${COMPLIANCE_AGENT_USER}/.ssh"
sudo chmod 700 "/home/${COMPLIANCE_AGENT_USER}/.ssh"
sudo chmod 600 "/home/${COMPLIANCE_AGENT_USER}/.ssh/authorized_keys"

sudo mkdir -p "${COLLECTOR_DIR}"
sudo chown -R root:root /usr/local/lib/compliance
sudo chmod -R 755 /usr/local/lib/compliance

sudo install \
  -o root \
  -g root \
  -m 0755 \
  "${DISPATCHER_SOURCE}" \
  /usr/local/sbin/compliance-agent-command

cat <<EOF | sudo tee /etc/sudoers.d/.compliance-agent.new >/dev/null
Defaults:${COMPLIANCE_AGENT_USER} !requiretty
${COMPLIANCE_AGENT_USER} ALL=(root) NOPASSWD: /usr/local/sbin/compliance-agent-command *
EOF

sudo chown root:root /etc/sudoers.d/.compliance-agent.new
sudo chmod 0440 /etc/sudoers.d/.compliance-agent.new
sudo visudo -cf /etc/sudoers.d/.compliance-agent.new
sudo mv -f \
  /etc/sudoers.d/.compliance-agent.new \
  /etc/sudoers.d/compliance-agent
sudo rm -f /etc/sudoers.d/compliance-agent-collectors
sudo visudo -cf /etc/sudoers

echo "[+] Managed target bootstrap complete."
