#!/usr/bin/env bash
set -euo pipefail

REMOTE_USER="${REMOTE_USER:-compliance-agent}"
PUBLIC_KEY="${1:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root or with sudo."
  exit 1
fi

if [[ -z "${PUBLIC_KEY}" ]]; then
  echo "Usage: sudo $0 '<central_server_public_key>'"
  exit 1
fi

apt-get update -y
apt-get install -y openssh-server sudo curl jq auditd

if ! id "${REMOTE_USER}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "${REMOTE_USER}"
fi

mkdir -p "/home/${REMOTE_USER}/.ssh"
chmod 700 "/home/${REMOTE_USER}/.ssh"

grep -qxF "${PUBLIC_KEY}" "/home/${REMOTE_USER}/.ssh/authorized_keys" 2>/dev/null || \
  echo "${PUBLIC_KEY}" >> "/home/${REMOTE_USER}/.ssh/authorized_keys"

sort -u "/home/${REMOTE_USER}/.ssh/authorized_keys" -o "/home/${REMOTE_USER}/.ssh/authorized_keys"

chmod 600 "/home/${REMOTE_USER}/.ssh/authorized_keys"
chown -R "${REMOTE_USER}:${REMOTE_USER}" "/home/${REMOTE_USER}/.ssh"

cat >/etc/sudoers.d/compliance-agent <<'EOF'
compliance-agent ALL=(root) NOPASSWD: /usr/bin/hostnamectl, /usr/bin/lsb_release, /usr/bin/uname, /usr/bin/uptime, /usr/bin/df, /usr/bin/free, /usr/bin/ip, /usr/bin/ss
compliance-agent ALL=(root) NOPASSWD: /usr/bin/apt-mark, /usr/bin/apt-cache, /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/timedatectl
compliance-agent ALL=(root) NOPASSWD: /usr/sbin/nginx, /bin/systemctl status nginx, /bin/systemctl reload nginx
compliance-agent ALL=(root) NOPASSWD: /usr/bin/journalctl, /usr/bin/tail, /usr/bin/grep, /usr/bin/zgrep, /usr/bin/find, /usr/bin/cat
compliance-agent ALL=(root) NOPASSWD: /usr/sbin/ufw status, /usr/bin/docker ps
EOF

chmod 440 /etc/sudoers.d/compliance-agent
visudo -cf /etc/sudoers.d/compliance-agent

systemctl enable ssh auditd
systemctl restart ssh auditd

echo "[+] Managed target bootstrap completed."
