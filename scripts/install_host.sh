#!/usr/bin/env bash
set -euo pipefail
APP_USER="${APP_USER:-aivuln}"; APP_ROOT="${APP_ROOT:-/opt/ai-vulnerability-management}"; DOCKER_NETWORK="${DOCKER_NETWORK:-aivuln-net}"
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release git jq yq unzip zip tar rsync openssh-client openssh-server ufw nginx fail2ban python3 python3-pip python3-venv acl auditd logrotate netcat-openbsd dnsutils iputils-ping traceroute openssl
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; chmod a+r /etc/apt/keyrings/docker.gpg; fi
UBUNTU_CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME} stable
EOF
apt-get update -y; apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable docker; systemctl restart docker
id "$APP_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$APP_USER"
usermod -aG docker "$APP_USER"
mkdir -p "$APP_ROOT" /var/lib/ai-vulnerability-management/evidence /var/lib/ai-vulnerability-management/job-output /var/lib/ai-vulnerability-management/remote-cache /var/log/ai-vulnerability-management
chown -R "$APP_USER:$APP_USER" "$APP_ROOT" /var/lib/ai-vulnerability-management /var/log/ai-vulnerability-management
docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1 || docker network create "$DOCKER_NETWORK"
mkdir -p "/home/$APP_USER/.ssh"; chown "$APP_USER:$APP_USER" "/home/$APP_USER/.ssh"; chmod 700 "/home/$APP_USER/.ssh"
[[ -f "/home/$APP_USER/.ssh/aivuln_remote_exec" ]] || sudo -u "$APP_USER" ssh-keygen -t ed25519 -f "/home/$APP_USER/.ssh/aivuln_remote_exec" -N "" -C "aivuln-central-remote-exec"
chmod 600 "/home/$APP_USER/.ssh/aivuln_remote_exec"; chmod 644 "/home/$APP_USER/.ssh/aivuln_remote_exec.pub"; chown "$APP_USER:$APP_USER" "/home/$APP_USER/.ssh/aivuln_remote_exec"*
ufw allow OpenSSH || true; ufw allow 80/tcp || true; ufw allow 443/tcp || true; ufw allow 3000/tcp || true; ufw allow 8000/tcp || true
