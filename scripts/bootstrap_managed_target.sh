#!/usr/bin/env bash
set -euo pipefail

COMPLIANCE_AGENT_USER="${COMPLIANCE_AGENT_USER:-compliance-agent}"
COLLECTOR_DIR="${COLLECTOR_DIR:-/usr/local/lib/compliance/collectors}"
DASHBOARD_SSH_PUBLIC_KEY="${DASHBOARD_SSH_PUBLIC_KEY:-ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC76Rn4tBkd6tgv3U0Ca5TjVrHJkF2wC6L3BY2yTKFc3hGr/yuvA6iWWQAit701SGz0aBEEZJ2b4JZxjMqzf/0zAL9A64XRMvGZW7eRBisyRb0U8O2LB+QM23ZaVZgTPdsEJykB3aBzIuov4iOhaa+aDGPlFAfuZaLnJxXY0VFS8X2/obGbCYuPDiahib318VzdisgANqxoUk4pLhNbWEoOfHol683V1LvbNABpDvAbdfobg3OrhZGuRJBMd3NcB/e301+MnFgp8xhzLogsuuRVR6Pjuz4zuf4S9alyRtJIOXqV+vZ5RcyB0KGMMBI+h3QT7Y64X4ooJh+KUHHNz64w2MQaY6Vyr3t18wQWpoEnAn4MorTPzs2B560KZB6an3A7TV/GNLEWy0VEtZzTOATbx1DAIfwyNF3AkpdyWOMI0ahEbbQxR+r3/0jO4hJ8aezWqEP4y1KSuZGkyBJB9tCUQicbDhl6+y4UMR/iTi+ovleKxh7HPsJis1PkN+o/T5Jg7bCM3cJaguokZBaZN8FOTGmSe5U4fIcLuAVms9iEm1sn2+9KqGt89VQBsDp7HOM6nGxcLeZsAWGfKthYunnWPDnzcGZIxOgLyiSKR/dk34mq+MYzlJ2Ywgg+f2przI8wzBvnfVTvNERolF7fI2bl/a73wB6n8jqaOIyDGVOThQ== root@aisecurity}"

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

cat <<EOF | sudo tee /etc/sudoers.d/compliance-agent >/dev/null
${COMPLIANCE_AGENT_USER} ALL=(ALL) NOPASSWD: /usr/local/lib/compliance/collectors/*
${COMPLIANCE_AGENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/grep, /usr/bin/cat, /usr/bin/ss, /usr/sbin/ss, /usr/bin/netstat, /usr/sbin/netstat, /usr/sbin/ufw, /usr/sbin/nft, /usr/sbin/iptables, /usr/bin/lsblk, /usr/bin/findmnt, /usr/bin/df, /usr/bin/docker, /usr/bin/dpkg-query, /usr/bin/apt-cache
EOF
sudo chmod 440 /etc/sudoers.d/compliance-agent

echo "[+] Managed target bootstrap complete."
