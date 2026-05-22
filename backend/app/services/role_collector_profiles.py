from __future__ import annotations

from typing import Any


BASELINE_LINUX_COLLECTORS = {
    "trend_micro_ds_agent": {
        "label": "Trend Micro ds_agent",
        "control_ids": ["SI-03", "VM-02"],
        "command": "if systemctl list-unit-files | grep -q '^ds_agent.service'; then systemctl is-active ds_agent || true; elif test -x /opt/ds_agent/dsa_control; then echo present; else echo missing; fi",
    },
    "automox_amagent": {
        "label": "Automox amagent",
        "control_ids": ["VM-02", "CM-05"],
        "command": "if systemctl list-unit-files | grep -q '^amagent.service'; then systemctl is-active amagent || true; elif command -v amagent >/dev/null 2>&1; then echo present; else echo missing; fi",
    },
    "duo_mfa_linux": {
        "label": "Duo MFA PAM",
        "control_ids": ["AC-01", "AC-04"],
        "command": "printf 'pam_duo_conf='; test -f /etc/duo/pam_duo.conf && echo present || echo missing; printf 'pam_duo_sshd='; grep -R 'pam_duo.so' /etc/pam.d/sshd /etc/pam.d/common-auth 2>/dev/null | head -20 || true",
    },
    "wazuh_agent": {
        "label": "Wazuh Agent",
        "control_ids": ["SI-01", "SI-03"],
        "command": "if systemctl list-unit-files | grep -q '^wazuh-agent.service'; then systemctl is-active wazuh-agent || true; elif test -d /var/ossec; then echo present; else echo missing; fi",
    },
    "listening_ports": {
        "label": "Listening Ports",
        "control_ids": ["NS-01", "NS-02"],
        "command": "ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true",
    },
    "time_sync": {
        "label": "Time Synchronization",
        "control_ids": ["SI-01"],
        "command": "timedatectl status 2>/dev/null || chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null || true",
    },
    "package_updates": {
        "label": "Package Updates",
        "control_ids": ["VM-01", "VM-02"],
        "command": "if command -v apt >/dev/null 2>&1; then apt list --upgradable 2>/dev/null | sed -n '1,50p'; elif command -v dnf >/dev/null 2>&1; then dnf check-update || true; else echo package_manager_unknown; fi",
    },
    "held_packages": {
        "label": "Held Packages",
        "control_ids": ["VM-01"],
        "command": "apt-mark showhold 2>/dev/null || true",
    },
}

ROLE_LINUX_COLLECTORS = {
    "monitoring_server": {
        "prometheus_status": {
            "label": "Prometheus Status",
            "control_ids": ["SI-01", "SI-03"],
            "command": "if systemctl list-unit-files | grep -q '^prometheus.service'; then systemctl is-active prometheus || true; elif pgrep -af prometheus >/dev/null 2>&1; then pgrep -af prometheus; elif ss -tulpen 2>/dev/null | grep -E ':9090\\b'; then echo prometheus_port_detected; else echo missing; fi",
        },
        "grafana_status": {
            "label": "Grafana Status",
            "control_ids": ["SI-01"],
            "command": "if systemctl list-unit-files | grep -q '^grafana-server.service'; then systemctl is-active grafana-server || true; elif pgrep -af grafana >/dev/null 2>&1; then pgrep -af grafana; elif ss -tulpen 2>/dev/null | grep -E ':3000\\b'; then echo grafana_port_detected; else echo missing; fi",
        },
        "alertmanager_status": {
            "label": "Alertmanager Status",
            "control_ids": ["SI-01", "IR-01"],
            "command": "if systemctl list-unit-files | grep -q '^alertmanager.service'; then systemctl is-active alertmanager || true; elif pgrep -af alertmanager >/dev/null 2>&1; then pgrep -af alertmanager; elif ss -tulpen 2>/dev/null | grep -E ':9093\\b'; then echo alertmanager_port_detected; else echo missing; fi",
        },
    },
    "central_log_server": {
        "wazuh_manager_status": {
            "label": "Wazuh Manager Status",
            "control_ids": ["SI-01", "SI-03"],
            "command": "if systemctl list-unit-files | grep -q '^wazuh-manager.service'; then systemctl is-active wazuh-manager || true; elif test -x /var/ossec/bin/wazuh-control; then /var/ossec/bin/wazuh-control status || true; else echo missing; fi",
        },
        "log_retention_check": {
            "label": "Log Retention Check",
            "control_ids": ["SI-01"],
            "command": "find /var/log /var/ossec/logs -type f -mtime -30 2>/dev/null | head -50 || true",
        },
    },
    "siem_server": {
        "siem_manager_status": {
            "label": "SIEM Manager Status",
            "control_ids": ["SI-01", "SI-03"],
            "command": "systemctl is-active wazuh-manager 2>/dev/null || systemctl is-active elasticsearch 2>/dev/null || systemctl is-active opensearch 2>/dev/null || echo missing",
        },
    },
    "sftp_server": {
        "sftp_configuration": {
            "label": "SFTP Configuration",
            "control_ids": ["AC-04", "NS-02"],
            "command": "sshd -T 2>/dev/null | grep -Ei 'subsystem|passwordauthentication|pubkeyauthentication|permitrootlogin|allowusers|allowgroups|chrootdirectory|forcecommand' || grep -Ei 'Subsystem|PasswordAuthentication|PubkeyAuthentication|PermitRootLogin|AllowUsers|AllowGroups|ChrootDirectory|ForceCommand' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null || true",
        },
        "authorized_keys_review": {
            "label": "Authorized Keys Review",
            "control_ids": ["AC-04", "AC-05"],
            "command": "find /home /root -maxdepth 3 -name authorized_keys -type f -exec sh -c 'echo FILE:$1; wc -l < \"$1\"' _ {} \\; 2>/dev/null || true",
        },
        "sftp_auth_logs": {
            "label": "SFTP Authentication Logs",
            "control_ids": ["SI-01", "AC-02"],
            "command": "grep -Ei 'sshd|sftp|pam_duo|Accepted|Failed' /var/log/auth.log /var/log/secure 2>/dev/null | tail -100 || true",
        },
    },
    "web_server": {
        "web_service_status": {
            "label": "Web Service Status",
            "control_ids": ["NS-01", "SI-01"],
            "command": "systemctl is-active nginx 2>/dev/null || systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null || pgrep -af 'nginx|apache2|httpd' || echo missing",
        },
        "web_tls_config": {
            "label": "Web TLS Config",
            "control_ids": ["NS-02"],
            "command": "grep -RniE 'ssl_protocols|ssl_ciphers|listen 443|SSLCipherSuite|SSLProtocol' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | head -100 || true",
        },
    },
    "database_server": {
        "database_service_status": {
            "label": "Database Service Status",
            "control_ids": ["CM-01", "SI-01"],
            "command": "systemctl is-active postgresql 2>/dev/null || systemctl is-active mysql 2>/dev/null || systemctl is-active mariadb 2>/dev/null || pgrep -af 'postgres|mysqld|mariadbd' || echo missing",
        },
        "database_listeners": {
            "label": "Database Listeners",
            "control_ids": ["NS-01", "AC-04"],
            "command": "ss -tulpen 2>/dev/null | grep -E ':5432\\b|:3306\\b|:33060\\b|:1433\\b|:1521\\b' || true",
        },
    },
    "ci_cd_server": {
        "jenkins_status": {
            "label": "Jenkins Status",
            "control_ids": ["SD-01", "SI-01"],
            "command": "systemctl is-active jenkins 2>/dev/null || pgrep -af jenkins || ss -tulpen 2>/dev/null | grep -E ':8080\\b|:8443\\b' || echo missing",
        },
        "cicd_workspace_review": {
            "label": "CI/CD Workspace Review",
            "control_ids": ["SD-01", "CM-02"],
            "command": "find /var/lib/jenkins /home/jenkins -maxdepth 3 -type d \\( -name workspace -o -name jobs \\) 2>/dev/null | head -50 || true",
        },
    },
    "identity_provider": {
        "keycloak_status": {
            "label": "Keycloak Status",
            "control_ids": ["AC-01", "AC-02"],
            "command": "systemctl is-active keycloak 2>/dev/null || pgrep -af keycloak || ss -tulpen 2>/dev/null | grep -E ':8080\\b|:8443\\b' || echo missing",
        },
    },
    "container_host": {
        "docker_runtime": {
            "label": "Docker Runtime",
            "control_ids": ["CM-01", "NS-01"],
            "command": "docker ps --format '{{json .}}' 2>/dev/null | head -100 || echo docker_unavailable",
        },
        "docker_socket_review": {
            "label": "Docker Socket Review",
            "control_ids": ["AC-04", "CM-01"],
            "command": "ls -l /var/run/docker.sock 2>/dev/null || true",
        },
    },
    "application_server": {
        "application_services": {
            "label": "Application Services",
            "control_ids": ["CM-01", "SI-01"],
            "command": "systemctl --type=service --state=running 2>/dev/null | sed -n '1,80p' || ps -eo pid,comm,args --sort=comm | sed -n '1,80p'",
        },
    },
}


def normalize_roles(asset: Any) -> list[str]:
    roles = getattr(asset, "asset_roles", None) or []
    if isinstance(roles, str):
        return [r.strip() for r in roles.split(",") if r.strip()]
    return [str(r).strip() for r in roles if str(r).strip()]


def collector_plan_for_asset(asset: Any) -> list[dict[str, Any]]:
    roles = normalize_roles(asset)
    plan = []

    for name, spec in BASELINE_LINUX_COLLECTORS.items():
        item = {"collector": name, "role": "baseline", **spec}
        plan.append(item)

    for role in roles:
        for name, spec in ROLE_LINUX_COLLECTORS.get(role, {}).items():
            item = {"collector": name, "role": role, **spec}
            plan.append(item)

    seen = set()
    deduped = []

    for item in plan:
        key = item["collector"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped
