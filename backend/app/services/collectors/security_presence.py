from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def linux_security_presence_commands():
    linux = {
        "trend_micro_ds_agent": {
            "control_ids": ["SI-03", "VM-02"],
            "command": "if systemctl list-unit-files | grep -q '^ds_agent.service'; then systemctl is-active ds_agent || true; elif command -v /opt/ds_agent/dsa_control >/dev/null 2>&1; then echo present; else echo missing; fi",
        },
        "automox_amagent": {
            "control_ids": ["VM-02", "CM-05"],
            "command": "if systemctl list-unit-files | grep -q '^amagent.service'; then systemctl is-active amagent || true; elif command -v amagent >/dev/null 2>&1; then echo present; else echo missing; fi",
        },
        "duo_mfa_linux": {
            "control_ids": ["AC-01", "AC-04"],
            "command": "printf 'pam_duo_conf='; test -f /etc/duo/pam_duo.conf && echo present || echo missing; printf 'pam_sshd_duo='; grep -R 'pam_duo.so' /etc/pam.d/sshd /etc/pam.d/common-auth 2>/dev/null | head -5 || true",
        },
        "wazuh_agent": {
            "control_ids": ["SI-01", "SI-03"],
            "command": "if systemctl list-unit-files | grep -q '^wazuh-agent.service'; then systemctl is-active wazuh-agent || true; elif test -d /var/ossec; then echo present; else echo missing; fi",
        },
        "listening_services": {
            "control_ids": ["NS-01", "NS-02"],
            "command": "ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true",
        },
        "sftp_configuration": {
            "control_ids": ["AC-04", "NS-02"],
            "command": "sshd -T 2>/dev/null | grep -Ei 'subsystem|passwordauthentication|pubkeyauthentication|permitrootlogin|allowusers|allowgroups|chrootdirectory|forcecommand' || grep -Ei 'Subsystem|PasswordAuthentication|PubkeyAuthentication|PermitRootLogin|AllowUsers|AllowGroups|ChrootDirectory|ForceCommand' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null || true",
        },
        "ssh_hardening": {
            "control_ids": ["AC-04", "NS-02"],
            "command": "sshd -T 2>/dev/null | grep -Ei 'passwordauthentication|permitrootlogin|pubkeyauthentication|maxauthtries|clientaliveinterval|allowusers|allowgroups' || true",
        },
        "authorized_keys_review": {
            "control_ids": ["AC-04", "AC-05"],
            "command": "find /home /root -maxdepth 3 -name authorized_keys -type f -exec sh -c 'echo FILE:$1; wc -l < \"$1\"' _ {} \\; 2>/dev/null || true",
        },
    }


def windows_security_presence_powershell():
    return {
        "trend_micro_ds_agent": {
            "control_ids": ["SI-03", "VM-02"],
            "command": "Get-Service -Name ds_agent -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | ConvertTo-Json -Compress",
        },
        "automox_amagent": {
            "control_ids": ["VM-02", "CM-05"],
            "command": "Get-Service -Name amagent -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | ConvertTo-Json -Compress",
        },
        "duo_mfa_linux": {
            "control_ids": ["AC-01", "AC-04"],
            "command": "$svc=Get-Service -Name DuoCredProv -ErrorAction SilentlyContinue; $paths=@('C:\\Program Files\\Duo Security','C:\\Program Files (x86)\\Duo Security'); [PSCustomObject]@{DuoCredProv=$svc; Paths=($paths | Where-Object { Test-Path $_ })} | ConvertTo-Json -Compress -Depth 4",
        },
        "wazuh_agent": {
            "control_ids": ["SI-01", "SI-03"],
            "command": "Get-Service -Name wazuh -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | ConvertTo-Json -Compress",
        },
        "listening_services": {
            "control_ids": ["NS-01", "NS-02"],
            "command": "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress",
        },
    }


def build_presence_evidence(asset_id, os_family, collector_name, raw_output, control_ids):
    status = "present"

    lowered = str(raw_output).lower()
    if "missing" in lowered or raw_output in [None, ""]:
        status = "missing"

    return {
        "collector": collector_name,
        "asset_id": asset_id,
        "collected_at": _now(),
        "os_family": os_family,
        "status": status,
        "control_ids": control_ids,
        "raw_output": raw_output,
    }
