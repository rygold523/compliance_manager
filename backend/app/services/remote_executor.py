import re
import paramiko
from app.core.config import settings

BLOCKED_PATTERNS = [
    r"rm\s+-rf", r"mkfs", r"dd\s+if=", r"shutdown", r"reboot", r"init\s+[06]",
    r"chmod\s+-R\s+777", r"docker\s+build", r"docker\s+compose\s+build",
    r"docker\s+pull", r"docker\s+run", r"DROP\s+DATABASE", r"TRUNCATE\s+TABLE",
]

ALLOWED_PREFIXES = [
    "hostname", "hostnamectl", "lsb_release", "uname", "uptime", "df", "free",
    "ip", "ss", "apt-mark showhold", "apt-cache policy", "apt list --upgradable",
    "dpkg -l", "timedatectl", "sudo apt-mark", "sudo apt-cache",
    "sudo apt-get install --only-upgrade", "sudo nginx -t",
    "sudo systemctl status nginx", "sudo systemctl reload nginx", "sudo journalctl",
    "sudo tail", "sudo grep", "sudo find", "sudo cat", "sudo ufw status",
    "sudo docker ps", "grep",
]


def redact_output(value: str) -> str:
    patterns = [
        r"(?i)(password|token|secret|api_key)=\S+",
        r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+",
    ]
    redacted = value or ""
    for pattern in patterns:
        redacted = re.sub(pattern, r"\1[REDACTED]", redacted)
    return redacted


def validate_command(command: str) -> tuple[bool, str]:
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Blocked command pattern matched: {pattern}"

    if settings.remote_exec_allow_arbitrary_commands:
        return True, "Allowed by arbitrary command setting"

    normalized = " ".join(command.split())
    if any(normalized.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        return True, "Allowed"

    return False, "Command is not in the allowlist"


def run_ssh_command(host: str, username: str, command: str, key_path: str | None = None, timeout: int | None = None, port: int = 22) -> dict:
    allowed, reason = validate_command(command)
    if not allowed:
        return {"allowed": False, "reason": reason, "stdout": "", "stderr": reason, "exit_code": 126}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        key_filename=key_path or settings.remote_exec_key,
        timeout=timeout or settings.remote_exec_timeout_seconds,
        banner_timeout=30,
        auth_timeout=30,
    )

    stdin, stdout, stderr = client.exec_command(command, timeout=timeout or settings.remote_exec_timeout_seconds)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    client.close()

    return {
        "allowed": True,
        "reason": "Executed",
        "stdout": redact_output(out),
        "stderr": redact_output(err),
        "exit_code": exit_code,
    }
