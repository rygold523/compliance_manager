import subprocess

ALLOWED_COMMAND_PREFIXES = [
    "hostname",
    "uname",
    "cat /etc/os-release",
    "df ",
    "free ",
    "uptime",
    "systemctl",
    "docker ",
    "sudo grep",
    "sudo cat",
    "sudo ss",
    "sudo netstat",
    "sudo ufw",
    "sudo nft",
    "sudo iptables",
    "sudo lsblk",
    "sudo findmnt",
    "sudo apt",
    "sudo dpkg",
    "sudo /usr/local/lib/compliance/collectors/",
]

def is_command_allowed(command: str) -> bool:
    command = (command or "").strip()
    return any(command == p.strip() or command.startswith(p) for p in ALLOWED_COMMAND_PREFIXES)

def run_ssh_command(host: str, username: str, command: str, timeout: int = 120, port: int = 22) -> dict:
    if not is_command_allowed(command):
        return {
            "stdout": "",
            "stderr": "Command is not in the allowlist",
            "exit_code": 126,
        }

    ssh_cmd = [
        "ssh",
        "-i", "/opt/ssh/id_rsa",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-p", str(port),
        f"{username}@{host}",
        command,
    ]

    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "exit_code": result.returncode,
        }

    except subprocess.TimeoutExpired as exc:
        return {
            "stdout": exc.stdout or "",
            "stderr": f"SSH command timed out after {timeout} seconds",
            "exit_code": 124,
        }

    except Exception as exc:
        return {
            "stdout": "",
            "stderr": str(exc),
            "exit_code": 1,
        }


def validate_command(command: str) -> bool:
    """
    Compatibility wrapper for older API imports.
    """
    return is_command_allowed(command)
