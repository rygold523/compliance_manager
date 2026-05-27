import re
import subprocess

ALLOWED_COMMAND_PATTERNS = [
    r"^sudo /usr/local/lib/compliance/collectors/[a-zA-Z0-9_\-]+\.py$",
]

def is_command_allowed(command: str) -> bool:
    command = (command or "").strip()
    return any(re.match(pattern, command) for pattern in ALLOWED_COMMAND_PATTERNS)

def validate_command(command: str) -> bool:
    return is_command_allowed(command)

def run_ssh_command(host: str, username: str, command: str, timeout: int = 120, port: int = 22) -> dict:
    if not is_command_allowed(command):
        return {"stdout": "", "stderr": f"Command is not in the allowlist: {command}", "exit_code": 126}

    ssh_cmd = [
        "ssh", "-i", "/opt/ssh/id_rsa",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-p", str(port),
        f"{username}@{host}",
        command,
    ]

    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": r.stdout or "", "stderr": r.stderr or "", "exit_code": r.returncode}
    except subprocess.TimeoutExpired as exc:
        return {"stdout": exc.stdout or "", "stderr": f"SSH command timed out after {timeout} seconds", "exit_code": 124}
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc), "exit_code": 1}
