import re
import subprocess


PACKAGE_MANAGER_PATH = (
    "/usr/local/sbin/compliance-agent-command"
)

BULK_INCLUDE_HELD_COMMAND = (
    f"sudo {PACKAGE_MANAGER_PATH} "
    "manage-packages upgrade-all-including-held"
)

BULK_EXCLUDE_HELD_COMMAND = (
    f"sudo {PACKAGE_MANAGER_PATH} "
    "manage-packages upgrade-all"
)

ALLOWED_EXACT_COMMANDS = {
    BULK_INCLUDE_HELD_COMMAND,
    BULK_EXCLUDE_HELD_COMMAND,
    f"sudo {PACKAGE_MANAGER_PATH} remove-agent",
    "dpkg -l",
    "apt-mark showhold",
    (
        "apt-cache policy "
        "$(dpkg-query -W "
        "-f='${binary:Package} ' "
        "2>/dev/null) "
        "2>/dev/null | head -20000"
    ),
}

ALLOWED_COMMAND_PATTERNS = [
    re.compile(
        r"^sudo /usr/local/sbin/compliance-agent-command "
        r"(?:collect-(?:agent-lifecycle|collector-health|disk-usage|"
        r"docker-inventory|iam-users|listening-ports|os-inventory|"
        r"package-inventory|user-changes|auth-success|auth-failure|"
        r"sudo-activity|ssh-config|firewall-status)|remove-agent)$"
    ),
    re.compile(
        r"^sudo /usr/local/sbin/compliance-agent-command "
        r"manage-packages (?:upgrade|upgrade-held) "
        r"[A-Za-z0-9][A-Za-z0-9+_.:-]*$"
    ),
]


def is_command_allowed(
    command: str,
) -> bool:
    if command in ALLOWED_EXACT_COMMANDS:
        return True

    return any(
        pattern.fullmatch(command)
        for pattern in ALLOWED_COMMAND_PATTERNS
    )


def validate_command(
    command: str,
) -> tuple[bool, str]:
    allowed = is_command_allowed(
        command
    )

    if allowed:
        return (
            True,
            "Command is in the allowlist",
        )

    return (
        False,
        "Command is not in the allowlist",
    )


def run_ssh_command(
    host: str,
    username: str,
    command: str,
    timeout: int = 120,
    port: int = 22,
) -> dict:
    if not is_command_allowed(command):
        return {
            "allowed": False,
            "reason": (
                "Command is not in the allowlist"
            ),
            "stdout": "",
            "stderr": (
                "Command is not in the allowlist: "
                f"{command}"
            ),
            "exit_code": 126,
        }

    ssh_command = [
        "ssh",
        "-i",
        "/opt/ssh/id_rsa",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-p",
        str(port),
        f"{username}@{host}",
        command,
    ]

    try:
        completed = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return {
            "allowed": True,
            "reason": (
                "Command completed"
                if completed.returncode == 0
                else "Command failed"
            ),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "exit_code": completed.returncode,
        }

    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode(
                errors="replace"
            )
            if isinstance(
                exc.stdout,
                bytes,
            )
            else exc.stdout
        ) or ""

        stderr = (
            exc.stderr.decode(
                errors="replace"
            )
            if isinstance(
                exc.stderr,
                bytes,
            )
            else exc.stderr
        ) or ""

        return {
            "allowed": True,
            "reason": "Command timed out",
            "stdout": stdout,
            "stderr": (
                stderr
                or (
                    "SSH command timed out after "
                    f"{timeout} seconds"
                )
            ),
            "exit_code": 124,
        }

    except Exception as exc:
        return {
            "allowed": True,
            "reason": "Execution failed",
            "stdout": "",
            "stderr": str(exc),
            "exit_code": 1,
        }
