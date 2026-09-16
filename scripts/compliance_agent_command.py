#!/usr/bin/python3
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path


COLLECTOR_DIR = Path("/usr/local/lib/compliance/collectors")
PACKAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:-]*$")
COLLECTORS = {
    "collect-agent-lifecycle": "agent_lifecycle.py",
    "collect-collector-health": "collector_health.py",
    "collect-disk-usage": "disk_usage.py",
    "collect-docker-inventory": "docker_inventory.py",
    "collect-iam-users": "iam_users.py",
    "collect-listening-ports": "listening_ports.py",
    "collect-os-inventory": "os_inventory.py",
    "collect-package-inventory": "package_inventory.py",
}
AUTH_PATTERNS = {
    "collect-user-changes": re.compile(
        r"useradd|userdel|usermod|groupadd|groupdel|passwd",
        re.IGNORECASE,
    ),
    "collect-auth-success": re.compile(
        r"accepted password|accepted publickey|session opened",
        re.IGNORECASE,
    ),
    "collect-auth-failure": re.compile(
        r"failed password|authentication failure|invalid user",
        re.IGNORECASE,
    ),
    "collect-sudo-activity": re.compile(
        r"sudo:|COMMAND=",
        re.IGNORECASE,
    ),
}


def fail(message: str, status: int = 2) -> int:
    print(message, file=sys.stderr)
    return status


def secure_collector(name: str) -> Path:
    path = COLLECTOR_DIR / name
    info = path.stat()

    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"Collector is not a regular file: {path}")

    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(f"Collector ownership or mode is unsafe: {path}")

    return path


def run_collector(action: str, arguments: list[str]) -> int:
    if arguments:
        return fail(f"Unexpected arguments for {action}")

    path = secure_collector(COLLECTORS[action])
    os.execv("/usr/bin/python3", ["/usr/bin/python3", str(path)])
    return 127


def collect_auth_log(action: str, arguments: list[str]) -> int:
    if arguments:
        return fail(f"Unexpected arguments for {action}")

    matches: list[str] = []
    pattern = AUTH_PATTERNS[action]

    for path in (Path("/var/log/auth.log.1"), Path("/var/log/auth.log")):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                matches.extend(line.rstrip("\n") for line in handle if pattern.search(line))
        except FileNotFoundError:
            continue

    for line in matches[-200:]:
        print(line)

    return 0


def collect_ssh_config(arguments: list[str]) -> int:
    if arguments:
        return fail("Unexpected arguments for collect-ssh-config")

    paths = [Path("/etc/ssh/sshd_config")]
    drop_in = Path("/etc/ssh/sshd_config.d")

    if drop_in.is_dir():
        paths.extend(sorted(drop_in.glob("*.conf")))

    for path in paths:
        try:
            print(f"# FILE: {path}")
            print(path.read_text(encoding="utf-8", errors="replace"), end="")
        except FileNotFoundError:
            continue

    return 0


def run_fixed(command: list[str]) -> int:
    return subprocess.run(command, check=False).returncode


def collect_firewall(arguments: list[str]) -> int:
    if arguments:
        return fail("Unexpected arguments for collect-firewall-status")

    commands = (
        ["/usr/sbin/ufw", "status", "verbose"],
        ["/usr/sbin/nft", "list", "ruleset"],
        ["/usr/sbin/iptables", "-S"],
    )

    for command in commands:
        if Path(command[0]).exists():
            return run_fixed(command)

    print("NO_FIREWALL_TOOL_FOUND")
    return 0


def manage_packages(arguments: list[str]) -> int:
    if not arguments:
        return fail("A package action is required")

    action = arguments[0]
    package_manager = secure_collector("package_manager.py")

    if action in {"upgrade", "upgrade-held"}:
        if len(arguments) != 2 or not PACKAGE_PATTERN.fullmatch(arguments[1]):
            return fail("A valid package name is required")
    elif action in {"upgrade-all", "upgrade-all-including-held"}:
        if len(arguments) != 1:
            return fail(f"Unexpected arguments for {action}")
    else:
        return fail(f"Unsupported package action: {action}")

    os.execv(
        "/usr/bin/python3",
        ["/usr/bin/python3", str(package_manager), *arguments],
    )
    return 127


def remove_agent(arguments: list[str]) -> int:
    if arguments:
        return fail("Unexpected arguments for remove-agent")

    os.execv("/usr/sbin/userdel", ["/usr/sbin/userdel", "compliance-agent"])
    return 127


def main() -> int:
    if os.geteuid() != 0:
        return fail("This dispatcher must run through sudo", 1)

    if len(sys.argv) < 2:
        return fail("An action is required")

    action = sys.argv[1]
    arguments = sys.argv[2:]

    if action in COLLECTORS:
        return run_collector(action, arguments)
    if action in AUTH_PATTERNS:
        return collect_auth_log(action, arguments)
    if action == "collect-ssh-config":
        return collect_ssh_config(arguments)
    if action == "collect-firewall-status":
        return collect_firewall(arguments)
    if action == "manage-packages":
        return manage_packages(arguments)
    if action == "remove-agent":
        return remove_agent(arguments)

    return fail(f"Unsupported action: {action}")


if __name__ == "__main__":
    raise SystemExit(main())
