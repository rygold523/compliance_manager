#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys


APT_GET = "/usr/bin/apt-get"
APT_MARK = "/usr/bin/apt-mark"
APT = "/usr/bin/apt"

PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9+_.:-]*$"
)

VALID_ACTIONS = {
    "upgrade",
    "upgrade-held",
    "upgrade-all",
    "upgrade-all-including-held",
}


def run_command(
    command: list[str],
    *,
    capture_output: bool = False,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=capture_output,
    )


def validate_package(
    package_name: str,
) -> str:
    package_name = package_name.strip()

    if not PACKAGE_PATTERN.fullmatch(
        package_name
    ):
        raise ValueError(
            f"Invalid package name: "
            f"{package_name!r}"
        )

    return package_name


def get_held_packages() -> list[str]:
    result = run_command(
        [
            APT_MARK,
            "showhold",
        ],
        capture_output=True,
    )

    if result.returncode != 0:
        if result.stdout:
            print(
                result.stdout,
                end="",
            )

        if result.stderr:
            print(
                result.stderr,
                end="",
                file=sys.stderr,
            )

        raise RuntimeError(
            "Unable to read held packages."
        )

    return sorted(
        {
            validate_package(line)
            for line in result.stdout.splitlines()
            if line.strip()
        }
    )


def get_upgradable_packages() -> list[str]:
    result = run_command(
        [
            APT,
            "list",
            "--upgradable",
        ],
        capture_output=True,
    )

    if result.returncode != 0:
        if result.stdout:
            print(
                result.stdout,
                end="",
            )

        if result.stderr:
            print(
                result.stderr,
                end="",
                file=sys.stderr,
            )

        raise RuntimeError(
            "Unable to list upgradable packages."
        )

    packages = set()

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line or line.startswith(
            "Listing..."
        ):
            continue

        package_name = line.split(
            "/",
            1,
        )[0].strip()

        packages.add(
            validate_package(
                package_name
            )
        )

    return sorted(packages)


def change_hold_state(
    operation: str,
    packages: list[str],
) -> int:
    if not packages:
        return 0

    result = run_command(
        [
            APT_MARK,
            operation,
            *packages,
        ]
    )

    return result.returncode


def upgrade_package(
    package_name: str,
) -> int:
    result = run_command(
        [
            APT_GET,
            "install",
            "--only-upgrade",
            "-y",
            package_name,
        ]
    )

    return result.returncode


def upgrade_held_package(
    package_name: str,
) -> int:
    unhold_status = change_hold_state(
        "unhold",
        [package_name],
    )

    if unhold_status != 0:
        return unhold_status

    update_status = upgrade_package(
        package_name
    )

    hold_status = change_hold_state(
        "hold",
        [package_name],
    )

    if update_status != 0:
        return update_status

    return hold_status


def upgrade_all(
    include_held: bool,
) -> int:
    held_packages = get_held_packages()

    if include_held:
        unhold_status = change_hold_state(
            "unhold",
            held_packages,
        )

        if unhold_status != 0:
            return unhold_status

        result = run_command(
            [
                APT_GET,
                "upgrade",
                "-y",
            ]
        )

        update_status = result.returncode

        hold_status = change_hold_state(
            "hold",
            held_packages,
        )

        if update_status != 0:
            return update_status

        return hold_status

    upgradable_packages = (
        get_upgradable_packages()
    )

    held_package_set = set(
        held_packages
    )

    selected_packages = [
        package_name
        for package_name in upgradable_packages
        if package_name
        not in held_package_set
    ]

    if not selected_packages:
        print(
            "NO_NON_HELD_UPGRADES_AVAILABLE"
        )

        return 0

    result = run_command(
        [
            APT_GET,
            "install",
            "--only-upgrade",
            "-y",
            *selected_packages,
        ]
    )

    return result.returncode


def usage() -> str:
    return (
        "Usage: package_manager.py "
        "{upgrade PACKAGE|"
        "upgrade-held PACKAGE|"
        "upgrade-all|"
        "upgrade-all-including-held}"
    )


def main() -> int:
    if len(sys.argv) < 2:
        print(
            usage(),
            file=sys.stderr,
        )

        return 2

    action = sys.argv[1]

    if action not in VALID_ACTIONS:
        print(
            f"Unsupported action: {action}",
            file=sys.stderr,
        )

        return 2

    try:
        if action in {
            "upgrade",
            "upgrade-held",
        }:
            if len(sys.argv) != 3:
                print(
                    usage(),
                    file=sys.stderr,
                )

                return 2

            package_name = validate_package(
                sys.argv[2]
            )

            if action == "upgrade":
                return upgrade_package(
                    package_name
                )

            return upgrade_held_package(
                package_name
            )

        if len(sys.argv) != 2:
            print(
                usage(),
                file=sys.stderr,
            )

            return 2

        return upgrade_all(
            include_held=(
                action
                == "upgrade-all-including-held"
            )
        )

    except (
        RuntimeError,
        ValueError,
    ) as error:
        print(
            str(error),
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
