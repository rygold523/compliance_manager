#!/usr/bin/env python3
import os
import shutil
from pathlib import Path


SOURCE_DIRECTORY = Path(
    "/tmp/compliance_collectors"
)

DESTINATION_DIRECTORY = Path(
    "/usr/local/lib/compliance/collectors"
)

MANIFEST_NAME = (
    "collector_manifest.json"
)


def install_python_collectors():
    for source_file in sorted(
        SOURCE_DIRECTORY.glob("*.py")
    ):
        destination_file = (
            DESTINATION_DIRECTORY
            / source_file.name
        )

        shutil.copy2(
            source_file,
            destination_file,
        )

        os.chown(
            destination_file,
            0,
            0,
        )

        os.chmod(
            destination_file,
            0o755,
        )


def install_manifest():
    source_file = (
        SOURCE_DIRECTORY
        / MANIFEST_NAME
    )

    if not source_file.is_file():
        raise FileNotFoundError(
            f"Missing collector manifest: "
            f"{source_file}"
        )

    destination_file = (
        DESTINATION_DIRECTORY
        / MANIFEST_NAME
    )

    shutil.copy2(
        source_file,
        destination_file,
    )

    os.chown(
        destination_file,
        0,
        0,
    )

    os.chmod(
        destination_file,
        0o644,
    )


def normalize_existing_permissions():
    for collector_file in (
        DESTINATION_DIRECTORY.glob("*.py")
    ):
        os.chown(
            collector_file,
            0,
            0,
        )

        os.chmod(
            collector_file,
            0o755,
        )


def main():
    if not SOURCE_DIRECTORY.is_dir():
        raise FileNotFoundError(
            f"Missing collector source directory: "
            f"{SOURCE_DIRECTORY}"
        )

    DESTINATION_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    install_python_collectors()
    install_manifest()
    normalize_existing_permissions()

    print(
        "collector_install_complete"
    )


if __name__ == "__main__":
    main()
