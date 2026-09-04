#!/usr/bin/env python3
from datetime import datetime, timezone
from pathlib import Path
import json
import socket


AGENT_VERSION = (
    "2026.09.04.3"
)

EXPECTED_AGENT_VERSION = (
    "2026.09.04.3"
)

MANIFEST_PATH = Path(
    "/usr/local/lib/compliance/collectors/"
    "collector_manifest.json"
)


def main():
    data = {
        "collector": "agent_lifecycle",
        "status": "completed",
        "collected_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "hostname": socket.gethostname(),
        "agent_version": AGENT_VERSION,
        "expected_agent_version": (
            EXPECTED_AGENT_VERSION
        ),
        "agent_current": False,
        "manifest_present": (
            MANIFEST_PATH.is_file()
        ),
        "collector_manifest_version": None,
        "manifest_error": None,
    }

    if MANIFEST_PATH.is_file():
        try:
            manifest = json.loads(
                MANIFEST_PATH.read_text(
                    encoding="utf-8"
                )
            )

            manifest_version = (
                manifest.get(
                    "manifest_version"
                )
            )

            data[
                "collector_manifest_version"
            ] = manifest_version

            data["agent_current"] = (
                AGENT_VERSION
                == EXPECTED_AGENT_VERSION
                == manifest_version
            )

        except Exception as exc:
            data["manifest_error"] = str(
                exc
            )
            data["agent_current"] = False

    print(
        json.dumps(
            data
        )
    )


if __name__ == "__main__":
    main()
