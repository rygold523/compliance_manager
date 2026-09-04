import json
import os
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = "/app/config/sources.json"


def load_sources() -> list[dict[str, Any]]:
    path = Path(
        os.getenv(
            "IAM_DB_SOURCES_FILE",
            DEFAULT_CONFIG_PATH,
        )
    )

    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        payload = json.load(handle)

    if not isinstance(
        payload,
        list,
    ):
        raise ValueError(
            "IAM database source configuration must be a JSON array."
        )

    return payload


def resolve_secret(
    source: dict[str, Any],
) -> str:
    env_name = source.get(
        "password_env",
    )

    if not env_name:
        raise ValueError(
            f"Source '{source.get('name')}' "
            "does not define password_env."
        )

    password = os.getenv(
        env_name,
    )

    if not password:
        raise ValueError(
            f"Environment variable '{env_name}' "
            f"is not configured for source "
            f"'{source.get('name')}'."
        )

    return password
