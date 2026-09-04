import hmac
import os
from typing import Any

import requests

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
)

from app.services import (
    iam_db_service,
)


router = APIRouter(
    prefix="/iam",
    tags=["IAM"],
)

COLLECTOR_URL = os.getenv(
    "IAM_DB_COLLECTOR_URL",
    "http://iam-db-collector:8080",
).rstrip("/")


def collector_request(
    method: str,
    path: str,
    *,
    timeout: int = 5,
):
    try:
        response = requests.request(
            method,
            f"{COLLECTOR_URL}{path}",
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "The database IAM collector is unavailable. "
                "Review the iam-db-collector container logs."
            ),
        ) from exc


def validate_collector_token(
    token: str | None,
):
    expected = os.getenv(
        "IAM_COLLECTOR_TOKEN"
    )

    if not expected:
        raise HTTPException(
            status_code=503,
            detail=(
                "IAM_COLLECTOR_TOKEN "
                "is not configured."
            ),
        )

    if not token or not hmac.compare_digest(
        token,
        expected,
    ):
        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid IAM collector token."
            ),
        )


@router.post(
    "/db-ingest",
)
def ingest_database_iam(
    payload: dict[str, Any],
    x_iam_collector_token: str | None = (
        Header(
            default=None,
        )
    ),
):
    validate_collector_token(
        x_iam_collector_token,
    )

    try:
        return iam_db_service.ingest(
            payload,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to ingest database IAM evidence."
            ),
        )


@router.get(
    "/db-sources",
)
def database_sources():
    try:
        return {
            "sources": (
                iam_db_service.get_sources()
            )
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load database IAM sources."
            ),
        )


@router.get(
    "/db-access",
)
def database_access():
    try:
        return {
            "accounts": (
                iam_db_service
                .get_access_matrix()
            )
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load database IAM access data."
            ),
        )


@router.get(
    "/db-collector/status",
)
def database_collector_status():
    return collector_request(
        "GET",
        "/health",
        timeout=2,
    )


@router.post(
    "/db-collect",
)
def collect_database_iam():
    return collector_request(
        "POST",
        "/collect",
        timeout=120,
    )
