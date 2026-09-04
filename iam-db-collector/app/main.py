from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests
from fastapi import FastAPI, HTTPException

from app.config import (
    load_sources,
    resolve_secret,
)
from app.connectors.postgres import (
    PostgreSQLIAMConnector,
)


logging.basicConfig(
    level=os.getenv(
        "LOG_LEVEL",
        "INFO",
    ),
    format=(
        "%(asctime)s "
        "%(levelname)s "
        "%(message)s"
    ),
)

logger = logging.getLogger(
    "iam-db-collector",
)

app = FastAPI(
    title="IAM Database Collector",
)

DASHBOARD_INGEST_URL = os.getenv(
    "DASHBOARD_INGEST_URL",
    "http://backend:8000/api/iam/db-ingest",
)

COLLECTOR_TOKEN = os.getenv(
    "IAM_COLLECTOR_TOKEN",
)

POLL_SECONDS = max(
    int(
        os.getenv(
            "IAM_COLLECTOR_POLL_SECONDS",
            "60",
        )
    ),
    30,
)

_last_runs: dict[str, float] = {}
_run_states: dict[str, dict[str, Any]] = {}
_collection_lock = threading.Lock()
_scheduler_started = False


def utc_now_iso() -> str:
    return datetime.now(
        timezone.utc,
    ).isoformat()


def public_source(
    source: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": source.get("id"),
        "name": source.get("name"),
        "type": source.get(
            "type",
            "postgres",
        ),
        "host": source.get("host"),
        "port": source.get(
            "port",
            5432,
        ),
        "database": source.get(
            "database",
        ),
        "username": source.get(
            "username",
        ),
        "enabled": source.get(
            "enabled",
            True,
        ),
        "interval_minutes": (
            source.get(
                "interval_minutes",
                5,
            )
        ),
    }


def get_source(
    source_id: str,
) -> dict[str, Any]:
    for source in load_sources():
        if str(
            source.get("id")
        ) == str(source_id):
            return source

    raise KeyError(
        source_id,
    )


def collect_source(
    source: dict[str, Any],
) -> dict[str, Any]:
    source_type = source.get(
        "type",
        "postgres",
    )

    if source_type != "postgres":
        raise ValueError(
            f"Unsupported IAM source type: "
            f"{source_type}"
        )

    password = resolve_secret(
        source,
    )

    connector = PostgreSQLIAMConnector(
        source=source,
        password=password,
    )

    result = connector.collect()

    payload = {
        "collector": (
            "iam-db-collector"
        ),
        "collector_version": "1.0",
        "collected_at": utc_now_iso(),
        "source": public_source(
            source,
        ),
        **result,
    }

    if not COLLECTOR_TOKEN:
        raise RuntimeError(
            "IAM_COLLECTOR_TOKEN "
            "is not configured."
        )

    response = requests.post(
        DASHBOARD_INGEST_URL,
        headers={
            "X-IAM-Collector-Token": (
                COLLECTOR_TOKEN
            )
        },
        json=payload,
        timeout=30,
    )

    response.raise_for_status()

    return {
        "status": "success",
        "source": source["name"],
        "accounts": len(
            result["accounts"]
        ),
        "memberships": len(
            result["memberships"]
        ),
        "database_privileges": len(
            result[
                "database_privileges"
            ]
        ),
        "dashboard_response": (
            response.json()
        ),
    }


def collect_due_sources():
    if not _collection_lock.acquire(
        blocking=False,
    ):
        logger.info(
            "Skipping scheduled collection because another run is active."
        )
        return

    now = time.time()

    try:
        for source in load_sources():
            if not source.get(
                "enabled",
                True,
            ):
                continue

            source_id = str(
                source.get("id")
            )

            interval_seconds = max(
                int(
                    source.get(
                        "interval_minutes",
                        5,
                    )
                )
                * 60,
                300,
            )

            last_run = _last_runs.get(
                source_id,
                0,
            )

            if (
                now - last_run
                < interval_seconds
            ):
                continue

            _run_states[source_id] = {
                "status": "running",
                "started_at": utc_now_iso(),
                "finished_at": None,
                "error": None,
            }

            try:
                logger.info(
                    "Collecting IAM source: %s",
                    source.get("name"),
                )

                result = collect_source(
                    source,
                )

                _run_states[source_id] = {
                    "status": "success",
                    "started_at": _run_states[source_id]["started_at"],
                    "finished_at": utc_now_iso(),
                    "error": None,
                }

                logger.info(
                    "IAM collection successful: %s",
                    result,
                )

                _last_runs[source_id] = (
                    time.time()
                )

            except Exception:
                _run_states[source_id] = {
                    "status": "failed",
                    "started_at": _run_states[source_id]["started_at"],
                    "finished_at": utc_now_iso(),
                    "error": "Collection failed. Review collector logs.",
                }

                logger.exception(
                    "IAM collection failed for %s",
                    source.get("name"),
                )

    finally:
        _collection_lock.release()


def scheduler_loop():
    while True:
        try:
            collect_due_sources()

        except Exception:
            logger.exception(
                "IAM scheduler iteration failed."
            )

        time.sleep(
            POLL_SECONDS,
        )


@app.on_event(
    "startup",
)
def start_scheduler():
    global _scheduler_started

    if _scheduler_started:
        return

    _scheduler_started = True

    thread = threading.Thread(
        target=scheduler_loop,
        daemon=True,
        name="iam-db-scheduler",
    )

    thread.start()


@app.get(
    "/health",
)
def health():
    return {
        "status": "ok",
        "service": (
            "iam-db-collector"
        ),
        "sources": len(
            load_sources()
        ),
        "enabled_sources": len(
            [
                source
                for source in load_sources()
                if source.get("enabled", True)
            ]
        ),
        "schedule": {
            "minimum_interval_minutes": 5,
            "poll_seconds": POLL_SECONDS,
        },
        "collection_running": _collection_lock.locked(),
        "runs": _run_states,
    }


@app.get(
    "/sources",
)
def sources():
    return {
        "sources": [
            public_source(source)
            for source
            in load_sources()
        ]
    }


@app.post(
    "/collect",
)
def manual_collect_all():
    if not _collection_lock.acquire(
        blocking=False,
    ):
        raise HTTPException(
            status_code=409,
            detail="A database IAM collection is already running.",
        )

    results = []

    try:
        for source in load_sources():
            if not source.get("enabled", True):
                continue

            source_id = str(source.get("id"))
            started_at = utc_now_iso()
            _run_states[source_id] = {
                "status": "running",
                "started_at": started_at,
                "finished_at": None,
                "error": None,
            }

            try:
                result = collect_source(source)
                _run_states[source_id] = {
                    "status": "success",
                    "started_at": started_at,
                    "finished_at": utc_now_iso(),
                    "error": None,
                }
                results.append({
                    "source_id": source_id,
                    **result,
                })

                _last_runs[source_id] = time.time()
            except Exception:
                logger.exception(
                    "Manual IAM collection failed for %s",
                    source.get("name"),
                )
                _run_states[source_id] = {
                    "status": "failed",
                    "started_at": started_at,
                    "finished_at": utc_now_iso(),
                    "error": "Collection failed. Review collector logs.",
                }
                results.append({
                    "source_id": source_id,
                    "source": source.get("name"),
                    "status": "failed",
                    "error": "Collection failed. Review collector logs.",
                })
    finally:
        _collection_lock.release()

    return {
        "status": (
            "success"
            if all(item["status"] == "success" for item in results)
            else "partial_failure"
        ),
        "source_count": len(results),
        "results": results,
    }


@app.post(
    "/sources/{source_id}/test",
)
def test_source(
    source_id: str,
):
    try:
        source = get_source(
            source_id,
        )

        password = resolve_secret(
            source,
        )

        connector = (
            PostgreSQLIAMConnector(
                source=source,
                password=password,
            )
        )

        return {
            "status": "success",
            "source": public_source(
                source,
            ),
            "connection": (
                connector.test_connection()
            ),
        }

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="IAM source not found.",
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.post(
    "/sources/{source_id}/collect",
)
def manual_collect(
    source_id: str,
):
    try:
        source = get_source(
            source_id,
        )

        result = collect_source(
            source,
        )

        _last_runs[
            str(source_id)
        ] = time.time()

        return result

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="IAM source not found.",
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
