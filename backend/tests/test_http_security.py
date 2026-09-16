import asyncio

import pytest
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.http_security import (
    parse_allowed_hosts,
    production_api_documentation_urls,
)


def test_allowed_hosts_are_normalized_and_deduplicated():
    assert parse_allowed_hosts(
        " Compliance.Example.Internal.,192.168.1.246,localhost,localhost "
    ) == [
        "compliance.example.internal",
        "192.168.1.246",
        "localhost",
    ]


@pytest.mark.parametrize(
    "configured",
    [
        "",
        "*",
        "*.example.internal",
        "https://compliance.example.internal",
        "compliance.example.internal:8000",
        "compliance.example.internal/path",
        "192.168.1.0/24",
        "bad_host_name",
        "::1",
    ],
)
def test_unsafe_or_invalid_allowed_hosts_are_rejected(configured):
    with pytest.raises(ValueError):
        parse_allowed_hosts(configured)


def test_production_disables_api_documentation():
    assert production_api_documentation_urls("production") == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


def test_nonproduction_keeps_api_documentation_available():
    assert production_api_documentation_urls("development") == {
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
    }


def middleware_status(host: str) -> int:
    async def endpoint(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = TrustedHostMiddleware(
        endpoint,
        allowed_hosts=["192.168.1.246", "compliance.example.internal"],
    )
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/api/health",
        "raw_path": b"/api/health",
        "query_string": b"",
        "headers": [(b"host", host.encode("ascii"))],
        "client": ("192.0.2.10", 12345),
        "server": ("127.0.0.1", 8000),
    }
    asyncio.run(middleware(scope, receive, send))
    return next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )


def test_trusted_host_middleware_accepts_configured_host_with_port():
    assert middleware_status("192.168.1.246:8000") == 200


def test_trusted_host_middleware_rejects_unconfigured_host():
    assert middleware_status("attacker.example:8000") == 400
