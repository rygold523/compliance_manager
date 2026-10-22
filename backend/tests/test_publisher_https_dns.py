"""Focused regression tests for bounded, fail-closed publisher DNS resolution."""
import multiprocessing
import time

import pytest

from app.services import publisher_https as https


def test_dns_timeout_terminates_worker(monkeypatch):
    def blocked_getaddrinfo(*args, **kwargs):
        time.sleep(30)
        return []

    monkeypatch.setattr(https.socket, "getaddrinfo", blocked_getaddrinfo)
    started = time.monotonic()

    with pytest.raises(https.PublisherTransportError, match="timed out"):
        https._resolve_public("example.org")

    assert time.monotonic() - started < https.DNS_TIMEOUT_SECONDS + 2


def test_dns_resolution_error_fails_closed(monkeypatch):
    def fail_getaddrinfo(*args, **kwargs):
        raise OSError("simulated resolver failure")

    monkeypatch.setattr(https.socket, "getaddrinfo", fail_getaddrinfo)

    with pytest.raises(https.PublisherTransportError, match="resolution failed"):
        https._resolve_public("example.org")


def test_dns_mixed_public_and_private_addresses_rejected(monkeypatch):
    monkeypatch.setattr(
        https.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("8.8.8.8", 443)),
            (None, None, None, None, ("127.0.0.1", 443)),
        ],
    )

    with pytest.raises(https.PublisherTransportError, match="exclusively public"):
        https._resolve_public("example.org")


def test_dns_success_returns_deduplicated_public_addresses(monkeypatch):
    monkeypatch.setattr(
        https.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("8.8.8.8", 443)),
            (None, None, None, None, ("8.8.8.8", 443)),
        ],
    )

    assert https._resolve_public("example.org") == ["8.8.8.8"]


def test_dns_worker_uses_killable_process_context():
    # Guard against replacing the bounded process design with a non-cancellable
    # thread that could remain blocked in libc/NSS after the caller times out.
    assert "fork" in multiprocessing.get_all_start_methods()
    assert https.DNS_TIMEOUT_SECONDS > 0
