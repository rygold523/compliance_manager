from types import SimpleNamespace

import pytest

from app.core.client_address import (
    _trusted_proxy_networks,
    resolve_client_address,
)
from app.core.config import settings


def request(peer: str | None, forwarded: str | None = None):
    headers = {}
    if forwarded is not None:
        headers["x-forwarded-for"] = forwarded
    return SimpleNamespace(
        client=SimpleNamespace(host=peer) if peer is not None else None,
        headers=headers,
    )


@pytest.fixture(autouse=True)
def reset_proxy_config(monkeypatch):
    monkeypatch.setattr(settings, "auth_trusted_proxy_networks", "")
    _trusted_proxy_networks.cache_clear()
    yield
    _trusted_proxy_networks.cache_clear()


def test_direct_client_cannot_spoof_forwarded_address():
    assert resolve_client_address(
        request("192.0.2.10", "203.0.113.99")
    ) == "192.0.2.10"


def test_trusted_proxy_supplies_client_address(monkeypatch):
    monkeypatch.setattr(
        settings,
        "auth_trusted_proxy_networks",
        "172.18.0.4/32",
    )
    assert resolve_client_address(
        request("172.18.0.4", "192.0.2.20")
    ) == "192.0.2.20"


def test_rightmost_untrusted_address_is_selected(monkeypatch):
    monkeypatch.setattr(
        settings,
        "auth_trusted_proxy_networks",
        "172.18.0.0/16,10.0.0.0/8",
    )
    assert resolve_client_address(
        request(
            "172.18.0.4",
            "198.51.100.7, 203.0.113.8, 10.2.3.4",
        )
    ) == "203.0.113.8"


def test_malformed_forwarded_header_falls_back_to_peer(monkeypatch):
    monkeypatch.setattr(
        settings,
        "auth_trusted_proxy_networks",
        "172.18.0.4/32",
    )
    assert resolve_client_address(
        request("172.18.0.4", "not-an-address")
    ) == "172.18.0.4"


def test_all_trusted_chain_falls_back_to_immediate_peer(monkeypatch):
    monkeypatch.setattr(
        settings,
        "auth_trusted_proxy_networks",
        "172.18.0.0/16,10.0.0.0/8",
    )
    assert resolve_client_address(
        request("172.18.0.4", "10.2.3.4")
    ) == "172.18.0.4"


def test_entire_address_family_cannot_be_trusted(monkeypatch):
    monkeypatch.setattr(
        settings,
        "auth_trusted_proxy_networks",
        "0.0.0.0/0",
    )
    with pytest.raises(ValueError):
        resolve_client_address(request("172.18.0.4", "192.0.2.20"))


def test_missing_client_is_preserved():
    assert resolve_client_address(request(None)) is None
