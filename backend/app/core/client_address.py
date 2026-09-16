from functools import lru_cache
from ipaddress import ip_address, ip_network

from fastapi import Request

from app.core.config import settings


@lru_cache(maxsize=32)
def _trusted_proxy_networks(configured_networks: str):
    networks = []
    for value in configured_networks.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        network = ip_network(candidate, strict=False)
        if network.prefixlen == 0:
            raise ValueError(
                "AUTH_TRUSTED_PROXY_NETWORKS must not trust an entire "
                "address family."
            )
        networks.append(network)
    return tuple(networks)


def _is_trusted_proxy(address, networks) -> bool:
    return any(
        address.version == network.version and address in network
        for network in networks
    )


def resolve_client_address(request: Request) -> str | None:
    """Return a client address without trusting headers from direct clients."""
    if request.client is None:
        return None

    peer_text = request.client.host
    try:
        peer = ip_address(peer_text)
    except ValueError:
        return peer_text

    networks = _trusted_proxy_networks(settings.auth_trusted_proxy_networks)
    if not networks or not _is_trusted_proxy(peer, networks):
        return peer.compressed

    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer.compressed

    chain = []
    try:
        for value in forwarded.split(","):
            candidate = value.strip()
            if not candidate:
                raise ValueError("empty forwarded address")
            chain.append(ip_address(candidate))
    except ValueError:
        return peer.compressed

    chain.append(peer)
    for candidate in reversed(chain):
        if not _is_trusted_proxy(candidate, networks):
            return candidate.compressed

    return peer.compressed
