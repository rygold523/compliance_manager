import re
from ipaddress import ip_address


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


def parse_allowed_hosts(configured_hosts: str) -> list[str]:
    hosts = []
    for value in configured_hosts.split(","):
        candidate = value.strip().lower().rstrip(".")
        if not candidate:
            continue
        if candidate == "*" or candidate.startswith("*."):
            raise ValueError("AUTH_ALLOWED_HOSTS must not contain wildcards.")
        if "://" in candidate or "/" in candidate or ":" in candidate:
            raise ValueError(
                "AUTH_ALLOWED_HOSTS entries must be hostnames or IPv4 "
                "addresses without schemes, paths, or ports."
            )
        try:
            parsed_address = ip_address(candidate)
        except ValueError:
            if not HOSTNAME_PATTERN.fullmatch(candidate):
                raise ValueError(
                    f"Invalid AUTH_ALLOWED_HOSTS entry: {candidate!r}."
                )
            normalized = candidate
        else:
            if parsed_address.version != 4:
                raise ValueError(
                    "IPv6 Host-header allowlisting is not supported by the "
                    "current middleware configuration."
                )
            normalized = parsed_address.compressed
        if normalized not in hosts:
            hosts.append(normalized)

    if not hosts:
        raise ValueError("AUTH_ALLOWED_HOSTS must contain at least one host.")
    return hosts


def production_api_documentation_urls(app_env: str):
    if app_env.strip().lower() == "production":
        return {
            "docs_url": None,
            "redoc_url": None,
            "openapi_url": None,
        }
    return {
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
    }
