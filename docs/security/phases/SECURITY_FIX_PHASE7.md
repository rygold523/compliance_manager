# Security Fix Phase 7: Trusted Proxy Client Addresses

This phase centralizes client-address resolution for authentication and local
user-administration audit events.

- Forwarded headers are ignored for direct or otherwise untrusted peers.
- `X-Forwarded-For` is accepted only from explicitly configured proxy IPs or
  CIDR networks.
- Multi-proxy chains are evaluated from right to left and the first untrusted
  address is treated as the originating client.
- Malformed forwarded headers safely fall back to the immediate peer.
- Trusting an entire IPv4 or IPv6 address family is rejected.
- The same resolved address drives both login throttling and audit records.

Leave `AUTH_TRUSTED_PROXY_NETWORKS` empty unless a reverse proxy actually
forwards requests to the backend. Exact `/32` or `/128` proxy addresses are
preferred over broad networks.
