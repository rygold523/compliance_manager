# Security Fix Phase 8: HTTP Host and Documentation Surface

This phase limits Host-header values and removes unauthenticated API schema
disclosure in production.

- Production disables Swagger UI, ReDoc, and the OpenAPI JSON endpoint.
- Non-production environments retain interactive API documentation.
- Backend Host headers must match `AUTH_ALLOWED_HOSTS`.
- Schemes, paths, ports, CIDR notation, IPv6 literals, and wildcard entries are
  rejected from the allowlist.
- Current IP access and future HTTPS DNS names require configuration only.

Before a DNS or HTTPS cutover, add the exact new hostname to
`AUTH_ALLOWED_HOSTS` and its exact origin to `AUTH_CORS_ORIGINS`, then recreate
the backend. Keep existing addresses during a controlled transition and remove
them after the old access path is retired.
