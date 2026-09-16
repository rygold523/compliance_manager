# Phase 3: Asset-bound Windows credentials

This phase adds unique Windows-agent credentials without rotating or deleting
the existing shared ingestion token.

## Compatibility behavior

- `WINDOWS_AGENT_INGEST_TOKEN` is unchanged.
- `WINDOWS_AGENT_LEGACY_AUTH_ENABLED=true` keeps existing agents working.
- New Windows deployments and upgrades receive a unique credential bound to
  one asset.
- Only a SHA-256 digest is stored in PostgreSQL.
- The bootstrap validates the new credential before atomically replacing the
  installed `agent-config.json`.
- A failed deployment revokes the newly issued credential and leaves the
  installed agent configuration unchanged.
- Successful rotation revokes older asset-bound credentials. It does not
  revoke the shared legacy token.

## Configuration

The authentication preflight route must be included in `AUTH_SERVICE_PATHS`:

```text
/api/windows-agent/auth-check
```

Keep this setting during migration:

```text
WINDOWS_AGENT_LEGACY_AUTH_ENABLED=true
```

After every Windows agent has been upgraded and has completed a scheduled
submission using its asset-bound credential, legacy fallback can be disabled:

```text
WINDOWS_AGENT_LEGACY_AUTH_ENABLED=false
```

Disabling fallback does not alter or remove `WINDOWS_AGENT_INGEST_TOKEN`, so
the value remains available for a controlled rollback.

## Evidence integrity

The backend now computes the evidence `validated` value from the collector
status. A Windows client can no longer mark evidence validated merely by
submitting `"validated": true`.
