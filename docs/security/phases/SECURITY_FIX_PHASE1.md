# Security Remediation Phase 1

This bundle implements the first compatibility-preserving security fixes.

## Included fixes

- Adds a staged Windows-agent ingestion token.
- Preserves existing Windows-agent submissions while enforcement is disabled.
- Deploys and upgrades Windows agents with the new token.
- Restricts the installed Windows agent directory to SYSTEM and Administrators.
- Rejects path traversal in manual and Windows-agent evidence storage.
- Persists SSH host keys and rejects changed keys after initial enrollment.
- Stops PDF rendering from using the request Host header.
- Propagates the authenticated session into the internal PDF render request.
- Rejects unsuccessful internal PDF render responses.
- Repairs document upload framework mapping.
- Adds focused security regression tests.

## Windows-agent migration sequence

1. Deploy this bundle with `WINDOWS_AGENT_INGEST_ENFORCE_AUTH=false`.
2. Generate and configure `WINDOWS_AGENT_INGEST_TOKEN`.
3. Rebuild and restart the backend.
4. Upgrade or redeploy every Windows agent so its protected configuration contains the token.
5. Confirm every Windows agent submits successfully.
6. Change `WINDOWS_AGENT_INGEST_ENFORCE_AUTH=true`.
7. Recreate the backend container and confirm tokenless requests receive HTTP 401.

Do not enable enforcement before all existing Windows agents have been upgraded.

## Deferred work

Linux sudoers remediation is intentionally excluded from this phase. Both Linux
deployment paths must first be consolidated and tested against every collector
and package-update action. Removing privileges without that compatibility work
would break existing collection and remediation functions.
