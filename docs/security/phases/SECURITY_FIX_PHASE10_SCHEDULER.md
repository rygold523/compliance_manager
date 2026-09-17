# Phase 10 Scheduler Authentication Remediation

The host scheduler previously called authenticated dashboard endpoints without
credentials. Local authentication correctly rejected those requests with HTTP
401, preventing scheduled Linux collection.

This remediation adds an internal backend CLI and changes the host scheduler to
invoke it through `docker compose exec`. Public API authentication remains
unchanged. No dashboard password, session cookie, shared API token, or public
endpoint exemption is introduced.

The internal CLI:

- selects only deployed, non-Windows assets;
- runs the established 14-collector scheduled set;
- uses the existing collector execution service;
- uses Phase 10 change-aware persistence;
- records failures without aborting later collectors; and
- returns the response shape required by the existing host-side changelog
  comparison logic.

The installed cron script must be byte-identical to the repository script after
deployment.
