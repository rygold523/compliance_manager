# Phase 4: Non-root backend and worker

The backend image now runs as UID/GID `1001:1001`, matching the existing
host-side `aivuln` account. Both the API and worker inherit this image user.

Playwright browsers are installed at `/ms-playwright` rather than beneath
`/root`, and the application home is `/home/aivuln`.

Before deploying, the persistent application state must be assigned to
`aivuln:aivuln`. The read-only application SSH keys remain owned by root but
receive group `aivuln` and mode `0640`; this does not make them world-readable.

The broad `/var/lib/ai-vulnerability-management` mount remains present for
compatibility. Current APIs still use paths below it for policies, documents,
reports, control readiness, Windows collector downloads, and evidence. Mount
reduction must be handled separately after those paths are centralized in
configuration.

Rollback requires restoring `backend/Dockerfile`, rebuilding the old image,
and restoring `/opt/ai-vulnerability-management/backend/ssh/id_rsa` and
`id_ed25519` to root ownership and mode `0600`. Persistent state can remain
owned by `aivuln`; the former root container can still access it.
