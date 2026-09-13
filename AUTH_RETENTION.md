# Authentication Retention

This phase applies only to `auth_sessions` and `auth_audit_events`. It does not
delete or alter Changelog records, Changelog evidence, general evidence, access
reviews, findings, or asset inventory.

## Safety model

- Preview is the default and prints every candidate row.
- Active sessions are never eligible. A session is eligible only when it
  expired before the session cutoff or was revoked before that cutoff.
- Audit events are eligible only when their `created_at` timestamp is older
  than the audit cutoff. Retention-action audit events are always protected.
- Execution requires `--execute`, an administrative actor, and the exact
  confirmation phrase `DELETE ARCHIVED AUTH RECORDS`.
- Execution writes JSONL exports and a SHA-256 manifest before deleting rows.
- Preview and execution each create an `auth_audit_events` record and a
  Changelog record.
- No scheduler or automatic cleanup is installed or enabled.

The defaults are 30 days for completed sessions and 400 days for authentication
audit events. The audit setting is an operational default, not an approved
corporate records-retention policy. Compliance and Legal must approve the final
period before production deletion is scheduled.

## Preview

```bash
sudo docker compose exec backend \
  python -m app.cli.auth_retention \
  --actor dashboard.admin
```

Override retention periods when required:

```bash
sudo docker compose exec backend \
  python -m app.cli.auth_retention \
  --actor dashboard.admin \
  --session-days 45 \
  --audit-days 400
```

Review the complete JSON output. It includes the exact rows that would be
archived and deleted. Store the preview with the associated change ticket.

## Execute

```bash
sudo docker compose exec backend \
  python -m app.cli.auth_retention \
  --actor dashboard.admin \
  --session-days 45 \
  --audit-days 400 \
  --execute \
  --confirm 'DELETE ARCHIVED AUTH RECORDS'
```

Archives are written below `/app/evidence/retention/auth`, which is on the
existing persistent evidence volume. Each run has its own directory containing
`auth_sessions.jsonl`, `auth_audit_events.jsonl`, and `manifest.json`. Validate
the hashes in the manifest and copy the archive into the approved backup system
before treating the cleanup as complete.

## Restore archived rows

There is deliberately no automatic database restore command. Restoring audit or
session rows can conflict with IDs and token hashes created after cleanup. For a
required restore, stop cleanup scheduling, take a database backup, validate the
manifest hashes, and import the JSONL rows through a reviewed database change.
The dedicated rollback package removes this feature's code and configuration;
it does not erase archives or reverse already committed database deletions.

## Deploy and roll back the code

Extract the update package on the dashboard host, then run:

```bash
chmod 0755 deploy-auth-retention.sh rollback-auth-retention.sh
./deploy-auth-retention.sh /opt/ai-vulnerability-management
```

This rebuilds only the backend and does not run cleanup. To restore the files
that existed immediately before deployment, run:

```bash
./rollback-auth-retention.sh /opt/ai-vulnerability-management
```
