# Assessment-to-Evidence Relationships

This phase adds persistent assessment records and explicit links from assessments to evidence. It closes the first dependency gap identified by the Changelog and evidence retention preview.

## Safety boundary

- Evidence linked to a `planned` or `in_progress` assessment is protected by retention preview with reason `active_assessment`.
- `completed`, `closed`, and `cancelled` assessments do not independently create an indefinite retention hold.
- Existing legal-hold, current-evidence, open-finding, pending-approval, file-integrity, and shared-path protections remain in force.
- No evidence deletion or automatic scheduling capability is added.
- Generated-report and incident dependency gaps remain open and continue to be reported by the preview.

## Assessment lifecycle

Allowed transitions are:

- `planned` to `in_progress` or `cancelled`
- `in_progress` to `completed` or `cancelled`
- `completed` to `closed` or back to `in_progress`
- `closed` and `cancelled` are terminal

## API

Read operations require the `admin` or `auditor` role. Mutating operations require `admin`.

- `GET /api/assessments`
- `POST /api/assessments`
- `GET /api/assessments/{assessment_id}`
- `PATCH /api/assessments/{assessment_id}/status`
- `POST /api/assessments/{assessment_id}/evidence`
- `DELETE /api/assessments/{assessment_id}/evidence/{evidence_id}`

Every create, status change, link, and unlink operation writes both an authentication audit event and a Changelog event.

## Deployment

From the extracted update package:

```bash
chmod 0755 deploy-assessment-evidence.sh rollback-assessment-evidence.sh
./deploy-assessment-evidence.sh /opt/ai-vulnerability-management
```

The deployment creates an application-file backup, applies the additive database migration, rebuilds only the backend, waits for health, and verifies both new tables. The migration does not modify or remove existing evidence.

## Rollback

```bash
./rollback-assessment-evidence.sh /opt/ai-vulnerability-management
```

Rollback restores application files and rebuilds the backend. It deliberately preserves the two additive database tables and their contents so rollback cannot destroy assessment records or audit evidence.
