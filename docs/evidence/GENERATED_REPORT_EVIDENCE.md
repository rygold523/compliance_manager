# Generated Report-to-Evidence Relationships

This phase persists authoritative PDF and ZIP report artifacts, their SHA-256 hashes, and the exact evidence records used to generate them.

## Behavior

- PDF traceability reports and ZIP evidence packages are copied to `/app/evidence/generated-reports/<framework>/`.
- Each artifact creates a `generated_reports` row and one `generated_report_evidence` row per included evidence record.
- The response includes `X-Generated-Report-ID` for correlation.
- Reports begin in `current` status. Supported statuses are `draft`, `current`, `issued`, `superseded`, and `revoked`.
- Evidence linked to a `draft`, `current`, or `issued` report is protected by retention preview with reason `generated_report`.
- Every report record and status transition creates authentication-audit and Changelog events.
- No deletion or automatic scheduling is added.

## API

- `GET /api/report-records` — admin or auditor
- `GET /api/report-records/{report_id}` — admin or auditor
- `PATCH /api/report-records/{report_id}/status` — admin

Existing generation endpoints remain:

- `GET /api/reports/{framework}/pdf`
- `GET /api/reports/{framework}/package`

## Rollback

Rollback restores application files but preserves the additive database tables, report records, relationship records, and generated artifacts. Permanent removal would require a separate explicitly approved destructive procedure.
