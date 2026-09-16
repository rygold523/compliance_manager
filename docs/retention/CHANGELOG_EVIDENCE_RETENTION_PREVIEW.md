# Changelog and Evidence Retention Preview

This implementation provides inventory and analysis only. It cannot archive,
delete, or schedule Changelog or evidence cleanup.

## Run a preview

```bash
sudo docker compose exec backend \
  python -m app.cli.evidence_retention_preview \
  --actor dashboard.admin \
  --output /app/evidence/retention/previews/latest.json
```

The default thresholds are 400 days for Changelog events, validated evidence,
and unvalidated evidence. These thresholds identify records that would leave
the directly accessible tier under the proposed policy; they do not authorize
disposition.

The report includes exact candidate and protected records, file existence and
size data, protection reasons, candidate totals, a deterministic SHA-256
fingerprint, dependency-check limitations, and confirmation that no archive,
deletion, or schedule action occurred. The preview itself is recorded in the
authentication audit table and Changelog.

## Legal holds

Legal holds are optional for ordinary previews. When `--legal-hold-file` is
provided, the file is mandatory and malformed content fails the command.

Example:

```json
{
  "description": "Records retained for the current assessment",
  "approved_by": "compliance.owner",
  "updated_at": "2026-09-13T00:00:00Z",
  "evidence_ids": ["EV-EXAMPLE"],
  "changelog_event_ids": ["EVT-EXAMPLE"],
  "finding_ids": ["F-EXAMPLE"],
  "asset_ids": ["production-database"],
  "control_ids": ["AC-02"],
  "file_paths": []
}
```

Run with the hold inventory:

```bash
sudo docker compose exec backend \
  python -m app.cli.evidence_retention_preview \
  --actor dashboard.admin \
  --legal-hold-file /app/evidence/retention/legal_holds.json \
  --output /app/evidence/retention/previews/latest.json
```

## Enforced protections

The preview protects the newest evidence and newest validated evidence for each
asset, logical collector, control, and framework combination. It also protects
records related to open findings, pending approvals, legal holds, shared paths,
missing or unsafe files, active access-review campaigns, and annotated
Changelog events.

The current database does not persist assessment, generated-report, or incident
relationships to evidence. The report discloses these limitations on every run.
Use the legal-hold inventory to protect affected records until first-class
relationship tables exist.
