# Phase 10: Change-aware evidence persistence

Phase 10 separates collector execution history from full evidence snapshots.

- Every collector execution still creates a lightweight `collector_runs` record.
- The first observation and every meaningful state change create full evidence.
- Unchanged observations reuse the current evidence identifier.
- A full checkpoint is forced after `EVIDENCE_FORCED_SNAPSHOT_HOURS` (168 by default).
- PostgreSQL advisory locks serialize concurrent observations for one asset and collector.
- Linux API, initial deployment, and Windows ingestion use the same persistence service.
- The scheduled Linux inventory now includes every supported privileged collector;
  the existing scheduler cadence remains the detection interval.
- Historical duplicate analysis is available through the preview-only command below.

```bash
python -m app.cli.evidence_compaction_preview \
  --output /app/job-output/evidence-compaction-preview.json
```

The preview command cannot delete or modify evidence. Review and approval of a
separate deletion workflow is required before historical compaction can occur.
