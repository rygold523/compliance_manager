# Changelog and Evidence Archive Only Mode

This phase creates verified archive packages from an unchanged, approved
preview candidate set. It cannot delete source records or files and cannot
create a schedule.

## Required workflow

1. Run the preview-only CLI and save its complete JSON output.
2. Review the candidates, protected records, dependency limitations, and legal
   holds.
3. Record approval in the applicable change ticket.
4. Run archive-only mode with the exact candidate fingerprint and approval
   reference from that review.
5. Copy the completed archive into the approved backup system and record the
   external backup reference in the change ticket.

Archive example:

```bash
sudo docker compose exec backend \
  python -m app.cli.evidence_retention_archive \
  --actor dashboard.admin \
  --approval-reference CHG-12345 \
  --candidate-fingerprint EXPECTED_SHA256
```

Use the same `--legal-hold-file` and retention-day overrides used during the
approved preview. Any change to candidate metadata, Changelog content, evidence
file size, or evidence file content changes the fingerprint and blocks the
archive.

Archives are stored under
`/app/evidence/retention/changelog-evidence-archives`, which maps to the existing
persistent evidence volume. Each `.tar.gz` contains:

- Complete preview output.
- Candidate evidence metadata in JSONL.
- Candidate Changelog events in JSONL.
- Copies of candidate evidence files.
- A manifest with counts, paths, sizes, SHA-256 hashes, actor, approval
  reference, policy, cutoffs, and candidate fingerprint.

The command verifies copied evidence against the approved preview hashes and
then reopens the completed package to verify every archive member against the
manifest. It records successful and skipped archive actions in the
authentication audit table and Changelog.

An empty candidate set produces a logged `skipped` result and no archive file.
Archive output reports external backup confirmation as pending because the
application cannot verify a separate backup platform. No deletion capability
will be implemented or enabled until the retention policy is approved.
