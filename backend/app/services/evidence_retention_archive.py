import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.api.changelog import write_changelog
from app.auth.service import audit
from app.services.evidence_retention_preview import PreviewPolicy, build_preview


ARCHIVE_EVENT_TYPE = "changelog_evidence_retention_archived"
ARCHIVE_SKIPPED_EVENT_TYPE = "changelog_evidence_retention_archive_skipped"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _secure_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _jsonl(rows: list[dict]) -> bytes:
    return "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":"), default=str) + "\n"
        for row in rows
    ).encode("utf-8")


def _safe_component(value: str) -> str:
    sanitized = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "_"
        for character in value
    ).strip(".")
    if sanitized and sanitized not in {".", ".."}:
        return sanitized[:96]
    return f"record-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


def _record_action(db: Session, event_type: str, actor: str, detail: dict) -> str:
    audit_event_id = audit(
        db,
        event_type,
        username=actor,
        detail={"actor_username": actor, **detail},
    )
    db.commit()
    write_changelog(
        event_type=event_type,
        asset_id="compliance-dashboard",
        summary=(
            f"Changelog and evidence retention archive was "
            f"{'skipped' if event_type == ARCHIVE_SKIPPED_EVENT_TYPE else 'created'} by {actor}."
        ),
        details={"audit_event_id": audit_event_id, "actor_username": actor, **detail},
    )
    return audit_event_id


def create_archive(
    db: Session,
    policy: PreviewPolicy,
    evidence_root: Path,
    access_review_file: Path,
    archive_root: Path,
    actor: str,
    approval_reference: str,
    expected_fingerprint: str,
    *,
    legal_hold_file: Path | None = None,
    now: datetime | None = None,
) -> dict:
    actor = actor.strip()
    approval_reference = approval_reference.strip()
    expected_fingerprint = expected_fingerprint.strip().lower()
    if not actor:
        raise ValueError("An administrative actor is required.")
    if not approval_reference:
        raise ValueError("An approval reference is required.")
    if len(expected_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in expected_fingerprint):
        raise ValueError("The expected candidate fingerprint must be a SHA-256 hexadecimal value.")

    preview = build_preview(
        db,
        policy,
        evidence_root,
        access_review_file,
        legal_hold_file,
        now,
    )
    actual_fingerprint = preview["candidate_fingerprint_sha256"]
    if actual_fingerprint != expected_fingerprint:
        raise ValueError(
            "Candidate fingerprint mismatch. Run and approve a new preview before archiving."
        )

    common = {
        "approval_reference": approval_reference,
        "policy": preview["policy"],
        "cutoffs": preview["cutoffs"],
        "candidate_counts": preview["counts"],
        "candidate_fingerprint_sha256": actual_fingerprint,
        "actions_performed": {"archived": False, "deleted": False, "scheduled": False},
    }
    total_candidates = (
        preview["counts"]["candidate_evidence"]
        + preview["counts"]["candidate_changelog"]
    )
    if total_candidates == 0:
        audit_event_id = _record_action(
            db, ARCHIVE_SKIPPED_EVENT_TYPE, actor, {**common, "reason": "no_candidates"}
        )
        return {
            "mode": "archive_only",
            "status": "skipped",
            "reason": "no_candidates",
            **common,
            "audit_event_id": audit_event_id,
        }

    generated = datetime.now(timezone.utc)
    stamp = generated.strftime("%Y%m%dT%H%M%SZ")
    archive_id = f"changelog-evidence-{stamp}-{uuid4().hex[:12]}"
    archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    final_path = archive_root / f"{archive_id}.tar.gz"
    if final_path.exists():
        raise FileExistsError(f"Archive already exists: {final_path}")

    with tempfile.TemporaryDirectory(prefix=f".{archive_id}-", dir=archive_root) as temporary:
        work = Path(temporary)
        os.chmod(work, 0o700)
        records = work / "records"
        files_dir = work / "evidence-files"
        records.mkdir(mode=0o700)
        files_dir.mkdir(mode=0o700)

        evidence_rows = preview["candidates"]["evidence"]
        changelog_rows = preview["candidates"]["changelog"]
        _secure_write(records / "evidence.jsonl", _jsonl(evidence_rows))
        _secure_write(records / "changelog.jsonl", _jsonl(changelog_rows))
        _secure_write(
            records / "preview.json",
            (json.dumps(preview, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8"),
        )

        copied = []
        for item in evidence_rows:
            source = Path(item["file"]["path"]).resolve(strict=True)
            root = evidence_root.resolve(strict=True)
            if root not in source.parents:
                raise ValueError(f"Candidate evidence file is outside the evidence root: {source}")
            destination = files_dir / _safe_component(item["evidence_id"]) / source.name
            destination.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o600)
            source_hash = _hash_file(source)
            copied_hash = _hash_file(destination)
            if source_hash != item["file"]["sha256"] or copied_hash != source_hash:
                raise ValueError(f"Evidence file changed or failed verification: {source}")
            copied.append({
                "evidence_id": item["evidence_id"],
                "source_path": str(source),
                "archive_path": str(destination.relative_to(work)),
                "size_bytes": destination.stat().st_size,
                "sha256": copied_hash,
            })

        archived_files = []
        for path in sorted(work.rglob("*")):
            if path.is_file():
                archived_files.append({
                    "path": str(path.relative_to(work)),
                    "size_bytes": path.stat().st_size,
                    "sha256": _hash_file(path),
                })
        manifest = {
            "archive_id": archive_id,
            "created_at": generated.isoformat(),
            "actor": actor,
            "approval_reference": approval_reference,
            "policy": preview["policy"],
            "cutoffs": preview["cutoffs"],
            "candidate_fingerprint_sha256": actual_fingerprint,
            "counts": {
                "evidence_records": len(evidence_rows),
                "changelog_events": len(changelog_rows),
                "evidence_files": len(copied),
            },
            "evidence_files": copied,
            "archive_members": archived_files,
            "source_actions": {"deleted": False, "scheduled": False},
            "backup_confirmation": {
                "status": "pending_external_copy",
                "requirement": "Copy this archive into the approved backup system and record its reference before deletion is considered.",
            },
        }
        _secure_write(
            work / "manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

        temporary_archive = archive_root / f".{archive_id}.{uuid4().hex}.tmp"
        try:
            with tarfile.open(temporary_archive, "w:gz") as package:
                for path in sorted(work.rglob("*")):
                    package.add(path, arcname=str(Path(archive_id) / path.relative_to(work)), recursive=False)
            os.chmod(temporary_archive, 0o600)
            with tarfile.open(temporary_archive, "r:gz") as package:
                members = {member.name: member for member in package.getmembers()}
                manifest_name = f"{archive_id}/manifest.json"
                if manifest_name not in members:
                    raise ValueError("Archive verification failed: manifest is missing.")
                for expected in manifest["archive_members"]:
                    member_name = f"{archive_id}/{expected['path']}"
                    member = members.get(member_name)
                    if member is None or not member.isfile():
                        raise ValueError(f"Archive verification failed: missing member {member_name}")
                    extracted = package.extractfile(member)
                    if extracted is None:
                        raise ValueError(f"Archive verification failed: unreadable member {member_name}")
                    digest = hashlib.sha256()
                    for block in iter(lambda: extracted.read(1024 * 1024), b""):
                        digest.update(block)
                    if member.size != expected["size_bytes"] or digest.hexdigest() != expected["sha256"]:
                        raise ValueError(f"Archive verification failed: hash mismatch for {member_name}")
            os.replace(temporary_archive, final_path)
        finally:
            if temporary_archive.exists():
                temporary_archive.unlink()

    archive_hash = _hash_file(final_path)
    detail = {
        **common,
        "archive_id": archive_id,
        "archive_path": str(final_path),
        "archive_size_bytes": final_path.stat().st_size,
        "archive_sha256": archive_hash,
        "archive_counts": manifest["counts"],
        "backup_confirmation": manifest["backup_confirmation"],
        "actions_performed": {"archived": True, "deleted": False, "scheduled": False},
    }
    audit_event_id = _record_action(db, ARCHIVE_EVENT_TYPE, actor, detail)
    return {
        "mode": "archive_only",
        "status": "completed",
        **detail,
        "audit_event_id": audit_event_id,
    }
