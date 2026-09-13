import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.api.changelog import write_changelog
from app.auth.service import audit
from app.models.models import AuthAuditEvent, AuthSession


CONFIRMATION_PHRASE = "DELETE ARCHIVED AUTH RECORDS"
ACTION_EVENT_TYPES = frozenset({"auth_retention_previewed", "auth_retention_executed"})


@dataclass(frozen=True)
class RetentionPolicy:
    session_days: int
    audit_days: int

    def __post_init__(self):
        if self.session_days < 1 or self.audit_days < 1:
            raise ValueError("Retention periods must be at least one day.")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _session_record(row: AuthSession) -> dict:
    return {
        "id": row.id,
        "session_token_hash": row.session_token_hash,
        "user_id": row.user_id,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "last_seen_at": _iso(row.last_seen_at),
        "revoked_at": _iso(row.revoked_at),
    }


def _audit_record(row: AuthAuditEvent) -> dict:
    return {
        "id": row.id,
        "event_type": row.event_type,
        "username": row.username,
        "user_id": row.user_id,
        "source_address": row.source_address,
        "detail": row.detail if isinstance(row.detail, dict) else {},
        "created_at": _iso(row.created_at),
    }


def eligible_records(db: Session, policy: RetentionPolicy, now: datetime | None = None):
    reference = now or utc_now()
    session_cutoff = reference - timedelta(days=policy.session_days)
    audit_cutoff = reference - timedelta(days=policy.audit_days)

    sessions = (
        db.query(AuthSession)
        .filter(
            or_(
                AuthSession.expires_at <= session_cutoff,
                and_(
                    AuthSession.revoked_at.is_not(None),
                    AuthSession.revoked_at <= session_cutoff,
                ),
            )
        )
        .order_by(AuthSession.id.asc())
        .all()
    )
    audit_events = (
        db.query(AuthAuditEvent)
        .filter(
            AuthAuditEvent.created_at <= audit_cutoff,
            AuthAuditEvent.event_type.notin_(ACTION_EVENT_TYPES),
        )
        .order_by(AuthAuditEvent.id.asc())
        .all()
    )
    return reference, session_cutoff, audit_cutoff, sessions, audit_events


def build_preview(db: Session, policy: RetentionPolicy, now: datetime | None = None) -> dict:
    reference, session_cutoff, audit_cutoff, sessions, audit_events = eligible_records(
        db, policy, now
    )
    return {
        "mode": "preview",
        "generated_at": _iso(reference),
        "policy": asdict(policy),
        "session_cutoff": _iso(session_cutoff),
        "audit_cutoff": _iso(audit_cutoff),
        "sessions": [_session_record(row) for row in sessions],
        "audit_events": [_audit_record(row) for row in audit_events],
        "counts": {"sessions": len(sessions), "audit_events": len(audit_events)},
    }


def _secure_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_archive(preview: dict, archive_root: Path) -> dict:
    stamp = preview["generated_at"].replace("-", "").replace(":", "").replace("+00:00", "Z")
    archive_id = f"auth-retention-{stamp}-{uuid4().hex[:12]}"
    archive_dir = archive_root / archive_id
    archive_dir.mkdir(parents=True, exist_ok=False, mode=0o700)

    payloads = {
        "auth_sessions.jsonl": preview["sessions"],
        "auth_audit_events.jsonl": preview["audit_events"],
    }
    files = []
    for filename, rows in payloads.items():
        content = "".join(json.dumps(row, sort_keys=True, default=str) + "\n" for row in rows).encode()
        path = archive_dir / filename
        _secure_write(path, content)
        files.append({
            "name": filename,
            "rows": len(rows),
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })

    manifest = {
        "archive_id": archive_id,
        "created_at": preview["generated_at"],
        "policy": preview["policy"],
        "session_cutoff": preview["session_cutoff"],
        "audit_cutoff": preview["audit_cutoff"],
        "files": files,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    _secure_write(archive_dir / "manifest.json", manifest_bytes)
    return {
        "archive_id": archive_id,
        "archive_path": str(archive_dir),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "files": files,
    }


def _record_action(db: Session, event_type: str, actor: str, detail: dict) -> str:
    event_id = audit(db, event_type, username=actor, detail={"actor_username": actor, **detail})
    db.flush()
    write_changelog(
        event_type=event_type,
        asset_id="compliance-dashboard",
        summary=f"Authentication retention was {'previewed' if event_type.endswith('previewed') else 'executed'} by {actor}.",
        details={"audit_event_id": event_id, "actor_username": actor, **detail},
    )
    return event_id


def run_retention(
    db: Session,
    policy: RetentionPolicy,
    archive_root: Path,
    actor: str,
    *,
    execute: bool = False,
    confirmation: str | None = None,
    now: datetime | None = None,
) -> dict:
    if not actor.strip():
        raise ValueError("An administrative actor is required.")
    if execute and confirmation != CONFIRMATION_PHRASE:
        raise ValueError(f"Execution requires --confirm '{CONFIRMATION_PHRASE}'.")

    preview = build_preview(db, policy, now)
    common = {
        "policy": preview["policy"],
        "session_cutoff": preview["session_cutoff"],
        "audit_cutoff": preview["audit_cutoff"],
        "candidate_counts": preview["counts"],
    }
    if not execute:
        event_id = _record_action(db, "auth_retention_previewed", actor, common)
        db.commit()
        return {**preview, "audit_event_id": event_id}

    archive = write_archive(preview, archive_root)
    session_ids = [row["id"] for row in preview["sessions"]]
    audit_ids = [row["id"] for row in preview["audit_events"]]
    try:
        # Candidate ORM objects are no longer needed after the archive is
        # durable. Detaching them prevents stale identity-map entries during
        # the bulk deletes and the subsequent retention audit insert.
        db.expunge_all()
        deleted_sessions = 0
        deleted_audit_events = 0
        if session_ids:
            deleted_sessions = (
                db.query(AuthSession)
                .filter(AuthSession.id.in_(session_ids))
                .delete(synchronize_session=False)
            )
        if audit_ids:
            deleted_audit_events = (
                db.query(AuthAuditEvent)
                .filter(
                    AuthAuditEvent.id.in_(audit_ids),
                    AuthAuditEvent.event_type.notin_(ACTION_EVENT_TYPES),
                )
                .delete(synchronize_session=False)
            )
        deleted = {"sessions": deleted_sessions, "audit_events": deleted_audit_events}
        event_id = _record_action(
            db,
            "auth_retention_executed",
            actor,
            {**common, "deleted_counts": deleted, **archive},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "mode": "execute",
        "generated_at": preview["generated_at"],
        "policy": preview["policy"],
        "candidate_counts": preview["counts"],
        "deleted_counts": deleted,
        "archive": archive,
        "audit_event_id": event_id,
    }
