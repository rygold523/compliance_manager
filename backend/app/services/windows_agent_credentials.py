from datetime import datetime, timezone
import hashlib
import hmac
import secrets
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import WindowsAgentCredential


def issue_credential(db: Session, asset_id: str) -> tuple[WindowsAgentCredential, str]:
    token = secrets.token_urlsafe(48)
    record = WindowsAgentCredential(
        credential_id=f"WAC-{uuid4().hex.upper()}",
        asset_id=asset_id,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        status="active",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record, token


def verify_credential(
    db: Session, credential_id: str, token: str, asset_id: str
) -> WindowsAgentCredential | None:
    record = db.query(WindowsAgentCredential).filter(
        WindowsAgentCredential.credential_id == credential_id,
        WindowsAgentCredential.asset_id == asset_id,
        WindowsAgentCredential.status == "active",
    ).one_or_none()
    digest = hashlib.sha256(token.encode()).hexdigest()
    if record is None or not hmac.compare_digest(record.token_hash, digest):
        return None
    record.last_used_at = datetime.now(timezone.utc)
    return record


def revoke_credential(db: Session, credential_id: str) -> None:
    record = db.query(WindowsAgentCredential).filter(
        WindowsAgentCredential.credential_id == credential_id
    ).one_or_none()
    if record is not None:
        record.status = "revoked"
        record.revoked_at = datetime.now(timezone.utc)
        db.commit()


def revoke_other_credentials(db: Session, asset_id: str, keep_id: str) -> None:
    records = db.query(WindowsAgentCredential).filter(
        WindowsAgentCredential.asset_id == asset_id,
        WindowsAgentCredential.credential_id != keep_id,
        WindowsAgentCredential.status == "active",
    ).all()
    now = datetime.now(timezone.utc)
    for record in records:
        record.status = "revoked"
        record.revoked_at = now
    db.commit()
