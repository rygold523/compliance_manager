from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import shutil
import re

from app.services.control_catalog import (
    list_controls,
    suggest_controls,
    framework_mappings_for_controls,
)

router = APIRouter(prefix="/api/policies", tags=["policies"])

BASE_DIR = Path("/var/lib/ai-vulnerability-management/policies")
FILES_DIR = BASE_DIR / "files"
DB_FILE = BASE_DIR / "policies.json"

FILES_DIR.mkdir(parents=True, exist_ok=True)


def now():
    return datetime.now(timezone.utc).isoformat()


def load_db():
    if not DB_FILE.exists():
        return []
    try:
        return json.loads(DB_FILE.read_text())
    except Exception:
        return []


def save_db(records):
    DB_FILE.write_text(json.dumps(records, indent=2, sort_keys=True))


def safe_name(filename):
    name = Path(filename or "policy_document").name
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def hash_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_control_selection(mapped_controls):
    if not mapped_controls:
        return []

    if isinstance(mapped_controls, list):
        return sorted(set(mapped_controls))

    try:
        parsed = json.loads(mapped_controls)
        if isinstance(parsed, list):
            return sorted(set(str(item) for item in parsed if item))
    except Exception:
        pass

    return sorted(set(part.strip() for part in str(mapped_controls).split(",") if part.strip()))


def mappings_for(control_ids):
    selected = parse_control_selection(control_ids)
    return {
        "controls": selected,
        "frameworks": framework_mappings_for_controls(selected),
    }


@router.get("/")
def list_policies():
    return load_db()


@router.post("/suggest-mappings")
def suggest_mappings(payload: dict):
    filename = payload.get("filename", "")
    scope = payload.get("scope", "")

    suggested = suggest_controls(scope=scope, filename=filename)

    return {
        "controls": list_controls(),
        "suggested_control_ids": [item["control_id"] for item in suggested],
        "suggested_controls": suggested,
    }


@router.post("/upload")
async def upload_policy(
    file: UploadFile = File(...),
    scope: str = Form(""),
    mapped_controls: str = Form("[]"),
):
    records = load_db()
    original_name = safe_name(file.filename)
    policy_id = "POL-" + hashlib.sha1(f"{original_name}:{now()}".encode()).hexdigest()[:12].upper()
    stored_name = f"{policy_id}-{original_name}"
    stored_path = FILES_DIR / stored_name

    with stored_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    mapping = mappings_for(mapped_controls)

    record = {
        "policy_id": policy_id,
        "filename": original_name,
        "stored_filename": stored_name,
        "scope": scope,
        "sha256": hash_file(stored_path),
        "size_bytes": stored_path.stat().st_size,
        "mapped_controls": mapping["controls"],
        "mapped_frameworks": mapping["frameworks"],
        "created_at": now(),
        "updated_at": now(),
    }

    records.append(record)
    save_db(records)
    return record


@router.put("/{policy_id}/replace")
async def replace_policy(
    policy_id: str,
    file: UploadFile = File(...),
    scope: str = Form(None),
    mapped_controls: str = Form(None),
):
    records = load_db()

    for record in records:
        if record["policy_id"] == policy_id:
            old_path = FILES_DIR / record["stored_filename"]
            if old_path.exists():
                old_path.unlink()

            original_name = safe_name(file.filename)
            stored_name = f"{policy_id}-{original_name}"
            stored_path = FILES_DIR / stored_name

            with stored_path.open("wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            if scope is not None and scope.strip():
                record["scope"] = scope

            if mapped_controls is not None:
                mapping = mappings_for(mapped_controls)
                record["mapped_controls"] = mapping["controls"]
                record["mapped_frameworks"] = mapping["frameworks"]

            record["filename"] = original_name
            record["stored_filename"] = stored_name
            record["sha256"] = hash_file(stored_path)
            record["size_bytes"] = stored_path.stat().st_size
            record["updated_at"] = now()

            save_db(records)
            return record

    raise HTTPException(status_code=404, detail="Policy not found")


@router.put("/{policy_id}/mappings")
def update_policy_mappings(policy_id: str, payload: dict):
    records = load_db()
    selected = payload.get("mapped_controls", [])

    for record in records:
        if record["policy_id"] == policy_id:
            mapping = mappings_for(selected)
            record["mapped_controls"] = mapping["controls"]
            record["mapped_frameworks"] = mapping["frameworks"]
            record["updated_at"] = now()
            save_db(records)
            return record

    raise HTTPException(status_code=404, detail="Policy not found")


@router.delete("/{policy_id}")
def delete_policy(policy_id: str):
    records = load_db()
    remaining = []
    deleted = None

    for record in records:
        if record["policy_id"] == policy_id:
            deleted = record
            stored_path = FILES_DIR / record["stored_filename"]
            if stored_path.exists():
                stored_path.unlink()
        else:
            remaining.append(record)

    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")

    save_db(remaining)

    return {
        "deleted": True,
        "policy_id": policy_id,
        "unmapped_controls": deleted.get("mapped_controls", []),
    }


@router.get("/{policy_id}/download")
def download_policy(policy_id: str):
    records = load_db()

    for record in records:
        if record["policy_id"] == policy_id:
            stored_path = FILES_DIR / record["stored_filename"]
            if not stored_path.exists():
                raise HTTPException(status_code=404, detail="Stored file missing")
            return FileResponse(stored_path, filename=record["filename"])

    raise HTTPException(status_code=404, detail="Policy not found")
