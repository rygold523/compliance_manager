from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import shutil
import re

router = APIRouter(prefix="/api/policies", tags=["policies"])

BASE_DIR = Path("/var/lib/ai-vulnerability-management/policies")
FILES_DIR = BASE_DIR / "files"
DB_FILE = BASE_DIR / "policies.json"

FILES_DIR.mkdir(parents=True, exist_ok=True)

CONTROL_KEYWORDS = {
    "AC-01": ["mfa", "multi-factor", "multifactor", "authentication", "access control", "identity"],
    "AC-02": ["user access", "account", "login", "password", "privilege", "ssh", "administrator"],
    "AM-01": ["asset", "inventory", "ownership", "classification"],
    "CM-01": ["configuration", "baseline", "hardening", "change management", "system configuration"],
    "CP-01": ["backup", "recovery", "business continuity", "disaster recovery", "restore"],
    "IR-01": ["incident", "response", "escalation", "security event"],
    "SI-01": ["logging", "monitoring", "siem", "alert", "audit log"],
    "VM-01": ["vulnerability", "patch", "remediation", "scan", "cve", "updates"],
    "NS-01": ["firewall", "network", "segmentation", "ports", "vpn", "traffic"],
    "EN-01": ["encryption", "tls", "ssl", "certificate", "cryptographic"],
    "SD-01": ["secure development", "code review", "sdlc", "deployment", "ci/cd"],
}

FRAMEWORK_MAP = {
    "AC-01": {"pci_dss": ["8.4"], "soc2": ["CC6.1"], "nist_800_53": ["IA-2"], "iso_27002": ["5.17"]},
    "AC-02": {"pci_dss": ["8.2", "8.3"], "soc2": ["CC6.2"], "nist_800_53": ["AC-2"], "iso_27002": ["5.18"]},
    "AM-01": {"pci_dss": ["12.5"], "soc2": ["CC6.1"], "nist_800_53": ["CM-8"], "iso_27002": ["5.9"]},
    "CM-01": {"pci_dss": ["2.2"], "soc2": ["CC8.1"], "nist_800_53": ["CM-2"], "iso_27002": ["8.9"]},
    "CP-01": {"pci_dss": ["12.10"], "soc2": ["A1.2"], "nist_800_53": ["CP-9"], "iso_27002": ["5.30"]},
    "IR-01": {"pci_dss": ["12.10"], "soc2": ["CC7.4"], "nist_800_53": ["IR-4"], "iso_27002": ["5.24"]},
    "SI-01": {"pci_dss": ["10.2"], "soc2": ["CC7.2"], "nist_800_53": ["AU-6"], "iso_27002": ["8.16"]},
    "VM-01": {"pci_dss": ["6.3"], "soc2": ["CC7.1"], "nist_800_53": ["RA-5"], "iso_27002": ["8.8"]},
    "NS-01": {"pci_dss": ["1.2"], "soc2": ["CC6.6"], "nist_800_53": ["SC-7"], "iso_27002": ["8.20"]},
    "EN-01": {"pci_dss": ["3.5", "4.2"], "soc2": ["CC6.7"], "nist_800_53": ["SC-13"], "iso_27002": ["8.24"]},
    "SD-01": {"pci_dss": ["6.2"], "soc2": ["CC8.1"], "nist_800_53": ["SA-11"], "iso_27002": ["8.25"]},
}


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


def map_policy(scope, filename):
    text = f"{scope or ''} {filename or ''}".lower()
    mapped_controls = []

    for control_id, keywords in CONTROL_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            mapped_controls.append(control_id)

    if not mapped_controls:
        mapped_controls = ["AC-02", "CM-01", "SI-01", "VM-01"]

    frameworks = {}
    for control_id in mapped_controls:
        for framework, refs in FRAMEWORK_MAP.get(control_id, {}).items():
            frameworks.setdefault(framework, [])
            for ref in refs:
                if ref not in frameworks[framework]:
                    frameworks[framework].append(ref)

    return {
        "controls": sorted(mapped_controls),
        "frameworks": frameworks,
    }


@router.get("/")
def list_policies():
    return load_db()


@router.post("/upload")
async def upload_policy(
    file: UploadFile = File(...),
    scope: str = Form(""),
):
    records = load_db()
    original_name = safe_name(file.filename)
    policy_id = "POL-" + hashlib.sha1(f"{original_name}:{now()}".encode()).hexdigest()[:12].upper()
    stored_name = f"{policy_id}-{original_name}"
    stored_path = FILES_DIR / stored_name

    with stored_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    mapping = map_policy(scope, original_name)

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

            record["filename"] = original_name
            record["stored_filename"] = stored_name
            record["sha256"] = hash_file(stored_path)
            record["size_bytes"] = stored_path.stat().st_size
            record["updated_at"] = now()

            if scope is not None and scope.strip():
                record["scope"] = scope

            save_db(records)
            return record

    raise HTTPException(status_code=404, detail="Policy not found")


@router.post("/{policy_id}/remap")
def remap_policy(policy_id: str):
    records = load_db()

    for record in records:
        if record["policy_id"] == policy_id:
            mapping = map_policy(record.get("scope", ""), record.get("filename", ""))
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
