#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

collector_dir = Path("/usr/local/lib/compliance/collectors")
manifest_path = collector_dir / "collector_manifest.json"

result = {
    "collector": "collector_health",
    "status": "completed",
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "collector_dir": str(collector_dir),
    "manifest_present": manifest_path.exists(),
    "collectors": [],
    "drift_detected": False,
}

if manifest_path.exists():
    manifest = json.loads(manifest_path.read_text())
    expected = manifest.get("collectors", {})

    for name, meta in sorted(expected.items()):
        path = collector_dir / name
        exists = path.exists()
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest() if exists else None
        expected_hash = meta.get("sha256")
        drift = actual_hash != expected_hash

        if drift:
            result["drift_detected"] = True

        result["collectors"].append({
            "name": name,
            "version": meta.get("version"),
            "exists": exists,
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
            "drift": drift,
        })

print(json.dumps(result))
