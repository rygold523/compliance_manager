#!/usr/bin/env python3
import json, os, socket, subprocess
from datetime import datetime, timezone

r = subprocess.run("df -PT", shell=True, text=True, capture_output=True, timeout=30)
items = []
for line in r.stdout.splitlines()[1:]:
    p = line.split()
    if len(p) >= 7:
        items.append({"filesystem": p[0], "type": p[1], "size": p[2], "used": p[3], "available": p[4], "use_percent": p[5], "mountpoint": p[6]})

print(json.dumps({
    "collector": "disk_usage",
    "asset_id": os.environ.get("ASSET_ID") or socket.gethostname(),
    "hostname": socket.gethostname(),
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "filesystems": items,
    "stderr": r.stderr,
    "exit_code": r.returncode,
}, indent=2))
