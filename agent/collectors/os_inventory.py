#!/usr/bin/env python3
import json, os, platform, socket
from datetime import datetime, timezone

def read_os_release():
    data = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip('"')
    except Exception:
        pass
    return data

print(json.dumps({
    "collector": "os_inventory",
    "asset_id": os.environ.get("ASSET_ID") or socket.gethostname(),
    "hostname": socket.gethostname(),
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "os_release": read_os_release(),
    "kernel": platform.release(),
    "architecture": platform.machine(),
}, indent=2))
