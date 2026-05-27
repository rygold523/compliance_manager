#!/usr/bin/env python3
import json, os, socket, subprocess
from datetime import datetime, timezone

result = subprocess.run("sudo -n ss -tulpn || ss -tuln", shell=True, text=True, capture_output=True, timeout=30)
ports = []

for line in result.stdout.splitlines()[1:]:
    p = line.split()
    if len(p) >= 5:
        ports.append({
            "netid": p[0],
            "state": p[1],
            "recv_q": p[2],
            "send_q": p[3],
            "local_address": p[4],
            "peer_address": p[5] if len(p) > 5 else "",
            "process": " ".join(p[6:]) if len(p) > 6 else "",
        })

print(json.dumps({
    "collector": "listening_ports",
    "asset_id": os.environ.get("ASSET_ID") or socket.gethostname(),
    "hostname": socket.gethostname(),
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "ports": ports,
    "stderr": result.stderr,
    "exit_code": result.returncode,
}, indent=2))
