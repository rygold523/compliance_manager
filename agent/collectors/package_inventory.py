#!/usr/bin/env python3
import json, os, socket, subprocess
from datetime import datetime, timezone

packages, stderr, exit_code = [], "", 0

if subprocess.run("command -v dpkg-query >/dev/null 2>&1", shell=True).returncode == 0:
    r = subprocess.run("dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n'", shell=True, text=True, capture_output=True, timeout=120)
    stderr, exit_code = r.stderr, r.returncode
    for line in r.stdout.splitlines():
        p = line.split("\t")
        if len(p) >= 3:
            packages.append({"name": p[0], "version": p[1], "architecture": p[2]})

print(json.dumps({
    "collector": "package_inventory",
    "asset_id": os.environ.get("ASSET_ID") or socket.gethostname(),
    "hostname": socket.gethostname(),
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "package_manager": "dpkg" if packages else "unknown",
    "package_count": len(packages),
    "packages": packages,
    "stderr": stderr,
    "exit_code": exit_code,
}, indent=2))
