#!/usr/bin/env python3
import json, os, socket, subprocess
from datetime import datetime, timezone

def run(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=45)

docker_present = subprocess.run("command -v docker >/dev/null 2>&1", shell=True).returncode == 0
containers, images, errors = [], [], []

if docker_present:
    ps = run("sudo -n docker ps --format '{{json .}}'")
    if ps.stderr:
        errors.append(ps.stderr.strip())
    for line in ps.stdout.splitlines():
        try: containers.append(json.loads(line))
        except Exception: containers.append({"raw": line})

    imgs = run("sudo -n docker images --format '{{json .}}'")
    if imgs.stderr:
        errors.append(imgs.stderr.strip())
    for line in imgs.stdout.splitlines():
        try: images.append(json.loads(line))
        except Exception: images.append({"raw": line})

print(json.dumps({
    "collector": "docker_inventory",
    "asset_id": os.environ.get("ASSET_ID") or socket.gethostname(),
    "hostname": socket.gethostname(),
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "docker_present": docker_present,
    "containers": containers,
    "images": images,
    "errors": errors,
}, indent=2))
