#!/usr/bin/env python3
import json
import subprocess
from datetime import datetime, timezone


def run(cmd):
    p = subprocess.run(
        cmd,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return p.stdout.strip()


def get_packages():
    out = run("dpkg-query -W -f='${binary:Package}\\t${Version}\\n'")
    packages = []

    for line in out.splitlines():
        if "\t" not in line:
            continue

        name, version = line.split("\t", 1)

        packages.append({
            "name": name,
            "installed_version": version,
            "latest_candidate": version,
            "update_available": "no",
            "held": "no",
        })

    return packages


def get_upgradable():
    out = run("apt list --upgradable 2>/dev/null | tail -n +2")
    updates = {}

    for line in out.splitlines():
        if "/" not in line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        name = parts[0].split("/", 1)[0]
        candidate = parts[1]

        updates[name] = candidate

    return updates


def get_held():
    out = run("apt-mark showhold 2>/dev/null")
    return {line.strip() for line in out.splitlines() if line.strip()}


packages = get_packages()
updates = get_upgradable()
held = get_held()

for pkg in packages:
    name = pkg["name"]
    base_name = name.split(":", 1)[0]

    candidate = updates.get(name) or updates.get(base_name)
    if candidate:
        pkg["latest_candidate"] = candidate
        pkg["update_available"] = "yes"

    if name in held or base_name in held:
        pkg["held"] = "yes"

result = {
    "collector": "package_inventory",
    "status": "completed",
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "package_count": len(packages),
    "updates_available": sum(1 for p in packages if p["update_available"] == "yes"),
    "held_packages": sum(1 for p in packages if p["held"] == "yes"),
    "unknown_latest": 0,
    "packages": packages,
}

print(json.dumps(result))
