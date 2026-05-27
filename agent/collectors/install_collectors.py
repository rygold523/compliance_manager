#!/usr/bin/env python3
import os
import shutil
from pathlib import Path

src = Path("/tmp/compliance_collectors")
dst = Path("/usr/local/lib/compliance/collectors")

dst.mkdir(parents=True, exist_ok=True)

if src.exists():
    for file in src.glob("*.py"):
        target = dst / file.name
        shutil.copy2(file, target)
        os.chmod(target, 0o755)

for file in dst.glob("*.py"):
    os.chown(file, 0, 0)
    os.chmod(file, 0o755)

print("collector_install_complete")
