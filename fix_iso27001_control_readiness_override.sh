#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$FILE" "${FILE}.bak.fix_control_readiness_override.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

old = 'setScores((cr && cr.framework_scores) ? cr.framework_scores : (s || {}));'

new = '''
    const mergedScores = {
      ...(s || {}),
      ...((cr && cr.framework_scores) || {})
    };

    setScores(mergedScores);
'''

if old not in content:
    raise SystemExit("ERROR: Expected score override line not found.")

content = content.replace(old, new)

path.write_text(content)

print("[+] Replaced destructive framework score override with merge logic.")
PY

echo "[+] Verification:"
grep -nA8 "mergedScores\\|setScores" "$FILE"

echo "[+] Done."
