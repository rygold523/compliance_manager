#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.nested_arrays.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path
import re

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

pattern = r'''if \(Array\.isArray\(value\)\) \{
\s*if \(value\.length === 0\) \{
\s*return "";
\s*\}

\s*return value\.map\(\(item, index\) => \(
\s*<div key=\{index\} className="current-state-list-item">
\s*\{renderCurrentStateValue\(item\)\}
\s*</div>
\s*\)\);
\s*\}'''

replacement = r'''if (Array.isArray(value)) {
    if (value.length === 0) {
      return "";
    }

    return (
      <div className="current-state-array">
        {value.map((item, index) => {
          if (typeof item === "object" && item !== null) {
            return (
              <div key={index} className="current-state-array-object">
                {Object.entries(item).map(([k, v]) => (
                  <div key={k} className="current-state-array-row">
                    <strong>{k}:</strong> {renderCurrentStateValue(v)}
                  </div>
                ))}
              </div>
            );
          }

          return (
            <div key={index} className="current-state-list-item">
              {renderCurrentStateValue(item)}
            </div>
          );
        })}
      </div>
    );
  }'''

new_content, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)

if count != 1:
    raise SystemExit("ERROR: Could not locate Array.isArray(value) block.")

path.write_text(new_content)

print("[+] Nested array object rendering fixed.")
PY

cat >> frontend/src/style.css <<'CSS'

.current-state-array {
  display: grid;
  gap: 8px;
}

.current-state-array-object {
  border-left: 3px solid #d000ff;
  padding-left: 8px;
  margin-bottom: 8px;
}

.current-state-array-row {
  margin-bottom: 2px;
  word-break: break-word;
}
CSS

echo "[+] Verification:"
grep -nA40 "Array.isArray(value)" "$MAIN_FILE"
