#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.modal_object_render.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path
import re

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

helper = r'''
function renderAnyValue(value) {
  if (value === null || value === undefined || value === "") return "";

  if (Array.isArray(value)) {
    if (value.length === 0) return "";
    return (
      <ul className="modal-value-list">
        {value.map((item, index) => (
          <li key={index}>{renderAnyValue(item)}</li>
        ))}
      </ul>
    );
  }

  if (typeof value === "object") {
    return (
      <div className="modal-object-value">
        {Object.entries(value).map(([key, itemValue]) => (
          <div key={key} className="modal-object-row">
            <span className="modal-object-key">{key}:</span>{" "}
            <span className="modal-object-detail">{renderAnyValue(itemValue)}</span>
          </div>
        ))}
      </div>
    );
  }

  return String(value);
}
'''

if "function renderAnyValue(value)" not in content:
    content = helper + "\n" + content

# Replace string interpolation patterns that force object values to become [object Object].
content = re.sub(
    r'Object\.entries\(([^)]+)\)\.map\(\(\[k,\s*v\]\)\s*=>\s*<div key=\{k\}>\{k\}:\s*\{v\}</div>\)',
    r'Object.entries(\1).map(([k, v]) => <div key={k}><strong>{k}:</strong> {renderAnyValue(v)}</div>)',
    content
)

content = re.sub(
    r'Object\.entries\(([^)]+)\)\.map\(\(\[key,\s*value\]\)\s*=>\s*<div key=\{key\}>\{key\}:\s*\{value\}</div>\)',
    r'Object.entries(\1).map(([key, value]) => <div key={key}><strong>{key}:</strong> {renderAnyValue(value)}</div>)',
    content
)

# Replace common raw modal object value renderers.
content = content.replace("{v}", "{renderAnyValue(v)}")
content = content.replace("{value}", "{renderAnyValue(value)}")

path.write_text(content)

print("[+] Generic modal object renderer patched.")
PY

cat >> frontend/src/style.css <<'CSS'

/* Generic Modal Object Rendering */
.modal-object-value {
  display: grid;
  gap: 6px;
}

.modal-object-row {
  padding-bottom: 6px;
  border-bottom: 1px solid #d8dbe3;
}

.modal-object-row:last-child {
  border-bottom: 0;
}

.modal-object-key {
  font-weight: 700;
  color: #050505;
}

.modal-object-detail {
  color: #30363d;
}

.modal-value-list {
  margin: 4px 0 4px 18px;
  padding: 0;
}

.modal-value-list li {
  margin-bottom: 4px;
}
CSS

echo "[+] Relevant render references:"
grep -n "renderAnyValue\|modalData\|Object.entries" "$MAIN_FILE" | head -120

echo "[+] Done."
