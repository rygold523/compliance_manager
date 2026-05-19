#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.datatable_object_render.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path
import re

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

pattern = r"function DataTable\(\{ columns, rows \}\) \{.*?\n\}"

replacement = r'''function DataTable({ columns, rows }) {
  return (
    <table>
      <thead>
        <tr>
          {columns.map(col => (
            <th key={col.key}>{col.label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {!rows || rows.length === 0 ? (
          <tr>
            <td colSpan={columns.length}>No records found.</td>
          </tr>
        ) : (
          rows.map((row, idx) => (
            <tr key={idx}>
              {columns.map(col => (
                <td key={col.key}>
                  {col.render
                    ? col.render(row)
                    : renderCurrentStateValue(row[col.key])}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
    </table>
  );
}'''

new_content, count = re.subn(pattern, replacement, content, count=1, flags=re.DOTALL)

if count != 1:
    raise SystemExit("ERROR: Could not safely replace DataTable function.")

path.write_text(new_content)

print("[+] DataTable now renders nested objects safely.")
PY

echo "[+] DataTable block:"
nl -ba "$MAIN_FILE" | sed -n '260,295p'
