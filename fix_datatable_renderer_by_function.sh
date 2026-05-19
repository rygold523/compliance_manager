#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

cp "$MAIN_FILE" "${MAIN_FILE}.bak.datatable_function.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

start = content.find("function DataTable({ columns, rows })")
if start == -1:
    raise SystemExit("ERROR: DataTable function not found.")

next_fn = content.find("\nfunction ", start + 1)
if next_fn == -1:
    raise SystemExit("ERROR: Could not locate end of DataTable function.")

block = content[start:next_fn]

print("[+] Current DataTable block:")
print(block)

replacements = [
    ("{col.render ? col.render(row) : row[col.key]}", "{col.render ? col.render(row) : renderCurrentStateValue(row[col.key])}"),
    ("{col.render ? col.render(row) : (row[col.key] || '')}", "{col.render ? col.render(row) : renderCurrentStateValue(row[col.key])}"),
    ("{col.render ? col.render(row) : row[col.key] || ''}", "{col.render ? col.render(row) : renderCurrentStateValue(row[col.key])}"),
    ("{col.render ? col.render(row) : String(row[col.key] || '')}", "{col.render ? col.render(row) : renderCurrentStateValue(row[col.key])}"),
]

new_block = block
changed = False

for old, new in replacements:
    if old in new_block:
        new_block = new_block.replace(old, new)
        changed = True

if not changed:
    print("[!] Known pattern not found. Replacing full DataTable function.")
    new_block = '''function DataTable({ columns, rows }) {
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
}
'''

content = content[:start] + new_block + content[next_fn:]
path.write_text(content)

print("[+] DataTable renderer patched.")
PY

echo "[+] New DataTable location:"
grep -n "function DataTable" frontend/src/main.jsx
