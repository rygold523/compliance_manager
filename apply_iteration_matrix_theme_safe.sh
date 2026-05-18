#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
cd "$REPO_DIR"

echo "[+] Applying Iteration Matrix dashboard theme safely..."

mkdir -p frontend/public/brand

if [ -f /mnt/data/full-logo-animation-01.gif ]; then
  cp /mnt/data/full-logo-animation-01.gif frontend/public/brand/full-logo-animation-01.gif
else
  echo "[!] Warning: /mnt/data/full-logo-animation-01.gif not found"
fi

if [ -f /mnt/data/5e32c5ec-da82-40c4-99ee-fada7f2e9d26.png ]; then
  cp /mnt/data/5e32c5ec-da82-40c4-99ee-fada7f2e9d26.png frontend/public/brand/iteration-matrix-banner.png
else
  echo "[!] Warning: /mnt/data/5e32c5ec-da82-40c4-99ee-fada7f2e9d26.png not found"
fi

cp frontend/src/main.jsx "frontend/src/main.jsx.bak.theme.$(date +%Y%m%d_%H%M%S)"
cp frontend/src/style.css "frontend/src/style.css.bak.theme.$(date +%Y%m%d_%H%M%S)"

python3 <<'PY'
from pathlib import Path
import re

path = Path("frontend/src/main.jsx")
content = path.read_text()

if 'className="im-hero"' in content:
    print("[+] Header already themed.")
    raise SystemExit(0)

match = re.search(r"<header>(.*?)</header>", content, re.DOTALL)

if not match:
    raise SystemExit("ERROR: Could not locate <header>...</header> block.")

header_body = match.group(1)

actions_match = re.search(r'(<div className="actions">.*?</div>)', header_body, re.DOTALL)
actions_block = actions_match.group(1) if actions_match else ""

new_header = f'''<header className="im-hero">
          <div className="im-brand-row">
            <img
              src="/brand/full-logo-animation-01.gif"
              alt="Iteration Matrix"
              className="im-logo-gif"
            />
            <div>
              <h1>Compliance Manager</h1>
              <p>Central control plane for agents, evidence, findings, compliance scoring, and reporting.</p>
            </div>
          </div>
          <div className="im-grid-accent"></div>
          {actions_block}
        </header>'''

content = content[:match.start()] + new_header + content[match.end():]

path.write_text(content)

print("[+] Header safely updated.")
PY

cat >> frontend/src/style.css <<'CSS'

/* Iteration Matrix Theme */
:root {
  --im-black: #050505;
  --im-white: #ffffff;
  --im-bg: #f7f7fb;
  --im-card: #ffffff;
  --im-border: #d8dbe3;
  --im-muted: #5f6673;
  --im-magenta: #d000ff;
  --im-magenta-dark: #9b00d9;
  --im-text: #050505;
}

body {
  background:
    radial-gradient(circle at top left, rgba(208, 0, 255, 0.11), transparent 28rem),
    linear-gradient(180deg, #ffffff 0%, var(--im-bg) 100%);
  color: var(--im-text);
}

main {
  max-width: 100%;
}

.im-hero {
  position: relative;
  overflow: hidden;
  border: 1px solid var(--im-border);
  border-radius: 18px;
  padding: 24px;
  margin-bottom: 20px;
  background: linear-gradient(135deg, #ffffff 0%, #ffffff 58%, rgba(208, 0, 255, 0.08) 100%);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.06);
}

.im-brand-row {
  display: flex;
  align-items: center;
  gap: 22px;
  position: relative;
  z-index: 2;
}

.im-logo-gif {
  width: 170px;
  max-width: 28vw;
  height: auto;
  object-fit: contain;
}

.im-hero h1 {
  font-size: 34px;
  letter-spacing: -0.03em;
  margin: 0;
  color: var(--im-black);
}

.im-hero p {
  color: var(--im-muted);
  margin-top: 8px;
}

.im-grid-accent {
  height: 42px;
  margin-top: 18px;
  background:
    linear-gradient(var(--im-magenta) 1px, transparent 1px),
    linear-gradient(90deg, var(--im-magenta) 1px, transparent 1px);
  background-size: 28px 12px;
  transform: perspective(140px) rotateX(42deg);
  transform-origin: top;
  opacity: 0.85;
}

.actions {
  margin-top: 18px;
}

button,
.actions button,
input[type="submit"] {
  background: var(--im-black);
  color: var(--im-white);
  border: 1px solid var(--im-black);
  border-radius: 10px;
  padding: 9px 14px;
  font-weight: 700;
}

button:hover,
.actions button:hover,
input[type="submit"]:hover {
  background: var(--im-magenta);
  border-color: var(--im-magenta);
}

select,
input,
textarea {
  border: 1px solid var(--im-border);
  border-radius: 10px;
}

section,
.card,
.dashboard-section,
.cc-state-card,
.continuous-compliance-card {
  border-radius: 16px !important;
  border: 1px solid var(--im-border) !important;
  background: var(--im-card) !important;
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.045);
}

h1,
h2,
h3 {
  color: var(--im-black);
}

a {
  color: var(--im-magenta-dark);
  font-weight: 600;
}

a:hover {
  color: var(--im-magenta);
}

table {
  border-radius: 12px;
  overflow: hidden;
}

th {
  background: #f1f1f6 !important;
  color: var(--im-black);
}

td,
th {
  border-color: var(--im-border) !important;
}

.cc-status-current,
.validated {
  border: 1px solid rgba(17, 99, 41, 0.2);
}

.cc-status-action,
.documented {
  border: 1px solid rgba(125, 78, 0, 0.2);
}

.cc-status-stale,
.missing {
  border: 1px solid rgba(130, 7, 30, 0.2);
}

@media (max-width: 760px) {
  .im-brand-row {
    align-items: flex-start;
    flex-direction: column;
  }

  .im-logo-gif {
    width: 140px;
    max-width: 80vw;
  }

  .im-hero h1 {
    font-size: 28px;
  }
}
CSS

echo "[+] Iteration Matrix theme safely applied."
