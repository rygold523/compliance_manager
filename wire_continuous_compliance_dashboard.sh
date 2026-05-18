#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/ai-vulnerability-management"
MAIN_FILE="$REPO_DIR/frontend/src/main.jsx"

cd "$REPO_DIR"

if [ ! -f "$MAIN_FILE" ]; then
  echo "ERROR: $MAIN_FILE not found"
  exit 1
fi

BACKUP="${MAIN_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
cp "$MAIN_FILE" "$BACKUP"

echo "[+] Backup created: $BACKUP"

python3 <<'PY'
from pathlib import Path

path = Path("/opt/ai-vulnerability-management/frontend/src/main.jsx")
content = path.read_text()

if "Continuous Compliance Operations" in content:
    print("[+] Continuous Compliance dashboard section already appears to be wired.")
    raise SystemExit(0)

component = r'''

function ContinuousComplianceOperationsSection() {
  const domains = [
    {
      title: "Regulatory Monitoring",
      description: "Tracks FCC, TCPA, CTIA, CASL, A2P, and vendor compliance source changes."
    },
    {
      title: "Messaging Compliance",
      description: "Monitors suppression, opt-out handling, consent validation, and quiet-hour protections."
    },
    {
      title: "Compliance Drift",
      description: "Identifies stale evidence, failed collectors, expired reviews, and baseline drift."
    },
    {
      title: "Evidence Freshness",
      description: "Evaluates whether required evidence remains current and defensible."
    },
    {
      title: "Incident Monitoring",
      description: "Tracks suppression failures, rejection spikes, opt-out violations, and delivery failures."
    },
    {
      title: "Vendor / Control Plane Validation",
      description: "Validates Twilio and other authoritative control-plane evidence sources."
    }
  ];

  return (
    <section className="dashboard-section continuous-compliance-section">
      <div className="section-header">
        <h2>Continuous Compliance Operations</h2>
        <p>
          Operational compliance monitoring for regulatory changes, messaging controls,
          evidence freshness, compliance drift, incidents, and vendor control-plane validation.
        </p>
      </div>

      <div className="continuous-compliance-grid">
        {domains.map((domain) => (
          <div className="continuous-compliance-card" key={domain.title}>
            <h3>{domain.title}</h3>
            <p>{domain.description}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
'''

content = component + "\n" + content

inserted = False

markers = [
    "</main>",
    "</div>\n  );",
    "</div>\r\n  );",
]

for marker in markers:
    if marker in content:
        content = content.replace(marker, "      <ContinuousComplianceOperationsSection />\n      " + marker, 1)
        inserted = True
        break

if not inserted:
    raise SystemExit("ERROR: Could not safely locate insertion point in main.jsx")

path.write_text(content)
print("[+] Continuous Compliance dashboard section wired into main.jsx")
PY

cat >> "$REPO_DIR/frontend/src/style.css" <<'CSS'

/* Continuous Compliance Operations */
.continuous-compliance-section {
  margin-top: 24px;
}

.continuous-compliance-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
  margin-top: 16px;
}

.continuous-compliance-card {
  border: 1px solid #d8dee4;
  border-radius: 12px;
  padding: 16px;
  background: #ffffff;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.continuous-compliance-card h3 {
  margin: 0 0 8px 0;
  font-size: 16px;
}

.continuous-compliance-card p {
  margin: 0;
  color: #57606a;
  font-size: 14px;
  line-height: 1.4;
}
CSS

echo "[+] Frontend dashboard wiring complete."
