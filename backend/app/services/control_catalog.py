from pathlib import Path
import re

CONTROLS_DIR = Path("/var/lib/ai-vulnerability-management/controls")

DEFAULT_CONTROLS = [
    {
        "control_id": "AC-01",
        "title": "MFA Enforcement",
        "domain": "Access Control",
        "description": "Multi-factor authentication is enforced for in-scope systems.",
        "framework_mappings": {
            "pci_dss": ["8.4"],
            "soc2": ["CC6.1"],
            "nist_800_53": ["IA-2"],
            "iso_27002": ["5.17"],
        },
    },
    {
        "control_id": "AC-02",
        "title": "Centralized Identity and Access Management",
        "domain": "Access Control",
        "description": "User access, authentication, account lifecycle, and privileged access are managed.",
        "framework_mappings": {
            "pci_dss": ["8.2", "8.3"],
            "soc2": ["CC6.2"],
            "nist_800_53": ["AC-2"],
            "iso_27002": ["5.18"],
        },
    },
    {
        "control_id": "AM-01",
        "title": "Asset Inventory",
        "domain": "Asset Management",
        "description": "Assets are inventoried, classified, and tracked.",
        "framework_mappings": {
            "pci_dss": ["12.5"],
            "soc2": ["CC6.1"],
            "nist_800_53": ["CM-8"],
            "iso_27002": ["5.9"],
        },
    },
    {
        "control_id": "CM-01",
        "title": "Baseline Configuration Management",
        "domain": "Configuration Management",
        "description": "Systems are configured against approved baselines and change-controlled.",
        "framework_mappings": {
            "pci_dss": ["2.2"],
            "soc2": ["CC8.1"],
            "nist_800_53": ["CM-2"],
            "iso_27002": ["8.9"],
        },
    },
    {
        "control_id": "CP-01",
        "title": "Backup and Recovery",
        "domain": "Business Continuity",
        "description": "Backups and recovery processes are implemented and tested.",
        "framework_mappings": {
            "pci_dss": ["12.10"],
            "soc2": ["A1.2"],
            "nist_800_53": ["CP-9"],
            "iso_27002": ["5.30"],
        },
    },
    {
        "control_id": "IR-01",
        "title": "Incident Response",
        "domain": "Incident Response",
        "description": "Security incidents are detected, escalated, responded to, and documented.",
        "framework_mappings": {
            "pci_dss": ["12.10"],
            "soc2": ["CC7.4"],
            "nist_800_53": ["IR-4"],
            "iso_27002": ["5.24"],
        },
    },
    {
        "control_id": "SI-01",
        "title": "Centralized Logging and Monitoring",
        "domain": "Security Monitoring",
        "description": "Security logs are collected, monitored, and reviewed.",
        "framework_mappings": {
            "pci_dss": ["10.2"],
            "soc2": ["CC7.2"],
            "nist_800_53": ["AU-6"],
            "iso_27002": ["8.16"],
        },
    },
    {
        "control_id": "VM-01",
        "title": "Vulnerability Management",
        "domain": "Vulnerability Management",
        "description": "Vulnerabilities, patches, scans, and remediation are managed.",
        "framework_mappings": {
            "pci_dss": ["6.3"],
            "soc2": ["CC7.1"],
            "nist_800_53": ["RA-5"],
            "iso_27002": ["8.8"],
        },
    },
    {
        "control_id": "NS-01",
        "title": "Network Security and Segmentation",
        "domain": "Network Security",
        "description": "Firewalls, ports, services, VPN, and segmentation are controlled.",
        "framework_mappings": {
            "pci_dss": ["1.2"],
            "soc2": ["CC6.6"],
            "nist_800_53": ["SC-7"],
            "iso_27002": ["8.20"],
        },
    },
    {
        "control_id": "EN-01",
        "title": "Encryption and Certificate Management",
        "domain": "Encryption",
        "description": "Encryption, TLS, certificates, and cryptographic protections are managed.",
        "framework_mappings": {
            "pci_dss": ["3.5", "4.2"],
            "soc2": ["CC6.7"],
            "nist_800_53": ["SC-13"],
            "iso_27002": ["8.24"],
        },
    },
    {
        "control_id": "SD-01",
        "title": "Secure Development",
        "domain": "Secure Development",
        "description": "Secure development, code review, deployment, and CI/CD controls are implemented.",
        "framework_mappings": {
            "pci_dss": ["6.2"],
            "soc2": ["CC8.1"],
            "nist_800_53": ["SA-11"],
            "iso_27002": ["8.25"],
        },
    },
]


def _clean(value):
    value = str(value or "").strip()
    value = value.strip("\"'")
    return value


def _extract_scalar(text, key):
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", text)
    return _clean(match.group(1)) if match else ""


def _extract_framework_mappings(text):
    mappings = {}
    marker = re.search(r"(?m)^\s*framework_mappings\s*:\s*$", text)
    if not marker:
        return mappings

    block = text[marker.end():]
    current_framework = None

    for line in block.splitlines():
        if not line.strip():
            continue

        if re.match(r"^\S", line):
            break

        framework_match = re.match(r"^\s{2,}([A-Za-z0-9_.-]+)\s*:\s*(.*)$", line)
        if framework_match:
            current_framework = framework_match.group(1)
            remainder = framework_match.group(2).strip()
            mappings.setdefault(current_framework, [])

            inline_refs = re.findall(r"['\"]?([A-Za-z0-9_.-]+(?:\s+[A-Za-z0-9_.-]+)?)['\"]?", remainder)
            for ref in inline_refs:
                ref = ref.strip()
                if ref and ref not in ["[]"] and ref not in mappings[current_framework]:
                    mappings[current_framework].append(ref)
            continue

        item_match = re.match(r"^\s*-\s*['\"]?(.+?)['\"]?\s*$", line)
        if item_match and current_framework:
            ref = item_match.group(1).strip()
            if ref and ref not in mappings[current_framework]:
                mappings[current_framework].append(ref)

    return {k: v for k, v in mappings.items() if v}


def _control_from_yaml(path):
    text = path.read_text(errors="ignore")

    control_id = _extract_scalar(text, "control_id") or path.stem
    title = _extract_scalar(text, "title") or control_id
    domain = _extract_scalar(text, "domain") or ""
    description = _extract_scalar(text, "description") or ""

    return {
        "control_id": control_id,
        "title": title,
        "domain": domain,
        "description": description,
        "framework_mappings": _extract_framework_mappings(text),
        "source_file": str(path),
    }


def list_controls():
    controls = []

    if CONTROLS_DIR.exists():
        for path in sorted(list(CONTROLS_DIR.rglob("*.yml")) + list(CONTROLS_DIR.rglob("*.yaml"))):
            try:
                control = _control_from_yaml(path)
                if control.get("control_id"):
                    controls.append(control)
            except Exception:
                continue

    if not controls:
        controls = DEFAULT_CONTROLS

    deduped = {}
    for control in controls:
        deduped[control["control_id"]] = control

    return [deduped[k] for k in sorted(deduped)]


def get_control(control_id):
    for control in list_controls():
        if control["control_id"] == control_id:
            return control
    return None


def framework_mappings_for_controls(control_ids):
    selected = set(control_ids or [])
    frameworks = {}

    for control in list_controls():
        if control["control_id"] not in selected:
            continue

        for framework, refs in (control.get("framework_mappings") or {}).items():
            frameworks.setdefault(framework, [])
            for ref in refs:
                if ref not in frameworks[framework]:
                    frameworks[framework].append(ref)

    return frameworks


def suggest_controls(scope="", filename=""):
    text = f"{scope or ''} {filename or ''}".lower()
    controls = list_controls()

    keyword_map = {
        "AC": ["access", "identity", "authentication", "mfa", "password", "user", "privilege", "account", "login", "ssh"],
        "AM": ["asset", "inventory", "classification", "ownership"],
        "CM": ["configuration", "baseline", "hardening", "change", "standard", "build"],
        "CP": ["backup", "recovery", "continuity", "disaster", "restore"],
        "IR": ["incident", "response", "escalation", "breach", "event"],
        "SI": ["logging", "monitoring", "siem", "alert", "audit", "detection"],
        "VM": ["vulnerability", "patch", "scan", "cve", "remediation", "updates"],
        "NS": ["network", "firewall", "port", "segmentation", "vpn", "traffic"],
        "EN": ["encryption", "tls", "ssl", "certificate", "cryptographic", "key"],
        "SD": ["secure development", "sdlc", "code", "review", "deployment", "ci/cd"],
    }

    scored = []

    for control in controls:
        cid = control.get("control_id", "")
        prefix = cid.split("-")[0] if "-" in cid else cid
        haystack = " ".join([
            control.get("control_id", ""),
            control.get("title", ""),
            control.get("domain", ""),
            control.get("description", ""),
        ]).lower()

        score = 0

        for word in keyword_map.get(prefix, []):
            if word in text:
                score += 3
            if word in haystack and word in text:
                score += 2

        for token in re.findall(r"[a-z0-9]+", text):
            if len(token) >= 4 and token in haystack:
                score += 1

        if score > 0:
            scored.append((score, control))

    scored.sort(key=lambda item: (-item[0], item[1].get("control_id", "")))

    suggestions = [control for _, control in scored[:20]]

    if not suggestions:
        fallback_ids = {"AC-02", "CM-01", "SI-01", "VM-01"}
        suggestions = [c for c in controls if c.get("control_id") in fallback_ids]

    return suggestions
