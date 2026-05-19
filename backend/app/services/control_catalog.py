from pathlib import Path
import yaml

CONTROLS_DIR = Path("/var/lib/ai-vulnerability-management/controls")

def load_yaml(path):
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return None

def normalize_control(data, path):
    if not isinstance(data, dict):
        return None

    return {
        "control_id": data.get("control_id") or path.stem,
        "title": data.get("title") or "",
        "domain": data.get("domain") or "",
        "description": data.get("description") or "",
        "framework_mappings": data.get("framework_mappings") or {},
        "source_file": str(path)
    }

def list_controls():
    controls = []

    if CONTROLS_DIR.exists():
        for path in CONTROLS_DIR.rglob("*.yml"):
            data = load_yaml(path)
            control = normalize_control(data, path)
            if control and control.get("control_id"):
                controls.append(control)

    # Deduplicate by control_id
    deduped = {}
    for c in controls:
        deduped[c["control_id"]] = c

    return sorted(deduped.values(), key=lambda x: x["control_id"])

def get_control(control_id):
    for c in list_controls():
        if c["control_id"] == control_id:
            return c
    return None

def framework_mappings_for_controls(control_ids):
    frameworks = {}

    for control_id in control_ids or []:
        control = get_control(control_id)
        if not control:
            continue

        mappings = dict(control.get("framework_mappings") or {})

        # ISO 27001 should be treated as its own framework for reporting,
        # while inheriting ISO 27002 control mappings when explicit ISO 27001
        # mappings are not present in the control catalog.
        if "iso_27001" not in mappings and "iso_27002" in mappings:
            mappings["iso_27001"] = mappings["iso_27002"]

        for framework, requirements in mappings.items():
            frameworks.setdefault(framework, [])

            if isinstance(requirements, list):
                frameworks[framework].extend(requirements)
            elif requirements:
                frameworks[framework].append(requirements)

    # Deduplicate while preserving order.
    for framework, requirements in frameworks.items():
        seen = set()
        deduped = []

        for requirement in requirements:
            if requirement in seen:
                continue

            seen.add(requirement)
            deduped.append(requirement)

        frameworks[framework] = deduped

    return frameworks

def suggest_controls(scope="", filename=""):
    text = f"{scope} {filename}".lower()

    controls = list_controls()
    suggestions = []

    for c in controls:
        hay = f"{c['control_id']} {c['title']} {c['description']}".lower()
        score = sum(1 for word in text.split() if word in hay)

        if score > 0:
            suggestions.append((score, c))

    suggestions.sort(key=lambda x: -x[0])
    return [c for _, c in suggestions[:20]]
