# Controls that can be fully satisfied by mapped policies or supporting documents alone.
# These are procedural, governance, review, MSP-managed, or report-backed controls
# where uploaded documentation can reasonably serve as the validating artifact.
DOCUMENTATION_SATISFIED_CONTROLS = {
    "AC-07",  # Periodic Access Reviews

    "AM-01",
    "AM-02",
    "AM-03",
    "AM-05",  # Cloud Resource Inventory

    "CM-02",  # Configuration Change Management
    "CM-04",  # System Hardening Standards

    "CP-01",
    "CP-02",
    "CP-03",  # Backup Management - MSP handled
    "CP-04",  # Backup Restoration Testing - MSP handled

    "IR-01",
    "IR-02",
    "IR-03",  # Incident Escalation and Reporting
    "IR-04",  # Incident Investigation and Forensics
    "IR-05",  # Incident Post-Mortem Review

    "NS-02",  # Firewall Configuration Management - MSP handled

    "RM-01",

    "SD-01",  # Secure Development Lifecycle
    "SD-02",  # Code Review Requirements

    "SI-04",  # Alert Management and Response

    "VM-02",  # Patch Management
    "VM-04",  # External Vulnerability Scanning / ASV
    "VM-05",  # Dependency and Software Vulnerability Monitoring
}

# Controls that must be validated by collector evidence.
# Policies/documents can support these, but they should not fully satisfy the control.
COLLECTOR_VALIDATED_CONTROLS = {
    "CP-05",  # System Availability Monitoring
    "SD-04",  # CI/CD Security Controls
    "SI-03",  # Security Event Monitoring
    "SI-05",  # Time Synchronization for Logs
}


def control_score(control_id, has_policy=False, has_document=False, has_validated_evidence=False):
    if has_validated_evidence:
        return 100, "validated"

    if control_id in DOCUMENTATION_SATISFIED_CONTROLS and (has_policy or has_document):
        return 100, "satisfied_by_documentation"

    if control_id in COLLECTOR_VALIDATED_CONTROLS and (has_policy or has_document):
        return 50, "documented"

    if has_policy or has_document:
        return 50, "documented"

    return 0, "missing"


def control_status_label(status):
    labels = {
        "validated": "Validated",
        "satisfied_by_documentation": "Satisfied by Documentation",
        "documented": "Documented / Needs Evidence",
        "missing": "Missing",
    }

    return labels.get(status, status)
