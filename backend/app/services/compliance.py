FRAMEWORKS = ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]


def affected_frameworks_from_mappings(mappings: dict) -> list[str]:
    return [fw for fw in FRAMEWORKS if mappings.get(fw)]


def framework_label(framework: str) -> str:
    return {
        "pci_dss": "PCI DSS",
        "soc2": "SOC 2",
        "nist_800_53": "NIST 800-53",
        "iso_27001": "ISO 27001",
        "iso_27002": "ISO 27002",
    }.get(framework, framework)
