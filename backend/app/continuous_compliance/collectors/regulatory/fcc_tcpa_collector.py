from app.continuous_compliance.collectors.regulatory.base import RegulatoryCollector


class FCCTCPACollector(RegulatoryCollector):
    source_name = "fcc_tcpa"
    document_type = "regulatory_guidance"

    def fetch(self) -> str:
        # Placeholder.
        # Add authoritative FCC/TCPA retrieval logic here.
        # Keep this isolated from existing collectors.
        return "FCC/TCPA collector placeholder. Configure authoritative source retrieval."
