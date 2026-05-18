from typing import List, Optional
from pydantic import BaseModel


class EvidenceMetadata(BaseModel):
    environment: Optional[str] = None
    source_type: Optional[str] = None
    source_id: Optional[str] = None
    host_id: Optional[str] = None
    container_id: Optional[str] = None
    service_name: Optional[str] = None
    collector_name: Optional[str] = None
    evidence_scope: Optional[str] = None
    applies_to_controls: List[str] = []
    applies_to_frameworks: List[str] = []
    collected_at: Optional[str] = None
    freshness_requirement: Optional[str] = None
    coverage_basis: Optional[str] = None
    authoritative_source: bool = False
