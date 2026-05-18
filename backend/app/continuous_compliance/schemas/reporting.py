from pydantic import BaseModel
from typing import List, Optional


class ComplianceDomainSummary(BaseModel):
    domain: str
    total_controls: int
    satisfied_controls: int
    deficient_controls: int
    stale_controls: int
    open_findings: int
    readiness_score: float


class ComplianceControlStatus(BaseModel):
    control_id: str
    title: str
    domain: str
    status: str
    evidence_coverage: Optional[float] = None
    freshness_status: Optional[str] = None
    open_findings: int = 0
    mapped_frameworks: List[str] = []
