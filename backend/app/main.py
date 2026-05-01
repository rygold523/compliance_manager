from app.api import audit_readiness
from app.api import reports
from app.api import documents
from app.api import collector_mappings
from app.api import control_readiness
from app.api import controls
from app.api import windows_collectors
from app.api import remediations
from app.api import policies
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.assets import router as assets_router
from app.api.findings import router as findings_router
from app.api.approvals import router as approvals_router
from app.api.evidence import router as evidence_router
from app.api.evidence_analysis import router as evidence_analysis_router
from app.api.chat import router as chat_router
from app.api.remote_exec import router as remote_exec_router
from app.api.ai_analysis import router as ai_analysis_router
from app.api.agents import router as agents_router
from app.api.collectors import router as collectors_router
from app.api.compliance import router as compliance_router
from app.api.reports import router as reports_router
from app.api.scanners import router as scanners_router
from app.core.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Compliance Manager", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

app.include_router(assets_router, prefix="/api/assets", tags=["Assets"])
app.include_router(findings_router, prefix="/api/findings", tags=["Findings"])
app.include_router(approvals_router, prefix="/api/approvals", tags=["Approvals"])
app.include_router(evidence_router, prefix="/api/evidence", tags=["Evidence"])
app.include_router(evidence_analysis_router, prefix="/api/evidence-analysis", tags=["Evidence Analysis"])
app.include_router(chat_router, prefix="/api/chat", tags=["Chat"])
app.include_router(remote_exec_router, prefix="/api/remote-exec", tags=["Remote Execution"])
app.include_router(ai_analysis_router, prefix="/api/ai", tags=["AI Analysis"])
app.include_router(agents_router, prefix="/api/agents", tags=["Agents"])
app.include_router(collectors_router, prefix="/api/collectors", tags=["Collectors"])
app.include_router(compliance_router, prefix="/api/compliance", tags=["Compliance"])
app.include_router(reports_router, prefix="/api/reports", tags=["Reports"])
app.include_router(scanners_router, prefix="/api/scanners", tags=["Scanners"])

@app.get("/api/health")
def health():
    return {"status": "ok"}

app.include_router(policies.router)

app.include_router(remediations.router)

app.include_router(windows_collectors.router)

app.include_router(controls.router)

app.include_router(control_readiness.router)

app.include_router(collector_mappings.router)

app.include_router(documents.router)

app.include_router(reports.router)

app.include_router(audit_readiness.router)
