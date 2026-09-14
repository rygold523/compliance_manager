from app.api import iam_db
from app.api import auth
from app.api import admin_users
from app.api import access_reviews
from app.api import assessments
from app.api import report_records
from app.api import role_dashboard
from app.api import iam
from app.api import role_collectors
from app.api import audit_readiness
from app.api import reports
from app.api import documents
from app.api import collector_mappings
from app.api import control_readiness
from app.api import controls
from app.api import windows_collectors
from app.api import remediations
from app.api import policies
from app.api import agent_lifecycle
from fastapi import FastAPI, HTTPException
from pathlib import Path
from sqlalchemy import text
from app.continuous_compliance.api.routes import router as continuous_compliance_router
from app.continuous_compliance.api.reporting_routes import router as continuous_compliance_reporting_router
from app.continuous_compliance.api.state_routes import router as continuous_compliance_state_router
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
from app.api.report_pdf import router as report_pdf_router
from app.api.control_readiness_v2 import router as control_readiness_v2_router
from app.api.collector_coverage import router as collector_coverage_router
from app.api.windows_agent import router as windows_agent_router
from app.api.asset_details import router as asset_details_router
from app.api.package_updates import router as package_updates_router
from app.api.changelog import router as changelog_router
from app.core.database import Base, SessionLocal, engine
from app.auth.middleware import AuthenticationMiddleware
from app.core.config import settings

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Compliance Manager", version="1.0.0")

cors_origins = [
    origin.strip().rstrip("/")
    for origin in settings.auth_cors_origins.split(",")
    if origin.strip()
]
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Content-Type"],
)
app.include_router(auth.router)
app.include_router(admin_users.router)
app.include_router(access_reviews.router)
app.include_router(assessments.router)
app.include_router(report_records.router)

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


@app.get("/api/live")
def liveness():
    return {"status": "alive"}


@app.get("/api/ready")
def readiness():
    checks = {"database": "unavailable", "evidence_storage": "unavailable"}
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        pass

    evidence_root = Path(settings.evidence_root)
    try:
        evidence_root.mkdir(parents=True, exist_ok=True)
        probe = evidence_root / ".readiness-probe"
        probe.touch(exist_ok=True)
        probe.unlink(missing_ok=True)
        checks["evidence_storage"] = "ok"
    except OSError:
        pass

    if any(value != "ok" for value in checks.values()):
        raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": checks})
    return {"status": "ready", "checks": checks}

app.include_router(policies.router)

app.include_router(remediations.router)

app.include_router(windows_collectors.router)

app.include_router(controls.router)

app.include_router(control_readiness.router)

app.include_router(collector_mappings.router)

app.include_router(documents.router)

app.include_router(reports.router)

app.include_router(audit_readiness.router)

# Additive continuous compliance routes
app.include_router(continuous_compliance_router)
app.include_router(continuous_compliance_reporting_router)
app.include_router(continuous_compliance_state_router)
app.include_router(report_pdf_router)
app.include_router(role_collectors.router)
app.include_router(role_dashboard.router)
app.include_router(control_readiness_v2_router)
app.include_router(collector_coverage_router)
app.include_router(windows_agent_router)
app.include_router(asset_details_router)
app.include_router(package_updates_router)
app.include_router(changelog_router)

# IAM router
try:
    app.include_router(iam.router)
except Exception:
    pass

app.include_router(agent_lifecycle.router)
app.include_router(iam_db.router, prefix="/api")
