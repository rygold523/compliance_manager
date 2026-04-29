from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    asset_id = Column(String(128), unique=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    address = Column(String(255), nullable=False)
    environment = Column(String(64), nullable=False)
    role = Column(JSON, default=list)
    os_family = Column(String(64), default="ubuntu")
    access_method = Column(String(64), default="ssh")
    ssh_user = Column(String(128), default="compliance-agent")
    ssh_port = Column(Integer, default=22)
    approval_tier = Column(String(64), default="production")
    compliance_scope = Column(JSON, default=list)
    allowed_actions = Column(JSON, default=dict)
    blocked_actions = Column(JSON, default=list)
    agent_status = Column(String(64), default="not_deployed")
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    finding_id = Column(String(128), unique=True, index=True, nullable=False)
    asset_id = Column(String(128), index=True, nullable=False)
    source = Column(String(128), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(64), nullable=False)
    cve = Column(String(64), nullable=True)
    finding_type = Column(String(128), nullable=False)
    control_id = Column(String(64), nullable=True)
    status = Column(String(64), default="open")
    risk_score = Column(Integer, default=0)
    raw = Column(JSON, default=dict)
    framework_mappings = Column(JSON, default=dict)
    affected_frameworks = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Approval(Base):
    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True)
    approval_id = Column(String(128), unique=True, index=True, nullable=False)
    finding_id = Column(String(128), index=True, nullable=True)
    asset_id = Column(String(128), index=True, nullable=False)
    action_type = Column(String(128), nullable=False)
    proposed_action = Column(Text, nullable=False)
    status = Column(String(64), default="pending")
    review_depth = Column(JSON, default=dict)
    decision_reason = Column(Text, nullable=True)
    decided_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    decided_at = Column(DateTime(timezone=True), nullable=True)


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True)
    evidence_id = Column(String(128), unique=True, index=True, nullable=False)
    finding_id = Column(String(128), index=True, nullable=True)
    asset_id = Column(String(128), index=True, nullable=True)
    control_id = Column(String(64), index=True, nullable=True)
    framework = Column(String(64), nullable=True)
    filename = Column(String(512), nullable=False)
    file_path = Column(String(1024), nullable=False)
    source = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    collector = Column(String(128), nullable=True)
    evidence_type = Column(String(128), nullable=True)
    frameworks = Column(JSON, default=dict)
    validated = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class RemoteJob(Base):
    __tablename__ = "remote_jobs"

    id = Column(Integer, primary_key=True)
    job_id = Column(String(128), unique=True, index=True, nullable=False)
    asset_id = Column(String(128), index=True, nullable=False)
    action_type = Column(String(128), nullable=False)
    status = Column(String(64), default="queued")
    approval_id = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class RemoteJobLog(Base):
    __tablename__ = "remote_job_logs"

    id = Column(Integer, primary_key=True)
    job_id = Column(String(128), index=True, nullable=False)
    command = Column(Text, nullable=False)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True)
    thread_id = Column(String(128), index=True, nullable=False)
    role = Column(String(32), nullable=False)
    message = Column(Text, nullable=False)
    context = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AgentDeployment(Base):
    __tablename__ = "agent_deployments"

    id = Column(Integer, primary_key=True)
    deployment_id = Column(String(128), unique=True, index=True, nullable=False)
    asset_id = Column(String(128), index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    address = Column(String(255), nullable=False)
    username = Column(String(128), nullable=False)
    port = Column(Integer, default=22)
    status = Column(String(64), default="pending")
    output = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class CollectorRun(Base):
    __tablename__ = "collector_runs"

    id = Column(Integer, primary_key=True)
    run_id = Column(String(128), unique=True, index=True, nullable=False)
    asset_id = Column(String(128), index=True, nullable=False)
    collector = Column(String(128), nullable=False)
    status = Column(String(64), default="queued")
    output = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScannerResult(Base):
    __tablename__ = "scanner_results"

    id = Column(Integer, primary_key=True)
    scanner_result_id = Column(String(128), unique=True, index=True, nullable=False)
    scanner = Column(String(128), nullable=False)
    asset_id = Column(String(128), nullable=True)
    raw = Column(JSON, default=dict)
    imported_findings = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
