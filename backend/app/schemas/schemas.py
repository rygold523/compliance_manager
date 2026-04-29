from pydantic import BaseModel, Field
from typing import Any


class AssetCreate(BaseModel):
    asset_id: str
    hostname: str
    address: str
    environment: str
    role: list[str] = []
    os_family: str = "ubuntu"
    access_method: str = "ssh"
    ssh_user: str = "compliance-agent"
    ssh_port: int = 22
    approval_tier: str = "production"
    compliance_scope: list[str] = []
    allowed_actions: dict[str, Any] = {}
    blocked_actions: list[str] = []


class AgentDeployRequest(BaseModel):
    asset_id: str
    hostname: str
    address: str
    username: str
    password: str
    port: int = 22
    environment: str = "test"
    role: list[str] = ["ubuntu", "managed_target"]
    compliance_scope: list[str] = ["pci_dss", "soc2", "nist_800_53", "iso_27001", "iso_27002"]


class FindingImport(BaseModel):
    finding_id: str
    asset_id: str
    source: str
    title: str
    description: str | None = None
    severity: str
    cve: str | None = None
    finding_type: str
    raw: dict[str, Any] = {}


class ApprovalCreate(BaseModel):
    finding_id: str | None = None
    asset_id: str
    action_type: str
    proposed_action: str


class ApprovalDecision(BaseModel):
    decision: str = Field(pattern="^(approve|deny|review_in_depth)$")
    reason: str | None = None
    decided_by: str | None = None


class ChatRequest(BaseModel):
    message: str
    thread_id: str = "default"
    finding_id: str | None = None
    asset_id: str | None = None
    control_id: str | None = None


class RemoteCommandRequest(BaseModel):
    asset_id: str
    action_type: str
    command: str
    approval_id: str | None = None


class CollectorRunRequest(BaseModel):
    asset_id: str
    collectors: list[str] = [
        "user_changes", "auth_success", "auth_failure", "sudo_activity",
        "open_ports", "listening_services", "packages", "held_packages",
        "available_updates", "firewall_status", "ssh_config", "time_sync",
        "disk_usage", "docker_inventory",
    ]


class ScannerImportRequest(BaseModel):
    scanner: str
    asset_id: str | None = None
    raw: dict[str, Any]
