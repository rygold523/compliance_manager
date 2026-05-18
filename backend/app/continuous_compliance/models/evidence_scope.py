from enum import Enum


class EvidenceScope(str, Enum):
    HOST = "host"
    CONTAINER = "container"
    SERVICE = "service"
    APPLICATION = "application"
    ENVIRONMENT = "environment"
    CONTROL_PLANE = "control_plane"
    GOVERNANCE = "governance"
    REGULATORY = "regulatory"
    VENDOR = "vendor"
    REPRESENTATIVE_SAMPLE = "representative_sample"


class CoverageBasis(str, Enum):
    PER_HOST = "per_host"
    PER_CONTAINER = "per_container"
    PER_ENVIRONMENT = "per_environment"
    AUTHORITATIVE_SOURCE = "authoritative_source"
    CENTRAL_CONTROL_PLANE = "central_control_plane"
    CENTRAL_APPLICATION_LOG = "central_application_log"
    GOVERNANCE_RECORD = "governance_record"
    REPRESENTATIVE_SAMPLE = "representative_sample"
