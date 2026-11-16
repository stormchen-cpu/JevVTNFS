from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Assessment(str, Enum):
    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    FIXED = "FIXED"
    UNKNOWN = "UNKNOWN"


class ProposedAction(str, Enum):
    PRIORITIZE_REMEDIATION = "PRIORITIZE_REMEDIATION"
    SCHEDULE_REMEDIATION = "SCHEDULE_REMEDIATION"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    SUPPRESS_UNTIL = "SUPPRESS_UNTIL"


class RunMode(str, Enum):
    SHADOW = "shadow"
    ACTIVE = "active"


class RunStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"


class ReviewStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"


class SuppressionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class VerificationStatus(str, Enum):
    RULE_VERIFIED = "RULE_VERIFIED"
    HUMAN_VERIFIED = "HUMAN_VERIFIED"
    UNVERIFIED = "UNVERIFIED"


class PackageRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    ecosystem: str
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    dependency_path: Optional[str] = None


class FindingObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    observation_id: str
    source: str
    source_finding_id: Optional[str] = None
    observed_at: datetime
    asset_id: Optional[str] = None
    deployment_id: Optional[str] = None
    package: PackageRef
    vulnerability_id: str
    raw_ref: str
    scanner_severity: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None


class DeploymentSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    snapshot_id: str
    asset_id: str
    deployment_id: str
    environment: str
    criticality: str = "standard"
    artifact_digest: Optional[str] = None
    components: List[Dict[str, Any]] = Field(default_factory=list)
    configuration: Dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime


class AdvisorySnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory_id: str
    revision: str = "1"
    source_uri: Optional[str] = None
    retrieved_at: datetime
    content_hash: str
    ecosystem: Optional[str] = None
    package_name: Optional[str] = None
    affected_ranges: List[Dict[str, Any]] = Field(default_factory=list)
    trigger_conditions: List[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: str
    kind: str
    value: Any  # boolean, string, or structured fact
    source_ref: str
    observed_at: datetime
    valid_until: Optional[datetime] = None
    verification_status: VerificationStatus = VerificationStatus.RULE_VERIFIED


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    bundle_id: str
    finding: FindingObservation
    deployment: Optional[DeploymentSnapshot] = None
    advisory: Optional[AdvisorySnapshot] = None
    evidence: List[EvidenceItem] = Field(default_factory=list)
    missing_fields: List[str] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)
    fingerprint: str


class Prediction(BaseModel):
    model_config = ConfigDict(frozen=True)

    suggested_assessment: Assessment
    probabilities: Optional[Dict[str, float]] = None
    reason_code: str
    evidence_ids: List[str] = Field(default_factory=list)
    backend_id: str
    model_revision: str
    input_hash: str
    status: str = "SUCCESS"  # SUCCESS, FAILED, TIMEOUT, BLOCKED


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision_id: str
    assessment: Assessment
    priority: str
    proposed_action: ProposedAction
    reason_codes: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    policy_version: str
    expires_at: Optional[datetime] = None


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    audit_id: str
    decision_id: str
    reviewer_id: str
    reviewed_at: datetime
    assessment: Assessment
    reason: str
    evidence_ids: List[str] = Field(default_factory=list)
    supersedes_id: Optional[str] = None


class RiskAcceptance(BaseModel):
    model_config = ConfigDict(frozen=True)

    acceptance_id: str
    issue_key: str
    scope: str
    approved_by: str
    reason: str
    expires_at: datetime
    created_at: datetime


class DecisionInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    input_hash: str
    finding_summary: Dict[str, Any]
    advisory_summary: Dict[str, Any]
    evidence_summary: List[Dict[str, Any]]
    allowed_facts: Dict[str, Any]
