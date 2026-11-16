from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional
import uuid

from vuln_triage.config import PolicyConfig
from vuln_triage.domain.identity import compute_sha256
from vuln_triage.domain.models import (
    Assessment,
    EvidenceBundle,
    PolicyDecision,
    Prediction,
    ProposedAction,
    RunMode,
)


def calculate_priority(
    criticality: str,
    environment: str,
    scanner_severity: Optional[str],
    policy: PolicyConfig,
) -> str:
    """
    Calculates priority P1 ~ P4 based on asset criticality, environment, and scanner severity.
    """
    crit = "high_criticality" if criticality.lower() == "high" else "standard_criticality"
    env = "production" if "prod" in environment.lower() else "non_production"
    sev = (scanner_severity or "MEDIUM").upper()

    matrix_by_crit = getattr(policy.priority_matrix, crit, {})
    if not matrix_by_crit and hasattr(policy.priority_matrix, "model_dump"):
        matrix_by_crit = policy.priority_matrix.model_dump().get(crit, {})

    matrix_by_env = matrix_by_crit.get(env, {})
    return matrix_by_env.get(sev, "P3")


def evaluate_policy(
    evidence: EvidenceBundle,
    prediction: Optional[Prediction],
    policy: PolicyConfig,
    mode: RunMode = RunMode.SHADOW,
    now: Optional[datetime] = None,
) -> PolicyDecision:
    now_dt = now or datetime.now(timezone.utc)
    reason_codes: List[str] = []
    evidence_ids: List[str] = []

    environment = (
        evidence.deployment.environment if evidence.deployment else "unknown"
    )
    criticality = (
        evidence.deployment.criticality if evidence.deployment else "standard"
    )
    scanner_severity = evidence.finding.scanner_severity

    priority = calculate_priority(criticality, environment, scanner_severity, policy)

    # 1. Missing fields check
    if evidence.missing_fields:
        return PolicyDecision(
            decision_id=f"dec-{uuid.uuid4().hex[:12]}",
            assessment=Assessment.UNKNOWN,
            priority=priority,
            proposed_action=ProposedAction.HUMAN_REVIEW,
            reason_codes=[f"MISSING_FIELDS:{','.join(evidence.missing_fields)}"],
            evidence_ids=[e.evidence_id for e in evidence.evidence],
            policy_version=policy.version,
            expires_at=None,
        )

    # 2. Conflicts check
    if evidence.conflicts:
        return PolicyDecision(
            decision_id=f"dec-{uuid.uuid4().hex[:12]}",
            assessment=Assessment.UNKNOWN,
            priority=priority,
            proposed_action=ProposedAction.HUMAN_REVIEW,
            reason_codes=[f"CONFLICTS_DETECTED:{','.join(evidence.conflicts)}"],
            evidence_ids=[e.evidence_id for e in evidence.evidence],
            policy_version=policy.version,
            expires_at=None,
        )

    # 3. Model failure / timeout / blocked egress check
    if prediction is not None and prediction.status != "SUCCESS":
        return PolicyDecision(
            decision_id=f"dec-{uuid.uuid4().hex[:12]}",
            assessment=Assessment.UNKNOWN,
            priority=priority,
            proposed_action=ProposedAction.HUMAN_REVIEW,
            reason_codes=[f"PREDICTION_ABORTED_{prediction.status}:{prediction.reason_code}"],
            evidence_ids=[e.evidence_id for e in evidence.evidence],
            policy_version=policy.version,
            expires_at=None,
        )

    # 4. Check version evidence
    has_version_affected = any(
        e.kind == "version_in_affected_range" and e.value is True
        for e in evidence.evidence
    )
    has_version_unaffected = any(
        e.kind == "version_outside_affected_range" and e.value is True
        for e in evidence.evidence
    )

    # 5. Prohibited exclusion check
    has_prohibited_claim = any(
        e.kind == "prohibited_exclusion_warning" for e in evidence.evidence
    )

    # Collect cited evidence
    if prediction and prediction.evidence_ids:
        evidence_ids = prediction.evidence_ids
    else:
        evidence_ids = [e.evidence_id for e in evidence.evidence]

    # Evaluate Assessment
    has_trigger_conditions = bool(evidence.advisory and evidence.advisory.trigger_conditions)

    if has_version_affected:
        # If the advisory has specific conditional triggers, check if the Decision Model
        # verified that the trigger condition is NOT met in this deployment.
        if (
            has_trigger_conditions
            and prediction
            and prediction.suggested_assessment == Assessment.NOT_AFFECTED
            and not has_prohibited_claim
        ):
            # Check model confidence
            pred_conf = prediction.confidence
            if pred_conf is None and prediction.probabilities:
                pred_conf = max(prediction.probabilities.values())

            if pred_conf is not None and pred_conf < policy.decision_confidence_threshold:
                assessment = Assessment.UNKNOWN
                reason_codes.append(f"LOW_MODEL_CONFIDENCE:{pred_conf:.2f}<{policy.decision_confidence_threshold:.2f}")
                proposed_action = ProposedAction.HUMAN_REVIEW
                expires_at = None
            else:
                # Decision Model verified conditional trigger is unmet with valid evidence!
                assessment = Assessment.NOT_AFFECTED
                reason_codes.append(f"DECISION_MODEL_TRIGGER_UNMET:{prediction.reason_code}")
                proposed_action = ProposedAction.SUPPRESS_UNTIL
                expires_at = now_dt + timedelta(days=policy.default_suppression_days)
        else:
            # Crucial requirement from SYSTEM_DESIGN.md Section 9:
            # Confirmed affected: prioritize according to policy; never convert to false positive due to intranet/WAF.
            assessment = Assessment.AFFECTED
            reason_codes.append("RULE_VERIFIED_AFFECTED_VERSION")
            if priority == "P1":
                proposed_action = ProposedAction.PRIORITIZE_REMEDIATION
            else:
                proposed_action = ProposedAction.SCHEDULE_REMEDIATION
            expires_at = None

    elif has_version_unaffected:
        # Version is verified outside affected range: valid technical exclusion
        assessment = Assessment.NOT_AFFECTED
        reason_codes.append("RULE_VERIFIED_UNAFFECTED_VERSION")
        proposed_action = ProposedAction.SUPPRESS_UNTIL
        expires_at = now_dt + timedelta(days=policy.default_suppression_days)

    else:
        # Version was not verified outside affected range.
        # Check prediction confidence if prediction exists
        pred_conf = prediction.confidence if prediction else None
        if pred_conf is None and prediction and prediction.probabilities:
            pred_conf = max(prediction.probabilities.values())

        if prediction and pred_conf is not None and pred_conf < policy.decision_confidence_threshold:
            assessment = Assessment.UNKNOWN
            reason_codes.append(f"LOW_MODEL_CONFIDENCE:{pred_conf:.2f}<{policy.decision_confidence_threshold:.2f}")
            proposed_action = ProposedAction.HUMAN_REVIEW
            expires_at = None
        elif prediction and prediction.suggested_assessment == Assessment.NOT_AFFECTED:
            if has_prohibited_claim:
                assessment = Assessment.UNKNOWN
                reason_codes.append("PROHIBITED_EXCLUSION: WAF or intranet alone cannot justify NOT_AFFECTED without version proof")
                proposed_action = ProposedAction.HUMAN_REVIEW
                expires_at = None
            else:
                assessment = Assessment.NOT_AFFECTED
                reason_codes.append(f"MODEL_SUGGESTED_UNAFFECTED:{prediction.reason_code}")
                proposed_action = ProposedAction.SUPPRESS_UNTIL
                expires_at = now_dt + timedelta(days=policy.default_suppression_days)
        elif prediction and prediction.suggested_assessment == Assessment.AFFECTED:
            assessment = Assessment.AFFECTED
            reason_codes.append(f"MODEL_SUGGESTED_AFFECTED:{prediction.reason_code}")
            proposed_action = (
                ProposedAction.PRIORITIZE_REMEDIATION
                if priority == "P1"
                else ProposedAction.SCHEDULE_REMEDIATION
            )
            expires_at = None
        else:
            assessment = Assessment.UNKNOWN
            reason_codes.append("INSUFFICIENT_EVIDENCE")
            proposed_action = ProposedAction.HUMAN_REVIEW
            expires_at = None


    return PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:12]}",
        assessment=assessment,
        priority=priority,
        proposed_action=proposed_action,
        reason_codes=reason_codes,
        evidence_ids=evidence_ids,
        policy_version=policy.version,
        expires_at=expires_at,
    )
