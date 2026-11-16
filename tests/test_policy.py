from __future__ import annotations

from vuln_triage.config import PolicyConfig
from vuln_triage.domain.models import (
    Assessment,
    EvidenceBundle,
    FindingObservation,
    PolicyDecision,
    Prediction,
    ProposedAction,
    RunMode,
)
from vuln_triage.evidence.assembler import assemble_evidence
from vuln_triage.policy.engine import calculate_priority, evaluate_policy


def test_priority_calculation():
    policy = PolicyConfig()
    p1 = calculate_priority("high", "production", "CRITICAL", policy)
    assert p1 == "P1"

    p_low = calculate_priority("standard", "non_production", "LOW", policy)
    assert p_low == "P4"


def test_policy_missing_fields_routes_to_human_review(sample_finding: FindingObservation):
    policy = PolicyConfig()
    # No deployment or advisory -> missing fields
    bundle = assemble_evidence(finding=sample_finding, deployment=None, advisory=None)

    decision = evaluate_policy(evidence=bundle, prediction=None, policy=policy)
    assert decision.assessment == Assessment.UNKNOWN
    assert decision.proposed_action == ProposedAction.HUMAN_REVIEW
    assert any("MISSING_FIELDS" in r for r in decision.reason_codes)


def test_policy_affected_version_produces_prioritization(
    sample_finding: FindingObservation,
    sample_deployment,
    sample_advisory,
):
    policy = PolicyConfig()
    bundle = assemble_evidence(
        finding=sample_finding,
        deployment=sample_deployment,
        advisory=sample_advisory,
    )

    decision = evaluate_policy(evidence=bundle, prediction=None, policy=policy, mode=RunMode.SHADOW)
    assert decision.assessment == Assessment.AFFECTED
    assert decision.priority == "P1"  # high criticality production HIGH/CRITICAL
    assert decision.proposed_action == ProposedAction.PRIORITIZE_REMEDIATION


def test_policy_model_failure_routes_to_human_review(
    sample_finding: FindingObservation,
    sample_deployment,
    sample_advisory,
):
    policy = PolicyConfig()
    bundle = assemble_evidence(
        finding=sample_finding,
        deployment=sample_deployment,
        advisory=sample_advisory,
    )

    failed_pred = Prediction(
        suggested_assessment=Assessment.UNKNOWN,
        probabilities=None,
        reason_code="NETWORK_TIMEOUT",
        evidence_ids=[],
        backend_id="fake",
        model_revision="v1",
        input_hash="hash",
        status="TIMEOUT",
    )

    decision = evaluate_policy(evidence=bundle, prediction=failed_pred, policy=policy)
    assert decision.assessment == Assessment.UNKNOWN
    assert decision.proposed_action == ProposedAction.HUMAN_REVIEW
    assert any("PREDICTION_ABORTED_TIMEOUT" in r for r in decision.reason_codes)
