from __future__ import annotations

import json
from pathlib import Path
import pytest

from vuln_triage.config import PolicyConfig
from vuln_triage.decision.backend import FakeBackend
from vuln_triage.decision.local_backend import LocalDecisionBackend
from vuln_triage.decision.state_builder import build_decision_input
from vuln_triage.domain.models import (
    Assessment,
    EvidenceItem,
    FindingObservation,
    ProposedAction,
    RunMode,
    VerificationStatus,
)
from vuln_triage.evidence.assembler import assemble_evidence
from vuln_triage.policy.engine import evaluate_policy
from vuln_triage.privacy.egress import EgressGateway, EgressConfig
from vuln_triage.training.train_unsloth import (
    convert_dataset_for_unsloth,
    run_unsloth_training_pipeline,
)


def test_decision_model_trigger_condition_unmet(
    sample_finding: FindingObservation,
    sample_deployment,
    sample_advisory,
):
    """
    Tests that when an advisory has specific trigger conditions and the Decision Model
    determines the condition is unmet, policy marks NOT_AFFECTED and proposes SUPPRESS_UNTIL,
    even though the package version is inside the affected range!
    """
    policy = PolicyConfig()
    bundle = assemble_evidence(
        finding=sample_finding,
        deployment=sample_deployment,
        advisory=sample_advisory,
    )

    # 1. Without Decision Model reasoning (default fallback): version in range -> AFFECTED
    fallback_decision = evaluate_policy(evidence=bundle, prediction=None, policy=policy)
    assert fallback_decision.assessment == Assessment.AFFECTED
    assert fallback_decision.proposed_action == ProposedAction.PRIORITIZE_REMEDIATION

    # 2. With Decision Model identifying that the trigger condition is unmet:
    gateway = EgressGateway(EgressConfig())
    egress_payload = gateway.prepare(bundle)
    decision_input = build_decision_input(bundle)

    backend = FakeBackend(simulate_trigger_unmet=True)
    prediction = backend.predict(decision_input, egress_payload)

    assert prediction.suggested_assessment == Assessment.NOT_AFFECTED
    assert prediction.reason_code == "TRIGGER_CONDITION_UNMET"
    assert prediction.probabilities is not None
    assert prediction.probabilities["NOT_AFFECTED"] >= 0.95

    # 3. Policy evaluates bundle + Decision Model prediction:
    model_assisted_decision = evaluate_policy(
        evidence=bundle,
        prediction=prediction,
        policy=policy,
        mode=RunMode.SHADOW,
    )

    assert model_assisted_decision.assessment == Assessment.NOT_AFFECTED
    assert model_assisted_decision.proposed_action == ProposedAction.SUPPRESS_UNTIL
    assert any("DECISION_MODEL_TRIGGER_UNMET" in r for r in model_assisted_decision.reason_codes)


def test_local_decision_backend_temperature_calibration(
    sample_finding: FindingObservation,
    sample_deployment,
    sample_advisory,
):
    bundle = assemble_evidence(
        finding=sample_finding,
        deployment=sample_deployment,
        advisory=sample_advisory,
    )
    gateway = EgressGateway(EgressConfig())
    egress_payload = gateway.prepare(bundle)
    decision_input = build_decision_input(bundle)

    # Test LocalDecisionBackend
    local_backend = LocalDecisionBackend(temperature=1.2)
    pred = local_backend.predict(decision_input, egress_payload)

    assert pred.status == "SUCCESS"
    assert pred.probabilities is not None
    assert "AFFECTED" in pred.probabilities
    assert "NOT_AFFECTED" in pred.probabilities
    # Check probabilities sum to approx 1.0
    prob_sum = sum(pred.probabilities.values())
    assert abs(prob_sum - 1.0) < 0.01


def test_unsloth_pipeline_and_manifest(tmp_path: Path):
    # Create sample exported dataset
    sample_manifest = tmp_path / "dataset.json"
    sample_manifest.write_text(
        json.dumps({
            "manifest_version": "1.0.0",
            "records": [
                {
                    "vulnerability_id": "VULN-001",
                    "ecosystem": "npm",
                    "package_name": "test-pkg",
                    "package_version": "1.0.0",
                    "assessment": "NOT_AFFECTED",
                    "reason": "TRIGGER_CONDITION_UNMET",
                    "priority": "P4",
                    "occurrence_key": "occ-test-1",
                    "provenance": "human_verified",
                }
            ],
        }),
        encoding="utf-8",
    )

    out_jsonl = tmp_path / "unsloth_training.jsonl"
    count = convert_dataset_for_unsloth(sample_manifest, out_jsonl)
    assert count == 1
    assert out_jsonl.exists()

    res = run_unsloth_training_pipeline("configs/training.example.yaml", output_dir=tmp_path / "models")
    assert res["status"] == "SUCCESS"
    assert "calibration" in res
    assert (tmp_path / "models" / "calibration_params.json").exists()
    assert (tmp_path / "models" / "release_manifest.json").exists()
