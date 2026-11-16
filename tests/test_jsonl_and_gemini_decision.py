from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from vuln_triage.config import BackendConfig, EgressConfig, PolicyConfig, RootConfig
from vuln_triage.decision.gemini_decision_backend import GeminiDecisionBackend
from vuln_triage.decision.state_builder import build_decision_input
from vuln_triage.domain.models import (
    Assessment,
    EvidenceBundle,
    FindingObservation,
    PackageRef,
    ProposedAction,
    RunMode,
)
from vuln_triage.evaluation.runner import run_evaluation
from vuln_triage.evidence.assembler import assemble_evidence
from vuln_triage.ingest.readers import import_findings
from vuln_triage.policy.engine import evaluate_policy
from vuln_triage.privacy.egress import EgressGateway
from vuln_triage.storage.sqlite import Database
from vuln_triage.workflow.service import TriageService


def test_import_jsonl_dataset_and_advisory_synthesis(tmp_path: Path):
    db_path = tmp_path / "test_import.db"
    db = Database(db_path)
    db.init_db()

    dataset_file = Path("examples/triage_dataset.jsonl")
    assert dataset_file.exists()

    result = import_findings(dataset_file, source="test-jsonl")
    assert result.valid_count == 935
    assert result.failed_count == 0
    assert len(result.observations) == 935
    assert len(result.advisories) > 0

    import_id = db.save_import(result)
    assert import_id.startswith("imp-")

    # Verify observations in DB
    all_obs = db.get_observations(import_id=import_id)
    assert len(all_obs) == 935

    # Verify synthesized advisories in DB
    adv = db.get_advisory_snapshot("CVE-2022-48174")
    assert adv is not None
    assert adv.advisory_id == "CVE-2022-48174"
    assert "busybox" in adv.description.lower()
    assert adv.cvss_score == 9.8


def test_triage_run_with_limit_and_idempotency(tmp_path: Path):
    db_path = tmp_path / "test_run.db"
    db = Database(db_path)
    db.init_db()

    # Import full dataset
    result = import_findings("examples/triage_dataset.jsonl", source="test-jsonl")
    db.save_import(result)

    cfg = RootConfig()
    cfg.app.database_path = str(db_path)
    service = TriageService(cfg, db=db)

    # 1. Run with limit=10 on under_investigation
    summary1 = service.run_batch(
        batch_id="batch-limit-10",
        mode=RunMode.SHADOW,
        vex_status_filter="under_investigation",
        limit=10,
    )
    assert summary1.total_processed == 10
    assert summary1.succeeded == 10
    assert summary1.skipped_idempotent == 0

    # 2. Run again with same batch and verify idempotency skips
    summary2 = service.run_batch(
        batch_id="batch-limit-10-retry",
        mode=RunMode.SHADOW,
        vex_status_filter="under_investigation",
        limit=10,
    )
    assert summary2.total_processed == 10
    assert summary2.skipped_idempotent == 10
    assert summary2.succeeded == 0


def test_gemini_decision_backend_live_api_mock(sample_finding: FindingObservation):
    cfg = BackendConfig(
        type="gemini-decision",
        api_base_url="https://generativelanguage.googleapis.com/v1beta",
        model_name="gemini-decision-1",
        api_key="mock-gemini-key",
        confidence_threshold=0.80,
    )
    backend = GeminiDecisionBackend(cfg)

    bundle = assemble_evidence(finding=sample_finding, deployment=None, advisory=None)
    gateway = EgressGateway(EgressConfig())
    egress_payload = gateway.prepare(bundle)
    dec_input = build_decision_input(bundle)

    mock_resp_json = {
        "answers": {
            "overall_assessment": {
                "choice": "NOT_AFFECTED",
                "confidence": 0.94,
                "probabilities": {"NOT_AFFECTED": 0.94, "AFFECTED": 0.06},
            },
            "is_version_affected": {"noul": 0.05, "confidence": 0.95},
            "requires_specific_trigger": {"noul": 0.10, "confidence": 0.90},
        }
    }

    mock_resp_bytes = json.dumps(mock_resp_json).encode("utf-8")

    class MockHTTPResponse:
        def read(self):
            return mock_resp_bytes

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("urllib.request.urlopen", return_value=MockHTTPResponse()) as mock_urlopen:
        prediction = backend.predict(dec_input, egress_payload)

        assert prediction.status == "SUCCESS"
        assert prediction.suggested_assessment == Assessment.NOT_AFFECTED
        assert prediction.confidence == 0.95  # Calibrated from ver_conf or overall
        assert prediction.reason_code == "GEMINI_DECISION_VERSION_OR_COMPONENT_NOT_AFFECTED"
        assert prediction.sub_decisions is not None
        assert "overall_assessment" in prediction.sub_decisions

        # Verify outgoing HTTP request URL, headers, and payload
        mock_urlopen.assert_called_once()
        req_arg = mock_urlopen.call_args[0][0]
        assert req_arg.full_url == "https://generativelanguage.googleapis.com/v1beta/decisions"
        assert req_arg.headers["X-goog-api-key"] == "mock-gemini-key"

        req_payload = json.loads(req_arg.data.decode("utf-8"))
        assert req_payload["model"] == "gemini-decision-1"
        assert "questions" in req_payload
        assert "overall_assessment" in req_payload["questions"]
        assert "is_version_affected" in req_payload["questions"]
        assert "requires_specific_trigger" in req_payload["questions"]


def test_confidence_threshold_routing_to_human_review(
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
    dec_input = build_decision_input(bundle)

    cfg = BackendConfig(
        type="gemini-decision",
        api_key="mock-key",
        confidence_threshold=0.80,
    )
    backend = GeminiDecisionBackend(cfg)

    # Return low confidence (0.65 < 0.80)
    mock_resp_json = {
        "answers": {
            "overall_assessment": {
                "choice": "NOT_AFFECTED",
                "confidence": 0.65,
                "probabilities": {"NOT_AFFECTED": 0.65, "AFFECTED": 0.35},
            },
            "is_version_affected": {"noul": 0.40, "confidence": 0.65},
            "requires_specific_trigger": {"noul": 0.50, "confidence": 0.60},
        }
    }
    mock_resp_bytes = json.dumps(mock_resp_json).encode("utf-8")

    class MockHTTPResponse:
        def read(self):
            return mock_resp_bytes

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("urllib.request.urlopen", return_value=MockHTTPResponse()):
        prediction = backend.predict(dec_input, egress_payload)
        assert prediction.suggested_assessment == Assessment.NOT_AFFECTED
        assert prediction.confidence == 0.65

        policy = PolicyConfig(decision_confidence_threshold=0.80)
        decision = evaluate_policy(evidence=bundle, prediction=prediction, policy=policy)

        # Policy should gate on confidence and route to HUMAN_REVIEW
        assert decision.assessment == Assessment.UNKNOWN
        assert decision.proposed_action == ProposedAction.HUMAN_REVIEW
        assert any("LOW_MODEL_CONFIDENCE:0.65<0.80" in r for r in decision.reason_codes)


def test_egress_blocks_leaks_in_cve_description_while_allowing_doc_ips():
    from vuln_triage.config import DEFAULT_PROHIBITED_PATTERNS
    config = EgressConfig(prohibited_patterns=list(DEFAULT_PROHIBITED_PATTERNS))
    gateway = EgressGateway(config)

    # 1. Normal CVE with documentation / loopback IPs (e.g. 127.0.0.1, 0.0.0.0)
    from vuln_triage.domain.models import AdvisorySnapshot
    from datetime import datetime, timezone

    clean_adv = AdvisorySnapshot(
        advisory_id="CVE-2026-44492",
        retrieved_at=datetime.now(timezone.utc),
        content_hash="hash1",
        description="Axios issue with 127.0.0.1 and 169.254.169.254 bypass",
    )
    obs = FindingObservation(
        observation_id="obs-clean",
        source="test",
        observed_at=datetime.now(timezone.utc),
        package=PackageRef(ecosystem="npm", name="axios", version="1.15.2"),
        vulnerability_id="CVE-2026-44492",
        raw_ref="test:1",
    )
    bundle_clean = assemble_evidence(finding=obs, deployment=None, advisory=clean_adv)
    payload_clean = gateway.prepare(bundle_clean)
    assert not payload_clean.is_blocked
    assert payload_clean.sanitized_data["description"] == clean_adv.description

    # 2. CVE description with internal user file path leak
    leaky_adv_path = AdvisorySnapshot(
        advisory_id="CVE-2026-LEAK-PATH",
        retrieved_at=datetime.now(timezone.utc),
        content_hash="hash2",
        description="Crash occurred at /home/developer/secret_project/core.c line 42",
    )
    bundle_leak_path = assemble_evidence(finding=obs, deployment=None, advisory=leaky_adv_path)
    payload_leak_path = gateway.prepare(bundle_leak_path)
    assert payload_leak_path.is_blocked is True
    assert "internal_filepath" in payload_leak_path.block_reason

    # 3. CVE description with private internal corporate IP (RFC1918 192.168.1.50)
    leaky_adv_ip = AdvisorySnapshot(
        advisory_id="CVE-2026-LEAK-IP",
        retrieved_at=datetime.now(timezone.utc),
        content_hash="hash3",
        description="Leaked connection details to internal server at 192.168.1.50:8080",
    )
    bundle_leak_ip = assemble_evidence(finding=obs, deployment=None, advisory=leaky_adv_ip)
    payload_leak_ip = gateway.prepare(bundle_leak_ip)
    assert payload_leak_ip.is_blocked is True
    assert "ipv4_address" in payload_leak_ip.block_reason



def test_run_evaluation_on_jsonl_ground_truth():
    report = run_evaluation("configs/evaluation.example.yaml")
    assert report.total_ground_truth_samples == 85
    assert report.train_count + report.val_count + report.test_count == 85
    assert report.test_count > 0

    metrics = report.test_metrics.metrics
    assert "false_negative_rate" in metrics
    assert "suppression_error_rate" in metrics
    assert "automated_coverage" in metrics

    # Zero false negative leakage on the test split
    assert metrics["false_negative_rate"].rate == 0.0
    assert metrics["suppression_error_rate"].rate == 0.0
