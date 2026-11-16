from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol
from vuln_triage.domain.identity import compute_sha256
from vuln_triage.domain.models import (
    Assessment,
    DecisionInput,
    Prediction,
)
from vuln_triage.privacy.egress import EgressPayload


class DecisionBackend(Protocol):
    def predict(self, request: DecisionInput, egress_payload: EgressPayload) -> Prediction:
        ...


class FakeBackend:
    """
    Deterministic fake backend for testing and offline execution.
    Inspects sanitized egress payload and outputs consistent predictions.
    Supports fault injection for testing resilience.
    """

    def __init__(
        self,
        simulate_timeout: bool = False,
        simulate_invalid_citation: bool = False,
        simulate_malformed: bool = False,
        simulate_trigger_unmet: bool = False,
    ):
        self.simulate_timeout = simulate_timeout
        self.simulate_invalid_citation = simulate_invalid_citation
        self.simulate_malformed = simulate_malformed
        self.simulate_trigger_unmet = simulate_trigger_unmet
        self.model_revision = "fake-decision-v1.0.0"

    def predict(self, request: DecisionInput, egress_payload: EgressPayload) -> Prediction:
        if egress_payload.is_blocked:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code="EGRESS_BLOCKED",
                evidence_ids=[],
                backend_id="fake-backend",
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="BLOCKED",
            )

        if self.simulate_timeout:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code="BACKEND_TIMEOUT",
                evidence_ids=[],
                backend_id="fake-backend",
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="TIMEOUT",
            )

        if self.simulate_malformed:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code="MALFORMED_OUTPUT",
                evidence_ids=[],
                backend_id="fake-backend",
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="FAILED",
            )

        sanitized = egress_payload.sanitized_data
        evidence_list = sanitized.get("evidence", [])

        # Check citations
        cited_evidence_ids: List[str] = []
        is_affected = False
        is_unaffected = False

        for ev in evidence_list:
            kind = ev.get("kind")
            ref_id = ev.get("ref_id")
            # map back to local evidence_id
            local_id = egress_payload.evidence_id_map.get(ref_id, ref_id)

            if kind == "version_in_affected_range" and ev.get("value") is True:
                is_affected = True
                cited_evidence_ids.append(local_id)
            elif kind == "version_outside_affected_range" and ev.get("value") is True:
                is_unaffected = True
                cited_evidence_ids.append(local_id)

        if self.simulate_invalid_citation:
            cited_evidence_ids.append("evi-nonexistent-ghost-citation")

        # Decision Model trigger condition reasoning
        triggers = sanitized.get("trigger_conditions", [])
        if (self.simulate_trigger_unmet or any(ev.get("kind") == "feature_disabled" for ev in evidence_list)) and triggers:
            # Model deduces that even though version is affected, the required trigger condition is not met!
            return Prediction(
                suggested_assessment=Assessment.NOT_AFFECTED,
                probabilities={"NOT_AFFECTED": 0.96, "AFFECTED": 0.04},
                reason_code="TRIGGER_CONDITION_UNMET",
                evidence_ids=cited_evidence_ids,
                backend_id="fake-backend",
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="SUCCESS",
            )

        if is_affected:
            return Prediction(
                suggested_assessment=Assessment.AFFECTED,
                probabilities={"AFFECTED": 0.98, "NOT_AFFECTED": 0.02},
                reason_code="CONFIRMED_VERSION_AFFECTED",
                evidence_ids=cited_evidence_ids,
                backend_id="fake-backend",
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="SUCCESS",
            )
        elif is_unaffected:
            return Prediction(
                suggested_assessment=Assessment.NOT_AFFECTED,
                probabilities={"NOT_AFFECTED": 0.96, "AFFECTED": 0.04},
                reason_code="CONFIRMED_VERSION_OUTSIDE_RANGE",
                evidence_ids=cited_evidence_ids,
                backend_id="fake-backend",
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="SUCCESS",
            )
        else:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code="INSUFFICIENT_EVIDENCE",
                evidence_ids=cited_evidence_ids,
                backend_id="fake-backend",
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="SUCCESS",
            )
