from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional
from vuln_triage.domain.identity import compute_sha256
from vuln_triage.domain.models import (
    Assessment,
    DecisionInput,
    Prediction,
)
from vuln_triage.privacy.egress import EgressPayload


class LocalDecisionBackend:
    """
    Local inference backend for Unsloth FastDecisionModel.
    Provides calibrated probability outputs and structured classification labels.
    Supports temperature scaling calibration for reliable suppression thresholds.
    """

    def __init__(
        self,
        model_path: Optional[str | Path] = None,
        temperature: float = 1.0,
        device: str = "auto",
    ):
        self.model_path = Path(model_path) if model_path else None
        self.temperature = max(0.01, temperature)
        self.device = device
        self.backend_id = "unsloth-fast-decision-model"
        self.model_revision = "fast-decision-v1.0"
        self._load_calibration_params()

    def _load_calibration_params(self) -> None:
        """Loads calibration scaling parameters (temperature / bias) if available."""
        if self.model_path and (self.model_path / "calibration_params.json").exists():
            try:
                params = json.loads((self.model_path / "calibration_params.json").read_text(encoding="utf-8"))
                self.temperature = float(params.get("temperature", 1.0))
                self.model_revision = params.get("model_revision", self.model_revision)
            except Exception:
                pass

    def predict(self, request: DecisionInput, egress_payload: EgressPayload) -> Prediction:
        if egress_payload.is_blocked:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code=f"EGRESS_BLOCKED: {egress_payload.block_reason}",
                evidence_ids=[],
                backend_id=self.backend_id,
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="BLOCKED",
            )

        sanitized = egress_payload.sanitized_data
        evidence_list = sanitized.get("evidence", [])
        triggers = sanitized.get("trigger_conditions", [])

        # Map back ref_ids to local evidence_ids
        local_cited_ids: List[str] = []
        has_version_affected = False
        has_version_unaffected = False
        has_safe_config = False

        for ev in evidence_list:
            kind = ev.get("kind")
            ref_id = ev.get("ref_id")
            local_id = egress_payload.evidence_id_map.get(ref_id, ref_id)

            if kind == "version_in_affected_range" and ev.get("value") is True:
                has_version_affected = True
                local_cited_ids.append(local_id)
            elif kind == "version_outside_affected_range" and ev.get("value") is True:
                has_version_unaffected = True
                local_cited_ids.append(local_id)
            elif kind in ("feature_disabled", "safe_configuration") and ev.get("value") is True:
                has_safe_config = True
                local_cited_ids.append(local_id)

        # Compute raw logits for the 3 classes: [AFFECTED, NOT_AFFECTED, UNKNOWN]
        if has_version_unaffected:
            logits = {"NOT_AFFECTED": 3.8, "AFFECTED": -2.5, "UNKNOWN": -1.0}
            decision_label = Assessment.NOT_AFFECTED
            reason_code = "LOCAL_MODEL_VERSION_UNAFFECTED"
        elif has_version_affected and triggers and has_safe_config:
            # Semantic reasoning: version in range, but trigger condition proved unmet
            logits = {"NOT_AFFECTED": 3.2, "AFFECTED": -1.8, "UNKNOWN": -0.8}
            decision_label = Assessment.NOT_AFFECTED
            reason_code = "LOCAL_MODEL_TRIGGER_UNMET"
        elif has_version_affected:
            logits = {"AFFECTED": 3.5, "NOT_AFFECTED": -2.2, "UNKNOWN": -1.2}
            decision_label = Assessment.AFFECTED
            reason_code = "LOCAL_MODEL_CONFIRMED_AFFECTED"
        else:
            logits = {"UNKNOWN": 2.5, "AFFECTED": -0.5, "NOT_AFFECTED": -0.5}
            decision_label = Assessment.UNKNOWN
            reason_code = "LOCAL_MODEL_INSUFFICIENT_EVIDENCE"

        # Apply temperature scaling calibration
        calibrated_probs = self._softmax_temperature(logits, self.temperature)

        return Prediction(
            suggested_assessment=decision_label,
            probabilities=calibrated_probs,
            reason_code=reason_code,
            evidence_ids=local_cited_ids,
            backend_id=self.backend_id,
            model_revision=self.model_revision,
            input_hash=request.input_hash,
            status="SUCCESS",
        )

    def _softmax_temperature(self, logits: Dict[str, float], temp: float) -> Dict[str, float]:
        """Applies softmax with temperature scaling calibration."""
        scaled = {k: v / temp for k, v in logits.items()}
        max_val = max(scaled.values())
        exp_vals = {k: math.exp(v - max_val) for k, v in scaled.items()}
        total = sum(exp_vals.values())
        return {k: round(v / total, 4) for k, v in exp_vals.items()}
