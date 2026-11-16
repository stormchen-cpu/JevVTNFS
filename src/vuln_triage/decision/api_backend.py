from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from vuln_triage.config import BackendConfig
from vuln_triage.domain.models import (
    Assessment,
    DecisionInput,
    Prediction,
)
from vuln_triage.privacy.egress import EgressPayload


class ApiBackend:
    """
    API Backend for external AI LLM endpoints.
    Accepts sanitized EgressPayload, queries the model, and validates structured output.
    """

    def __init__(self, config: BackendConfig):
        self.config = config
        self.backend_id = f"api-{config.model_name}"
        self.model_revision = config.model_name

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

        if not self.config.api_key:
            # No API key provided, fall back safely to UNKNOWN without crashing
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code="API_KEY_NOT_CONFIGURED",
                evidence_ids=[],
                backend_id=self.backend_id,
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="FAILED",
            )

        system_prompt = (
            "You are a vulnerability triage decision engine. Analyze the provided sanitized "
            "vulnerability evidence. You must return ONLY a JSON object matching this schema:\n"
            "{\n"
            '  "suggested_assessment": "AFFECTED" | "NOT_AFFECTED" | "UNKNOWN",\n'
            '  "reason_code": "SHORT_REASON_CODE",\n'
            '  "evidence_ids": ["ref_id_1", "ref_id_2"]\n'
            "}\n"
            "Do not guess or assume. Only cite provided ref_id values. If evidence is incomplete, output UNKNOWN."
        )

        user_content = json.dumps(egress_payload.sanitized_data, ensure_ascii=False)

        payload = {
            "model": self.config.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }

        url = f"{self.config.api_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }

        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                choice = resp_data["choices"][0]["message"]["content"]
                parsed = json.loads(choice)

                raw_assessment = str(parsed.get("suggested_assessment", "UNKNOWN")).upper()
                if raw_assessment not in Assessment.__members__:
                    raw_assessment = "UNKNOWN"
                assessment = Assessment(raw_assessment)

                reason_code = str(parsed.get("reason_code", "MODEL_INFERENCE"))
                raw_ref_ids = parsed.get("evidence_ids", [])

                # Map ref_ids back to local evidence IDs and validate existence
                local_evidence_ids: List[str] = []
                for ref_id in raw_ref_ids:
                    if ref_id in egress_payload.evidence_id_map:
                        local_evidence_ids.append(egress_payload.evidence_id_map[ref_id])
                    else:
                        # Non-existent citation detected!
                        return Prediction(
                            suggested_assessment=Assessment.UNKNOWN,
                            probabilities=None,
                            reason_code="INVALID_EVIDENCE_CITATION",
                            evidence_ids=[],
                            backend_id=self.backend_id,
                            model_revision=self.model_revision,
                            input_hash=request.input_hash,
                            status="FAILED",
                        )

                return Prediction(
                    suggested_assessment=assessment,
                    probabilities=None,  # Do not treat raw LLM self-reported numbers as calibrated
                    reason_code=reason_code,
                    evidence_ids=local_evidence_ids,
                    backend_id=self.backend_id,
                    model_revision=self.model_revision,
                    input_hash=request.input_hash,
                    status="SUCCESS",
                )

        except urllib.error.HTTPError as e:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code=f"HTTP_ERROR_{e.code}",
                evidence_ids=[],
                backend_id=self.backend_id,
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="FAILED",
            )
        except urllib.error.URLError:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code="NETWORK_OR_TIMEOUT_ERROR",
                evidence_ids=[],
                backend_id=self.backend_id,
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="TIMEOUT",
            )
        except Exception as e:
            return Prediction(
                suggested_assessment=Assessment.UNKNOWN,
                probabilities=None,
                reason_code=f"MALFORMED_OUTPUT: {str(e)}",
                evidence_ids=[],
                backend_id=self.backend_id,
                model_revision=self.model_revision,
                input_hash=request.input_hash,
                status="FAILED",
            )
