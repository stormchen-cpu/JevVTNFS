from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from vuln_triage.config import EgressConfig
from vuln_triage.domain.identity import (
    _canonical_json,
    compute_sha256,
)
from vuln_triage.domain.models import (
    DecisionInput,
    EvidenceBundle,
)


class EgressPayload(BaseModel):
    payload_id: str
    is_blocked: bool = False
    block_reason: Optional[str] = None
    sanitized_data: Dict[str, Any] = Field(default_factory=dict)
    allowed_fields: List[str] = Field(default_factory=list)
    stripped_fields: List[str] = Field(default_factory=list)
    evidence_id_map: Dict[str, str] = Field(default_factory=dict)
    output_hash: str = ""


class EgressEvent(BaseModel):
    event_id: str
    run_id: Optional[str] = None
    provider: str
    model: str
    request_hash: str
    status: str  # ALLOWED, BLOCKED, FAILED
    allowed_fields: List[str] = Field(default_factory=list)
    stripped_fields: List[str] = Field(default_factory=list)
    created_at: str


class EgressGateway:
    def __init__(self, config: EgressConfig):
        self.config = config
        self._compiled_patterns = [
            (p.name, re.compile(p.regex)) for p in config.prohibited_patterns
        ]

    def prepare(self, bundle: EvidenceBundle) -> EgressPayload:
        if not self.config.enabled:
            # If egress is disabled globally, block immediately
            return EgressPayload(
                payload_id="egress-disabled",
                is_blocked=True,
                block_reason="Egress is globally disabled in configuration.",
            )

        stripped_fields: List[str] = []
        allowed_fields: List[str] = []
        sanitized_data: Dict[str, Any] = {}
        evidence_id_map: Dict[str, str] = {}

        # 1. Project allowed package & vulnerability metadata
        finding = bundle.finding
        sanitized_data["vulnerability_id"] = finding.vulnerability_id
        sanitized_data["ecosystem"] = finding.package.ecosystem
        sanitized_data["package_name"] = finding.package.name
        sanitized_data["package_version"] = finding.package.version
        allowed_fields.extend(["vulnerability_id", "ecosystem", "package_name", "package_version"])

        # 2. Abstract environment (never expose internal asset_id / hostname / deployment_id)
        if bundle.deployment:
            env = (bundle.deployment.environment or "unknown").lower()
            if "prod" in env:
                abstract_env = "PRODUCTION"
            elif "stag" in env:
                abstract_env = "STAGING"
            else:
                abstract_env = "NON_PRODUCTION"
            sanitized_data["abstract_environment"] = abstract_env
            allowed_fields.append("abstract_environment")

            # Strip internal identifiers
            stripped_fields.extend(["asset_id", "deployment_id", "artifact_digest"])
        else:
            sanitized_data["abstract_environment"] = "UNKNOWN"

        # 3. Advisory trigger conditions & public CVE metadata
        if bundle.advisory:
            sanitized_data["trigger_conditions"] = bundle.advisory.trigger_conditions
            allowed_fields.append("trigger_conditions")

            for field_name in (
                "cve_id",
                "euvd_id",
                "cvss_score",
                "is_actively_exploited",
                "description",
            ):
                val = getattr(bundle.advisory, field_name, None)
                if val is not None and field_name in self.config.allowed_fields:
                    if isinstance(val, str):
                        leak = self._detect_prohibited_patterns(val, is_cve_description=(field_name == "description"))
                        if leak:
                            return EgressPayload(
                                payload_id=f"egress-blocked-{bundle.bundle_id[:8]}",
                                is_blocked=True,
                                block_reason=f"Prohibited pattern '{leak}' detected in advisory.{field_name}.",
                                stripped_fields=stripped_fields,
                            )
                    sanitized_data[field_name] = val
                    allowed_fields.append(field_name)

        # 4. Filter and map evidence items
        sanitized_evidence: List[Dict[str, Any]] = []
        for idx, item in enumerate(bundle.evidence, start=1):
            anon_evidence_id = f"EV-{idx:03d}"
            evidence_id_map[anon_evidence_id] = item.evidence_id

            # Check value for prohibited patterns if string
            val = item.value
            if isinstance(val, str):
                violation = self._detect_prohibited_patterns(val)
                if violation:
                    # Sensitive pattern detected in evidence text!
                    return EgressPayload(
                        payload_id=f"egress-blocked-{bundle.bundle_id[:8]}",
                        is_blocked=True,
                        block_reason=f"Prohibited pattern '{violation}' detected in evidence text.",
                        stripped_fields=stripped_fields,
                    )

            sanitized_evidence.append({
                "ref_id": anon_evidence_id,
                "kind": item.kind,
                "value": item.value,
            })

        sanitized_data["evidence"] = sanitized_evidence
        allowed_fields.append("evidence")

        # 5. Check free-form text and whitelisted fields in raw payload
        if finding.raw_payload:
            for k, v in finding.raw_payload.items():
                if k in self.config.allowed_fields and k not in sanitized_data:
                    # Whitelisted raw payload fields (e.g. severity, pv_count, product_count)
                    if isinstance(v, str):
                        leak = self._detect_prohibited_patterns(v, is_cve_description=(k == "description"))
                        if leak:
                            return EgressPayload(
                                payload_id=f"egress-blocked-{bundle.bundle_id[:8]}",
                                is_blocked=True,
                                block_reason=f"Prohibited pattern '{leak}' detected in finding.raw_payload.{k}.",
                                stripped_fields=stripped_fields,
                            )
                    sanitized_data[k] = v
                    allowed_fields.append(k)
                elif k not in self.config.allowed_fields:
                    stripped_fields.append(f"finding.raw_payload.{k}")
                    if isinstance(v, str) and len(v) > 100:
                        # Potentially unvetted free-form text
                        if not self.config.allow_unvetted_free_text:
                            # Verify if free text contains internal sensitive leaks
                            leak = self._detect_prohibited_patterns(v)
                            if leak:
                                return EgressPayload(
                                    payload_id=f"egress-blocked-{bundle.bundle_id[:8]}",
                                    is_blocked=True,
                                    block_reason=f"Unvetted free-form text contains sensitive pattern: {leak}",
                                    stripped_fields=stripped_fields,
                                )

        output_json = _canonical_json(sanitized_data)
        output_hash = compute_sha256(output_json)
        payload_id = f"egr-{output_hash[:16]}"

        return EgressPayload(
            payload_id=payload_id,
            is_blocked=False,
            sanitized_data=sanitized_data,
            allowed_fields=allowed_fields,
            stripped_fields=sorted(list(set(stripped_fields))),
            evidence_id_map=evidence_id_map,
            output_hash=output_hash,
        )

    def _detect_prohibited_patterns(self, text: str, is_cve_description: bool = False) -> Optional[str]:
        for name, pattern in self._compiled_patterns:
            if is_cve_description:
                # For public CVE descriptions, check secrets, email addresses, and internal user file paths
                if name in ("secrets", "email_address", "internal_filepath"):
                    if pattern.search(text):
                        return name
                elif name == "ipv4_address":
                    # Check if text contains a private RFC1918 / sensitive corporate IP
                    # while allowing loopback/unspecified (0.0.0.0, 127.0.0.1), link-local doc (169.254.x.x), or dotted version numbers (e.g. 1.2.0.3, 1.3.6.1)
                    for match in pattern.finditer(text):
                        ip_str = match.group(0)
                        if (
                            ip_str.startswith("10.")
                            or ip_str.startswith("192.168.")
                            or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip_str)
                        ):
                            return name
            else:
                if pattern.search(text):
                    return name
        return None
