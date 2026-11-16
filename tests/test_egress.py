from __future__ import annotations

from vuln_triage.config import EgressConfig, ProhibitedPattern
from vuln_triage.domain.models import EvidenceBundle, EvidenceItem, FindingObservation, VerificationStatus
from vuln_triage.evidence.assembler import assemble_evidence
from vuln_triage.privacy.egress import EgressGateway


def test_egress_strips_internal_identifiers(
    sample_finding: FindingObservation,
    sample_deployment,
    sample_advisory,
):
    bundle = assemble_evidence(
        finding=sample_finding,
        deployment=sample_deployment,
        advisory=sample_advisory,
    )

    config = EgressConfig()
    gateway = EgressGateway(config)
    payload = gateway.prepare(bundle)

    assert not payload.is_blocked
    sanitized = payload.sanitized_data

    # Whitelisted fields are present
    assert sanitized["vulnerability_id"] == "VULN-DEMO-001"
    assert sanitized["ecosystem"] == "npm"
    assert sanitized["package_name"] == "demo-package"
    assert sanitized["package_version"] == "1.2.3"
    assert sanitized["abstract_environment"] == "PRODUCTION"

    # Internal identifiers are NOT in sanitized output
    assert "asset_id" not in sanitized
    assert "deployment_id" not in sanitized
    assert "artifact_digest" not in sanitized
    assert "asset-demo-1" not in str(sanitized)
    assert "deploy-demo-1" not in str(sanitized)


def test_egress_blocks_when_prohibited_patterns_detected(
    sample_finding: FindingObservation,
    sample_deployment,
    sample_advisory,
):
    config = EgressConfig(
        prohibited_patterns=[
            ProhibitedPattern(regex=r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", name="ipv4"),
            ProhibitedPattern(regex=r"(?i)api_key=[a-zA-Z0-9]+", name="secret"),
        ]
    )

    bundle = assemble_evidence(
        finding=sample_finding,
        deployment=sample_deployment,
        advisory=sample_advisory,
    )

    # Inject an evidence item containing an internal IP address
    tainted_evidence = list(bundle.evidence)
    tainted_evidence.append(
        EvidenceItem(
            evidence_id="evi-tainted",
            kind="internal_log",
            value="Error connecting to internal server at 192.168.1.100 with api_key=secretKey12345",
            source_ref="test",
            observed_at=sample_finding.observed_at,
            verification_status=VerificationStatus.UNVERIFIED,
        )
    )

    tainted_bundle = EvidenceBundle(
        bundle_id="bnd-tainted",
        finding=bundle.finding,
        deployment=bundle.deployment,
        advisory=bundle.advisory,
        evidence=tainted_evidence,
        missing_fields=[],
        conflicts=[],
        fingerprint="fp-tainted",
    )

    gateway = EgressGateway(config)
    payload = gateway.prepare(tainted_bundle)

    assert payload.is_blocked is True
    assert "Prohibited pattern" in (payload.block_reason or "")
    assert "192.168.1.100" not in str(payload.sanitized_data)
