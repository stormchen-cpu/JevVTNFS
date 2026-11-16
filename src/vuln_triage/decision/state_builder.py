from __future__ import annotations

from vuln_triage.domain.identity import (
    _canonical_json,
    compute_sha256,
)
from vuln_triage.domain.models import (
    DecisionInput,
    EvidenceBundle,
)


def build_decision_input(bundle: EvidenceBundle) -> DecisionInput:
    """
    Constructs an immutable DecisionInput snapshot strictly from evidence
    available at evaluation time.
    """
    finding_summary = {
        "vulnerability_id": bundle.finding.vulnerability_id,
        "ecosystem": bundle.finding.package.ecosystem,
        "package_name": bundle.finding.package.name,
        "package_version": bundle.finding.package.version,
        "scanner_severity": bundle.finding.scanner_severity,
    }

    advisory_summary = {}
    if bundle.advisory:
        advisory_summary = {
            "advisory_id": bundle.advisory.advisory_id,
            "affected_ranges": bundle.advisory.affected_ranges,
            "trigger_conditions": bundle.advisory.trigger_conditions,
        }

    evidence_summary = [
        {
            "evidence_id": item.evidence_id,
            "kind": item.kind,
            "value": item.value,
        }
        for item in bundle.evidence
    ]

    allowed_facts = {}
    if bundle.deployment:
        allowed_facts = {
            "environment": bundle.deployment.environment,
            "criticality": bundle.deployment.criticality,
        }

    raw_payload = {
        "finding": finding_summary,
        "advisory": advisory_summary,
        "evidence": evidence_summary,
        "allowed_facts": allowed_facts,
    }

    input_hash = compute_sha256(_canonical_json(raw_payload))

    return DecisionInput(
        input_hash=input_hash,
        finding_summary=finding_summary,
        advisory_summary=advisory_summary,
        evidence_summary=evidence_summary,
        allowed_facts=allowed_facts,
    )
