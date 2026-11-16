from __future__ import annotations

from typing import Any, Dict, List, Optional

from vuln_triage.config import PolicyConfig
from vuln_triage.domain.identity import (
    compute_fingerprint,
    compute_sha256,
)
from vuln_triage.domain.models import (
    AdvisorySnapshot,
    DeploymentSnapshot,
    EvidenceBundle,
    EvidenceItem,
    FindingObservation,
    VerificationStatus,
)
from vuln_triage.evidence.rules import (
    evaluate_version_range,
    validate_exclusion_claims,
)


def assemble_evidence(
    finding: FindingObservation,
    deployment: Optional[DeploymentSnapshot] = None,
    advisory: Optional[AdvisorySnapshot] = None,
    policy_config: Optional[PolicyConfig] = None,
) -> EvidenceBundle:
    missing_fields: List[str] = []
    conflicts: List[str] = []
    evidence_items: List[EvidenceItem] = []

    # 1. Check missing fields
    if not finding.asset_id:
        missing_fields.append("asset_id")
    if not finding.deployment_id:
        missing_fields.append("deployment_id")
    if not finding.package.version:
        missing_fields.append("package_version")
    if deployment is None:
        missing_fields.append("deployment_snapshot")
    if advisory is None:
        missing_fields.append("advisory_snapshot")

    # 2. Check advisory ecosystem and package consistency
    if advisory:
        if advisory.ecosystem and finding.package.ecosystem:
            if advisory.ecosystem.lower() != finding.package.ecosystem.lower():
                conflicts.append(
                    f"Ecosystem mismatch: finding={finding.package.ecosystem}, advisory={advisory.ecosystem}"
                )
        if advisory.package_name and finding.package.name:
            if advisory.package_name.lower() != finding.package.name.lower():
                conflicts.append(
                    f"Package name mismatch: finding={finding.package.name}, advisory={advisory.package_name}"
                )

    # 3. Version range evaluation rule
    if advisory and finding.package.version and advisory.affected_ranges:
        is_affected, reason = evaluate_version_range(
            ecosystem=finding.package.ecosystem,
            package_version=finding.package.version,
            affected_ranges=advisory.affected_ranges,
        )
        if is_affected is True:
            evidence_items.append(
                EvidenceItem(
                    evidence_id="evi-version-affected",
                    kind="version_in_affected_range",
                    value=True,
                    source_ref=f"advisory:{advisory.advisory_id}",
                    observed_at=finding.observed_at,
                    verification_status=VerificationStatus.RULE_VERIFIED,
                )
            )
        elif is_affected is False:
            evidence_items.append(
                EvidenceItem(
                    evidence_id="evi-version-unaffected",
                    kind="version_outside_affected_range",
                    value=True,
                    source_ref=f"advisory:{advisory.advisory_id}",
                    observed_at=finding.observed_at,
                    verification_status=VerificationStatus.RULE_VERIFIED,
                )
            )
        else:
            evidence_items.append(
                EvidenceItem(
                    evidence_id="evi-version-unknown",
                    kind="version_check_unknown",
                    value=reason,
                    source_ref=f"advisory:{advisory.advisory_id}",
                    observed_at=finding.observed_at,
                    verification_status=VerificationStatus.UNVERIFIED,
                )
            )

    # 4. Deployment configuration evidence
    if deployment:
        config = deployment.configuration or {}
        if config.get("waf_enabled") is True:
            evidence_items.append(
                EvidenceItem(
                    evidence_id="evi-deploy-waf",
                    kind="waf_present",
                    value=True,
                    source_ref=f"snapshot:{deployment.snapshot_id}",
                    observed_at=deployment.observed_at,
                    verification_status=VerificationStatus.RULE_VERIFIED,
                )
            )
        if config.get("network_facing") is False:
            evidence_items.append(
                EvidenceItem(
                    evidence_id="evi-deploy-intranet",
                    kind="intranet_only",
                    value=True,
                    source_ref=f"snapshot:{deployment.snapshot_id}",
                    observed_at=deployment.observed_at,
                    verification_status=VerificationStatus.RULE_VERIFIED,
                )
            )

        # Check component installed in deployment
        installed = any(
            c.get("name", "").lower() == finding.package.name.lower()
            for c in deployment.components
        )
        if installed:
            evidence_items.append(
                EvidenceItem(
                    evidence_id="evi-component-installed",
                    kind="component_installed",
                    value=True,
                    source_ref=f"snapshot:{deployment.snapshot_id}",
                    observed_at=deployment.observed_at,
                    verification_status=VerificationStatus.RULE_VERIFIED,
                )
            )

    # 5. Check prohibited exclusions
    if policy_config:
        kinds = [e.kind for e in evidence_items]
        violations = validate_exclusion_claims(kinds, policy_config.prohibited_exclusions)
        for v in violations:
            evidence_items.append(
                EvidenceItem(
                    evidence_id=f"evi-prohibited-claim-{len(evidence_items)}",
                    kind="prohibited_exclusion_warning",
                    value=v,
                    source_ref="policy:prohibited_exclusions",
                    observed_at=finding.observed_at,
                    verification_status=VerificationStatus.RULE_VERIFIED,
                )
            )

    # Convert to serializable dicts for fingerprint computation
    finding_dict = finding.model_dump(mode="json")
    deployment_dict = deployment.model_dump(mode="json") if deployment else None
    advisory_dict = advisory.model_dump(mode="json") if advisory else None
    evidence_dicts = [e.model_dump(mode="json") for e in evidence_items]

    fingerprint = compute_fingerprint(
        finding_dict=finding_dict,
        deployment_dict=deployment_dict,
        advisory_dict=advisory_dict,
        evidence_items=evidence_dicts,
        missing_fields=missing_fields,
        conflicts=conflicts,
    )

    bundle_id = f"bnd-{fingerprint[:16]}"

    return EvidenceBundle(
        bundle_id=bundle_id,
        finding=finding,
        deployment=deployment,
        advisory=advisory,
        evidence=evidence_items,
        missing_fields=sorted(missing_fields),
        conflicts=sorted(conflicts),
        fingerprint=fingerprint,
    )
