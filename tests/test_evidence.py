from __future__ import annotations

import pytest

from vuln_triage.config import PolicyConfig
from vuln_triage.domain.models import (
    AdvisorySnapshot,
    DeploymentSnapshot,
    FindingObservation,
    PackageRef,
    VerificationStatus,
)
from vuln_triage.evidence.assembler import assemble_evidence
from vuln_triage.evidence.rules import (
    compare_npm_version,
    compare_pypi_version,
    evaluate_version_range,
    validate_exclusion_claims,
)


def test_pypi_version_comparison():
    # 1.5.0 inside [1.0.0, 2.0.0)
    in_range, reason = compare_pypi_version("1.5.0", introduced="1.0.0", fixed="2.0.0")
    assert in_range is True

    # 2.0.0 is fixed -> not in range
    in_range, reason = compare_pypi_version("2.0.0", introduced="1.0.0", fixed="2.0.0")
    assert in_range is False

    # 0.9.0 is before introduced -> not in range
    in_range, reason = compare_pypi_version("0.9.0", introduced="1.0.0", fixed="2.0.0")
    assert in_range is False

    # Invalid version format returns None (Unknown)
    in_range, reason = compare_pypi_version("not_a_version_string", introduced="1.0.0", fixed="2.0.0")
    assert in_range is None
    assert "unsupported_version_format" in reason


def test_npm_version_comparison():
    # 1.2.3 inside [0.0.0, 1.3.0)
    in_range, reason = compare_npm_version("1.2.3", introduced="0.0.0", fixed="1.3.0")
    assert in_range is True

    # 1.3.0 at fixed
    in_range, reason = compare_npm_version("1.3.0", introduced="0.0.0", fixed="1.3.0")
    assert in_range is False

    # Malformed npm version returns None
    in_range, reason = compare_npm_version("custom-beta-build-xyz", introduced="0.0.0", fixed="1.3.0")
    assert in_range is None


def test_prohibited_negative_claims():
    kinds = ["intranet_only", "waf_present", "version_outside_affected_range"]
    prohibited = ["intranet_only", "waf_present", "no_upload_endpoint"]

    violations = validate_exclusion_claims(kinds, prohibited)
    assert len(violations) == 2
    assert any("intranet_only" in v for v in violations)
    assert any("waf_present" in v for v in violations)


def test_assemble_evidence_missing_fields_and_conflicts(sample_finding: FindingObservation):
    # Without deployment or advisory
    bundle = assemble_evidence(finding=sample_finding, deployment=None, advisory=None)
    assert "deployment_snapshot" in bundle.missing_fields
    assert "advisory_snapshot" in bundle.missing_fields
    assert bundle.fingerprint is not None

    # Advisory with mismatched ecosystem
    adv_mismatch = AdvisorySnapshot(
        advisory_id="CVE-MISMATCH",
        retrieved_at=sample_finding.observed_at,
        content_hash="h1",
        ecosystem="maven",  # finding is npm
        package_name="demo-package",
    )
    bundle_mismatch = assemble_evidence(finding=sample_finding, advisory=adv_mismatch)
    assert any("Ecosystem mismatch" in c for c in bundle_mismatch.conflicts)
