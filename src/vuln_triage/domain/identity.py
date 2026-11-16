from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional


def _canonical_json(data: Any) -> str:
    """Produce deterministic canonical JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def compute_sha256(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_observation_id(
    source: str,
    source_finding_id: Optional[str],
    ecosystem: str,
    package_name: str,
    package_version: Optional[str],
    vulnerability_id: str,
    observed_at: str,
    asset_id: Optional[str] = None,
    deployment_id: Optional[str] = None,
    dependency_path: Optional[str] = None,
) -> str:
    """
    Computes deterministic observation ID.
    If source_finding_id is present, uses canonical combination of source + source_finding_id + core keys.
    Otherwise hashes normalized fields and observed_at.
    """
    canonical_payload = {
        "source": source.strip().lower(),
        "source_finding_id": (source_finding_id or "").strip(),
        "ecosystem": ecosystem.strip().lower(),
        "package_name": package_name.strip().lower(),
        "package_version": (package_version or "").strip(),
        "vulnerability_id": vulnerability_id.strip().upper(),
        "observed_at": observed_at.strip(),
        "asset_id": (asset_id or "").strip(),
        "deployment_id": (deployment_id or "").strip(),
        "dependency_path": (dependency_path or "").strip(),
    }
    raw_hash = compute_sha256(_canonical_json(canonical_payload))
    return f"obs-{raw_hash[:16]}"


def compute_issue_key(
    asset_id: Optional[str],
    environment: Optional[str],
    dependency_path: Optional[str],
    vulnerability_id: str,
) -> str:
    """
    Links observations over time for the same asset, environment, component path, and vulnerability.
    """
    canonical = {
        "asset_id": (asset_id or "unassigned-asset").strip(),
        "environment": (environment or "unassigned-env").strip().lower(),
        "dependency_path": (dependency_path or "root").strip(),
        "vulnerability_id": vulnerability_id.strip().upper(),
    }
    raw_hash = compute_sha256(_canonical_json(canonical))
    return f"iss-{raw_hash[:16]}"


def compute_occurrence_key(
    issue_key: str,
    deployment_id: Optional[str],
    package_version: Optional[str],
) -> str:
    """
    Differentiates affected instances across deployments and package versions.
    """
    canonical = {
        "issue_key": issue_key,
        "deployment_id": (deployment_id or "no-deploy").strip(),
        "package_version": (package_version or "no-ver").strip(),
    }
    raw_hash = compute_sha256(_canonical_json(canonical))
    return f"occ-{raw_hash[:16]}"


def compute_fingerprint(
    finding_dict: Dict[str, Any],
    deployment_dict: Optional[Dict[str, Any]],
    advisory_dict: Optional[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
    missing_fields: List[str],
    conflicts: List[str],
) -> str:
    """
    Computes deterministic fingerprint from sorted canonical evidence bundle state.
    """
    # Sort evidence items by evidence_id
    sorted_evidence = sorted(evidence_items, key=lambda x: str(x.get("evidence_id", "")))
    canonical_bundle = {
        "finding": finding_dict,
        "deployment": deployment_dict,
        "advisory": advisory_dict,
        "evidence": sorted_evidence,
        "missing_fields": sorted(missing_fields),
        "conflicts": sorted(conflicts),
    }
    return compute_sha256(_canonical_json(canonical_bundle))


def compute_decision_key(
    occurrence_key: str,
    fingerprint: str,
    policy_version: str,
    model_version: str,
) -> str:
    """
    Ensures idempotent triage re-runs.
    """
    canonical = {
        "occurrence_key": occurrence_key,
        "fingerprint": fingerprint,
        "policy_version": policy_version,
        "model_version": model_version,
    }
    raw_hash = compute_sha256(_canonical_json(canonical))
    return f"dec-{raw_hash[:16]}"
