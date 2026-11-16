from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from vuln_triage.domain.identity import (
    compute_observation_id,
    compute_sha256,
)
from vuln_triage.domain.models import (
    AdvisorySnapshot,
    DeploymentSnapshot,
    FindingObservation,
    PackageRef,
)
from vuln_triage.ingest.normalize import (
    infer_ecosystem_from_component,
    normalize_ecosystem,
    normalize_string,
    normalize_vulnerability_id,
    parse_iso_datetime,
)


class ImportFailure(BaseModel):
    row_number: int
    raw_data: str
    error_message: str


class ImportResult(BaseModel):
    kind: str
    source: str
    source_path: str
    content_hash: str
    valid_count: int = 0
    failed_count: int = 0
    observations: List[FindingObservation] = Field(default_factory=list)
    deployments: List[DeploymentSnapshot] = Field(default_factory=list)
    advisories: List[AdvisorySnapshot] = Field(default_factory=list)
    failures: List[ImportFailure] = Field(default_factory=list)


MANDATORY_FINDING_COLUMNS = {
    "observed_at",
    "ecosystem",
    "package_name",
    "vulnerability_id",
}

REQUIRED_HEADER_COLUMNS = MANDATORY_FINDING_COLUMNS.union(
    {"asset_id", "deployment_id", "package_version"}
)


def _extract_trigger_conditions(description: str) -> List[str]:
    """Extract obvious conditional trigger phrases from CVE description text."""
    if not description:
        return []
    keywords = [
        "only applications that",
        "workaround",
        "only affects",
        "are not affected",
        "when configured with",
        "if the application",
        "under specific conditions",
        "requires specific",
        "an authenticated user",
        "authenticated attacker",
    ]
    lowered = description.lower()
    conditions = []
    for kw in keywords:
        if kw in lowered:
            conditions.append(kw)
    return conditions


def _parse_jsonl_finding_row(
    item: Dict[str, Any],
    source: str,
    default_tz: Optional[str],
    raw_ref: str,
    row_idx: int,
) -> tuple[FindingObservation, Optional[AdvisorySnapshot]]:
    # Support both standard finding schema and VEX/CVE jsonl schema
    package_name = item.get("package_name") or item.get("component_name")
    if not package_name or not str(package_name).strip():
        raise ValueError(f"Row {row_idx}: component/package name is missing.")
    package_name = str(package_name).strip()

    package_version = item.get("package_version") or item.get("component_version")
    package_version = normalize_string(str(package_version) if package_version is not None else None)

    # Prefer cve_id as vulnerability_id if present, else item["vulnerability_id"]
    cve_id_val = item.get("cve_id")
    raw_vuln_id = item.get("vulnerability_id")
    if cve_id_val and str(cve_id_val).strip():
        vulnerability_id = normalize_vulnerability_id(str(cve_id_val))
        source_finding_id = normalize_string(str(raw_vuln_id) if raw_vuln_id else None)
    elif raw_vuln_id and str(raw_vuln_id).strip():
        vulnerability_id = normalize_vulnerability_id(str(raw_vuln_id))
        source_finding_id = normalize_string(str(item.get("source_finding_id", "")) if item.get("source_finding_id") else None)
    else:
        raise ValueError(f"Row {row_idx}: vulnerability identifier (cve_id or vulnerability_id) is missing.")

    # Ecosystem
    description_val = item.get("description")
    if item.get("ecosystem"):
        ecosystem = normalize_ecosystem(str(item["ecosystem"]))
    else:
        ecosystem = infer_ecosystem_from_component(package_name, description_val or "")

    # Observed at (deterministic default for jsonl if omitted)
    if item.get("observed_at"):
        observed_dt = parse_iso_datetime(str(item["observed_at"]), default_tz=default_tz)
    else:
        observed_dt = parse_iso_datetime("2026-11-16T00:00:00+08:00", default_tz=default_tz)

    asset_id = normalize_string(str(item["asset_id"]) if item.get("asset_id") is not None else f"asset-{package_name.lower()}")
    deployment_id = normalize_string(str(item["deployment_id"]) if item.get("deployment_id") is not None else "deploy-jsonl")

    scanner_severity = normalize_string(str(item["severity"])) if item.get("severity") else normalize_string(str(item.get("scanner_severity") or ""))
    dependency_path = normalize_string(str(item.get("dependency_path", "")) if item.get("dependency_path") else None)
    purl = normalize_string(str(item.get("purl", "")) if item.get("purl") else None)

    package = PackageRef(
        ecosystem=ecosystem,
        name=package_name,
        version=package_version,
        purl=purl,
        dependency_path=dependency_path,
    )

    # If source_finding_id is present, make it uniquely scoped per row or raw_ref to preserve all 935 findings
    finding_id_key = f"{source_finding_id}:{row_idx}" if source_finding_id else f"row-{row_idx}"

    observation_id = compute_observation_id(
        source=source,
        source_finding_id=finding_id_key,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        vulnerability_id=vulnerability_id,
        observed_at=observed_dt.isoformat(),
        asset_id=asset_id,
        deployment_id=deployment_id,
        dependency_path=dependency_path,
    )

    obs = FindingObservation(
        observation_id=observation_id,
        source=source,
        source_finding_id=source_finding_id,
        observed_at=observed_dt,
        asset_id=asset_id,
        deployment_id=deployment_id,
        package=package,
        vulnerability_id=vulnerability_id,
        raw_ref=raw_ref,
        scanner_severity=scanner_severity,
        raw_payload=item,
    )


    # Synthesize AdvisorySnapshot if description or cve_id present
    adv: Optional[AdvisorySnapshot] = None
    if description_val or item.get("cve_id"):
        advisory_id = vulnerability_id
        content_hash = compute_sha256(description_val or advisory_id)
        cvss_score = float(item["cvss_score"]) if item.get("cvss_score") is not None else None
        is_actively_exploited = bool(item.get("is_actively_exploited", False))
        trigger_conditions = _extract_trigger_conditions(description_val or "")

        adv = AdvisorySnapshot(
            advisory_id=advisory_id,
            revision="1",
            source_uri=normalize_string(item.get("source_uri")),
            retrieved_at=observed_dt,
            content_hash=content_hash,
            ecosystem=ecosystem,
            package_name=package_name,
            affected_ranges=[],
            trigger_conditions=trigger_conditions,
            description=description_val,
            cve_id=item.get("cve_id"),
            euvd_id=item.get("euvd_id"),
            cvss_score=cvss_score,
            is_actively_exploited=is_actively_exploited,
        )

    return obs, adv


def import_findings(
    path: str | Path,
    source: str,
    default_tz: Optional[str] = "Asia/Taipei",
) -> ImportResult:
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"File not found: {target_path}")

    raw_bytes = target_path.read_bytes()
    content_hash = compute_sha256(raw_bytes)

    result = ImportResult(
        kind="findings",
        source=source,
        source_path=str(target_path),
        content_hash=content_hash,
    )

    seen_advisories = set()

    suffix = target_path.suffix.lower()
    if suffix == ".csv":
        text_content = raw_bytes.decode("utf-8-sig")
        reader = csv.DictReader(text_content.splitlines())
        if not reader.fieldnames:
            raise ValueError(f"CSV file {target_path} is empty or missing headers.")

        missing_headers = REQUIRED_HEADER_COLUMNS - set(reader.fieldnames)
        if missing_headers:
            raise ValueError(
                f"CSV header missing required columns: {sorted(missing_headers)}"
            )

        for row_idx, row in enumerate(reader, start=2):
            try:
                obs = _parse_finding_dict(row, source, default_tz, raw_ref=f"{target_path.name}:{row_idx}")
                result.observations.append(obs)
                result.valid_count += 1
            except Exception as e:
                result.failures.append(
                    ImportFailure(
                        row_number=row_idx,
                        raw_data=json.dumps(row, ensure_ascii=False),
                        error_message=str(e),
                    )
                )
                result.failed_count += 1

    elif suffix == ".json":
        text_content = raw_bytes.decode("utf-8")
        data = json.loads(text_content)
        if not isinstance(data, list):
            raise ValueError("Findings JSON must contain a top-level list of finding objects.")

        for row_idx, item in enumerate(data, start=1):
            try:
                if not isinstance(item, dict):
                    raise ValueError(f"Row {row_idx} is not a valid JSON object.")
                obs = _parse_finding_dict(item, source, default_tz, raw_ref=f"{target_path.name}:{row_idx}")
                result.observations.append(obs)
                result.valid_count += 1
            except Exception as e:
                result.failures.append(
                    ImportFailure(
                        row_number=row_idx,
                        raw_data=json.dumps(item, ensure_ascii=False) if isinstance(item, dict) else str(item),
                        error_message=str(e),
                    )
                )
                result.failed_count += 1

    elif suffix == ".jsonl":
        text_content = raw_bytes.decode("utf-8")
        for row_idx, line in enumerate(text_content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
                if not isinstance(item, dict):
                    raise ValueError(f"Line {row_idx} is not a valid JSON object.")

                # If the item has the standard finding format without component_name, fallback
                if "component_name" in item or "cve_id" in item:
                    obs, adv = _parse_jsonl_finding_row(item, source, default_tz, raw_ref=f"{target_path.name}:{row_idx}", row_idx=row_idx)
                else:
                    obs = _parse_finding_dict(item, source, default_tz, raw_ref=f"{target_path.name}:{row_idx}")
                    adv = None

                result.observations.append(obs)
                result.valid_count += 1

                if adv and adv.advisory_id not in seen_advisories:
                    seen_advisories.add(adv.advisory_id)
                    result.advisories.append(adv)

            except Exception as e:
                result.failures.append(
                    ImportFailure(
                        row_number=row_idx,
                        raw_data=stripped,
                        error_message=str(e),
                    )
                )
                result.failed_count += 1

    else:
        raise ValueError(f"Unsupported findings file format '{suffix}'. Supported formats: .csv, .json, .jsonl")

    return result


def _parse_finding_dict(
    row: Dict[str, Any],
    source: str,
    default_tz: Optional[str],
    raw_ref: str,
) -> FindingObservation:
    for col in MANDATORY_FINDING_COLUMNS:
        val = row.get(col)
        if val is None or (isinstance(val, str) and not val.strip()):
            raise ValueError(f"Mandatory field '{col}' is missing or empty.")

    raw_observed_at = str(row["observed_at"]).strip()
    observed_dt = parse_iso_datetime(raw_observed_at, default_tz=default_tz)

    ecosystem = normalize_ecosystem(str(row["ecosystem"]))
    package_name = str(row["package_name"]).strip()
    vulnerability_id = normalize_vulnerability_id(str(row["vulnerability_id"]))

    asset_id = normalize_string(str(row["asset_id"]) if row.get("asset_id") is not None else None)
    deployment_id = normalize_string(str(row["deployment_id"]) if row.get("deployment_id") is not None else None)
    package_version = normalize_string(str(row["package_version"]) if row.get("package_version") is not None else None)

    source_finding_id = normalize_string(str(row.get("source_finding_id", "")) if row.get("source_finding_id") else None)
    dependency_path = normalize_string(str(row.get("dependency_path", "")) if row.get("dependency_path") else None)
    purl = normalize_string(str(row.get("purl", "")) if row.get("purl") else None)
    scanner_severity = normalize_string(str(row.get("scanner_severity", "")) if row.get("scanner_severity") else None)

    package = PackageRef(
        ecosystem=ecosystem,
        name=package_name,
        version=package_version,
        purl=purl,
        dependency_path=dependency_path,
    )

    observation_id = compute_observation_id(
        source=source,
        source_finding_id=source_finding_id,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        vulnerability_id=vulnerability_id,
        observed_at=observed_dt.isoformat(),
        asset_id=asset_id,
        deployment_id=deployment_id,
        dependency_path=dependency_path,
    )

    return FindingObservation(
        observation_id=observation_id,
        source=source,
        source_finding_id=source_finding_id,
        observed_at=observed_dt,
        asset_id=asset_id,
        deployment_id=deployment_id,
        package=package,
        vulnerability_id=vulnerability_id,
        raw_ref=raw_ref,
        scanner_severity=scanner_severity,
        raw_payload=row,
    )


def import_deployments(
    path: str | Path,
    default_tz: Optional[str] = "Asia/Taipei",
) -> ImportResult:
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"File not found: {target_path}")

    raw_bytes = target_path.read_bytes()
    content_hash = compute_sha256(raw_bytes)
    data = json.loads(raw_bytes.decode("utf-8"))

    if not isinstance(data, list):
        raise ValueError("Deployments JSON must contain a top-level list of deployment objects.")

    result = ImportResult(
        kind="deployments",
        source="manual",
        source_path=str(target_path),
        content_hash=content_hash,
    )

    for row_idx, item in enumerate(data, start=1):
        try:
            observed_dt = parse_iso_datetime(str(item["observed_at"]), default_tz=default_tz)
            snapshot = DeploymentSnapshot(
                snapshot_id=str(item.get("snapshot_id", f"snap-deploy-{row_idx}")),
                asset_id=str(item["asset_id"]),
                deployment_id=str(item["deployment_id"]),
                environment=str(item.get("environment", "unknown")),
                criticality=str(item.get("criticality", "standard")),
                artifact_digest=normalize_string(item.get("artifact_digest")),
                components=item.get("components", []),
                configuration=item.get("configuration", {}),
                observed_at=observed_dt,
            )
            result.deployments.append(snapshot)
            result.valid_count += 1
        except Exception as e:
            result.failures.append(
                ImportFailure(
                    row_number=row_idx,
                    raw_data=json.dumps(item, ensure_ascii=False),
                    error_message=str(e),
                )
            )
            result.failed_count += 1

    return result


def import_advisories(
    path: str | Path,
    default_tz: Optional[str] = "Asia/Taipei",
) -> ImportResult:
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"File not found: {target_path}")

    raw_bytes = target_path.read_bytes()
    content_hash = compute_sha256(raw_bytes)
    data = json.loads(raw_bytes.decode("utf-8"))

    if not isinstance(data, list):
        raise ValueError("Advisories JSON must contain a top-level list of advisory objects.")

    result = ImportResult(
        kind="advisories",
        source="manual",
        source_path=str(target_path),
        content_hash=content_hash,
    )

    for row_idx, item in enumerate(data, start=1):
        try:
            retrieved_dt = parse_iso_datetime(str(item["retrieved_at"]), default_tz=default_tz)
            adv = AdvisorySnapshot(
                advisory_id=normalize_vulnerability_id(str(item["advisory_id"])),
                revision=str(item.get("revision", "1")),
                source_uri=normalize_string(item.get("source_uri")),
                retrieved_at=retrieved_dt,
                content_hash=str(item.get("content_hash", compute_sha256(json.dumps(item)))),
                ecosystem=normalize_ecosystem(str(item["ecosystem"])) if item.get("ecosystem") else None,
                package_name=normalize_string(item.get("package_name")),
                affected_ranges=item.get("affected_ranges", []),
                trigger_conditions=item.get("trigger_conditions", []),
            )
            result.advisories.append(adv)
            result.valid_count += 1
        except Exception as e:
            result.failures.append(
                ImportFailure(
                    row_number=row_idx,
                    raw_data=json.dumps(item, ensure_ascii=False),
                    error_message=str(e),
                )
            )
            result.failed_count += 1

    return result
