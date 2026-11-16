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
    else:
        raise ValueError(f"Unsupported findings file format '{suffix}'. Supported formats: .csv, .json")

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
