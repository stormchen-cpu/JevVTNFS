from __future__ import annotations

import json
from pathlib import Path
import pytest

from vuln_triage.ingest.normalize import parse_iso_datetime
from vuln_triage.ingest.readers import import_findings


def test_csv_and_json_produce_identical_observations(tmp_path: Path):
    csv_file = Path("examples/findings.csv")
    json_file = Path("examples/findings.json")

    res_csv = import_findings(csv_file, source="test-source")
    res_json = import_findings(json_file, source="test-source")

    assert res_csv.valid_count == res_json.valid_count
    assert res_csv.valid_count == 4

    for obs_csv, obs_json in zip(res_csv.observations, res_json.observations):
        assert obs_csv.package.name == obs_json.package.name
        assert obs_csv.package.version == obs_json.package.version
        assert obs_csv.vulnerability_id == obs_json.vulnerability_id
        assert obs_csv.asset_id == obs_json.asset_id
        assert obs_csv.deployment_id == obs_json.deployment_id
        assert obs_csv.observation_id == obs_json.observation_id


def test_corrupt_row_does_not_drop_valid_rows(tmp_path: Path):
    corrupt_csv = tmp_path / "corrupt.csv"
    corrupt_csv.write_text(
        "observed_at,asset_id,deployment_id,ecosystem,package_name,package_version,vulnerability_id\n"
        "2026-10-11T09:00:00+08:00,asset-1,deploy-1,npm,good-pkg,1.0.0,CVE-2026-001\n"
        "INVALID_DATETIME_FORMAT,asset-2,deploy-2,npm,bad-pkg,1.0.0,CVE-2026-002\n"
        "2026-10-11T09:00:00+08:00,asset-3,deploy-3,npm,another-good-pkg,2.0.0,CVE-2026-003\n",
        encoding="utf-8",
    )

    res = import_findings(corrupt_csv, source="test-source")
    assert res.valid_count == 2
    assert res.failed_count == 1
    assert len(res.failures) == 1
    assert res.failures[0].row_number == 3
    assert "good-pkg" in [o.package.name for o in res.observations]
    assert "another-good-pkg" in [o.package.name for o in res.observations]


def test_missing_mandatory_field_causes_row_failure(tmp_path: Path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text(
        json.dumps([
            {
                "observed_at": "2026-10-11T09:00:00+08:00",
                "ecosystem": "npm",
                # missing package_name
                "vulnerability_id": "CVE-2026-001",
            },
            {
                "observed_at": "2026-10-11T09:00:00+08:00",
                "ecosystem": "npm",
                "package_name": "valid-lib",
                "vulnerability_id": "CVE-2026-002",
            }
        ]),
        encoding="utf-8",
    )

    res = import_findings(bad_json, source="test")
    assert res.valid_count == 1
    assert res.failed_count == 1
    assert "package_name" in res.failures[0].error_message


def test_datetime_without_timezone_fails_when_no_default_tz():
    with pytest.raises(ValueError, match="lacks timezone"):
        parse_iso_datetime("2026-10-11T09:00:00", default_tz=None)
