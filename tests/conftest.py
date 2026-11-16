from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest

from vuln_triage.config import RootConfig, load_config
from vuln_triage.domain.models import (
    AdvisorySnapshot,
    DeploymentSnapshot,
    FindingObservation,
    PackageRef,
    VerificationStatus,
)
from vuln_triage.storage.sqlite import Database


@pytest.fixture
def tmp_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_triage.db"
    db = Database(db_file)
    db.init_db()
    return db


@pytest.fixture
def test_config(tmp_path: Path) -> RootConfig:
    cfg = load_config()
    cfg.app.database_path = str(tmp_path / "app_test.db")
    cfg.app.raw_dir = str(tmp_path / "raw")
    cfg.app.reports_dir = str(tmp_path / "reports")
    cfg.app.datasets_dir = str(tmp_path / "datasets")
    cfg.app.models_dir = str(tmp_path / "models")
    return cfg


@pytest.fixture
def sample_finding() -> FindingObservation:
    dt = datetime(2026, 10, 11, 9, 0, 0, tzinfo=timezone.utc)
    return FindingObservation(
        observation_id="obs-sample-001",
        source="test-scan",
        source_finding_id="scan-001",
        observed_at=dt,
        asset_id="asset-demo-1",
        deployment_id="deploy-demo-1",
        package=PackageRef(
            ecosystem="npm",
            name="demo-package",
            version="1.2.3",
            dependency_path="app > demo-package",
        ),
        vulnerability_id="VULN-DEMO-001",
        raw_ref="test:1",
        scanner_severity="HIGH",
        raw_payload={"observed_at": dt.isoformat(), "scanner_severity": "HIGH"},
    )


@pytest.fixture
def sample_deployment() -> DeploymentSnapshot:
    dt = datetime(2026, 10, 11, 8, 30, 0, tzinfo=timezone.utc)
    return DeploymentSnapshot(
        snapshot_id="snap-deploy-demo-1",
        asset_id="asset-demo-1",
        deployment_id="deploy-demo-1",
        environment="production",
        criticality="high",
        artifact_digest="sha256:abcdef",
        components=[
            {"name": "demo-package", "version": "1.2.3", "ecosystem": "npm"}
        ],
        configuration={"network_facing": False, "waf_enabled": True},
        observed_at=dt,
    )


@pytest.fixture
def sample_advisory() -> AdvisorySnapshot:
    dt = datetime(2026, 10, 11, 8, 0, 0, tzinfo=timezone.utc)
    return AdvisorySnapshot(
        advisory_id="VULN-DEMO-001",
        revision="1",
        retrieved_at=dt,
        content_hash="sha256:12345",
        ecosystem="npm",
        package_name="demo-package",
        affected_ranges=[
            {"type": "SEMVER", "events": [{"introduced": "0.0.0"}, {"fixed": "1.3.0"}]}
        ],
        trigger_conditions=["Unsafe parseXml invocation"],
    )
