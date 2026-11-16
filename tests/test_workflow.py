from __future__ import annotations

from pathlib import Path
import pytest

from vuln_triage.config import RootConfig
from vuln_triage.domain.models import RunMode
from vuln_triage.ingest.readers import import_advisories, import_deployments, import_findings
from vuln_triage.storage.sqlite import Database
from vuln_triage.workflow.service import TriageService


def test_workflow_batch_execution_and_idempotency(test_config: RootConfig):
    db = Database(test_config.app.database_path)
    db.init_db()

    # Import test fixtures
    dep_res = import_deployments("examples/products.json")
    db.save_import(dep_res)

    adv_res = import_advisories("examples/advisories.json")
    db.save_import(adv_res)

    find_res = import_findings("examples/findings.csv", source="generic")
    db.save_import(find_res)

    service = TriageService(test_config, db=db)

    # First run in shadow mode
    summary_1 = service.run_batch("batch-001", mode=RunMode.SHADOW)
    assert summary_1.total_processed == 4
    assert summary_1.succeeded == 4
    assert summary_1.skipped_idempotent == 0
    assert summary_1.failed == 0

    # Verify no ACTIVE suppressions in shadow mode
    with db.get_connection() as conn:
        active_sups = conn.execute("SELECT COUNT(*) as c FROM suppressions WHERE status = 'ACTIVE';").fetchone()["c"]
        assert active_sups == 0

    # Second run with exact same batch: should be 100% idempotent skipped
    summary_2 = service.run_batch("batch-001", mode=RunMode.SHADOW)
    assert summary_2.total_processed == 4
    assert summary_2.succeeded == 0
    assert summary_2.skipped_idempotent == 4


def test_reevaluation_revokes_active_suppression(test_config: RootConfig):
    db = Database(test_config.app.database_path)
    db.init_db()

    dep_res = import_deployments("examples/products.json")
    db.save_import(dep_res)

    adv_res = import_advisories("examples/advisories.json")
    db.save_import(adv_res)

    find_res = import_findings("examples/findings.csv", source="generic")
    db.save_import(find_res)

    service = TriageService(test_config, db=db)

    # Run in ACTIVE mode: unaffected findings create ACTIVE suppressions
    summary_active = service.run_batch("batch-active", mode=RunMode.ACTIVE)
    assert summary_active.succeeded >= 1

    with db.get_connection() as conn:
        active_sups = conn.execute("SELECT * FROM suppressions WHERE status = 'ACTIVE';").fetchall()
        assert len(active_sups) > 0
        target_issue = active_sups[0]["issue_key"]

    # Trigger re-evaluation
    res = service.reevaluate(issue_key=target_issue, cause="deployment_changed")
    assert res.revoked_suppressions >= 1

    # Check suppression status changed to REVOKED
    with db.get_connection() as conn:
        revoked = conn.execute("SELECT COUNT(*) as c FROM suppressions WHERE status = 'REVOKED';").fetchone()["c"]
        assert revoked >= 1
