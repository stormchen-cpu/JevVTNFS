from __future__ import annotations

import json
from pathlib import Path
import pytest

from vuln_triage.config import RootConfig
from vuln_triage.domain.models import Assessment, RunMode
from vuln_triage.ingest.readers import import_advisories, import_deployments, import_findings
from vuln_triage.review.service import export_review_tasks, import_review_tasks
from vuln_triage.storage.sqlite import Database
from vuln_triage.workflow.service import TriageService


def test_review_export_and_import_workflow(test_config: RootConfig, tmp_path: Path):
    db = Database(test_config.app.database_path)
    db.init_db()

    # Import fixtures
    db.save_import(import_deployments("examples/products.json"))
    db.save_import(import_advisories("examples/advisories.json"))
    db.save_import(import_findings("examples/findings.csv", source="generic"))

    service = TriageService(test_config, db=db)
    service.run_batch("batch-rev-test", mode=RunMode.SHADOW)

    # Export open review tasks
    export_file = tmp_path / "review_tasks.json"
    count = export_review_tasks(db, export_file, status="OPEN")
    assert count >= 2  # The 2 incomplete findings in findings.csv (missing version and missing asset)
    assert export_file.exists()

    tasks_data = json.loads(export_file.read_text(encoding="utf-8"))
    assert len(tasks_data) == count

    # Simulate analyst reviewing and changing assessment
    target_task = tasks_data[0]
    target_task["reviewer_action"] = {
        "assessment": "NOT_AFFECTED",
        "reason": "Confirmed by analyst that package is in non-vulnerable dead code path.",
        "reviewer_id": "security_analyst_alice",
        "risk_acceptance": None,
    }

    modified_file = tmp_path / "review_completed.json"
    modified_file.write_text(json.dumps([target_task]), encoding="utf-8")

    import_res = import_review_tasks(db, modified_file)
    assert import_res["resolved_count"] == 1
    assert len(import_res["errors"]) == 0

    # Verify audit event was recorded in DB
    with db.get_connection() as conn:
        audits = conn.execute("SELECT * FROM audit_events WHERE decision_id = ?;", (target_task["decision_id"],)).fetchall()
        assert len(audits) == 1
        assert audits[0]["reviewer_id"] == "security_analyst_alice"
        assert audits[0]["assessment"] == "NOT_AFFECTED"

    # Attempting to re-resolve the same task should report error
    second_import = import_review_tasks(db, modified_file)
    assert second_import["resolved_count"] == 0
    assert len(second_import["errors"]) == 1
    assert "already been resolved" in second_import["errors"][0]


def test_risk_acceptance_preserves_affected_assessment(test_config: RootConfig, tmp_path: Path):
    db = Database(test_config.app.database_path)
    db.init_db()

    db.save_import(import_deployments("examples/products.json"))
    db.save_import(import_advisories("examples/advisories.json"))
    db.save_import(import_findings("examples/findings.csv", source="generic"))

    service = TriageService(test_config, db=db)
    service.run_batch("batch-ra-test", mode=RunMode.SHADOW)

    export_file = tmp_path / "ra_review.json"
    export_review_tasks(db, export_file, status="OPEN")
    tasks = json.loads(export_file.read_text(encoding="utf-8"))

    # Set risk acceptance
    task = tasks[0]
    task["reviewer_action"] = {
        "assessment": "AFFECTED",
        "reason": "Technical vulnerability confirmed, but postponed until next quarterly release.",
        "reviewer_id": "lead_bob",
        "risk_acceptance": {
            "scope": "asset-demo-1",
            "approved_by": "lead_bob",
            "expires_in_days": 60,
        },
    }

    completed_file = tmp_path / "ra_completed.json"
    completed_file.write_text(json.dumps([task]), encoding="utf-8")

    res = import_review_tasks(db, completed_file)
    assert res["resolved_count"] == 1

    with db.get_connection() as conn:
        dec = conn.execute("SELECT assessment FROM decisions WHERE decision_id = ?;", (task["decision_id"],)).fetchone()
        assert dec["assessment"] == "AFFECTED"

        ra = conn.execute("SELECT * FROM risk_acceptances;").fetchone()
        assert ra is not None
        assert ra["approved_by"] == "lead_bob"
