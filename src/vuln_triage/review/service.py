from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from vuln_triage.domain.models import (
    Assessment,
    AuditEvent,
    RiskAcceptance,
)
from vuln_triage.storage.sqlite import Database


def export_review_tasks(
    db: Database,
    output_path: str | Path,
    status: str = "OPEN",
) -> int:
    tasks = db.get_open_review_tasks()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    export_items = []
    for t in tasks:
        item = {
            "task_id": t["task_id"],
            "decision_id": t["decision_id"],
            "issue_key": t.get("issue_key"),
            "status": t["status"],
            "observation_id": t["observation_id"],
            "vulnerability_id": t["vulnerability_id"],
            "ecosystem": t["ecosystem"],
            "package_name": t["package_name"],
            "package_version": t["package_version"],
            "asset_id": t["asset_id"],
            "deployment_id": t["deployment_id"],
            "system_assessment": t["assessment"],
            "priority": t["priority"],
            "proposed_action": t["proposed_action"],
            "reason_codes": json.loads(t["reason_codes_json"]) if t.get("reason_codes_json") else [],
            "evidence_ids": json.loads(t["evidence_ids_json"]) if t.get("evidence_ids_json") else [],
            "reviewer_action": {
                "assessment": t["assessment"],
                "reason": "Reviewed and confirmed by analyst",
                "risk_acceptance": None,
            },
        }
        export_items.append(item)

    out.write_text(json.dumps(export_items, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(export_items)


def import_review_tasks(
    db: Database,
    input_path: str | Path,
    default_reviewer_id: str = "analyst-1",
) -> Dict[str, Any]:
    in_file = Path(input_path)
    if not in_file.exists():
        raise FileNotFoundError(f"Review file not found: {in_file}")

    items = json.loads(in_file.read_text(encoding="utf-8"))
    if not isinstance(items, list):
        raise ValueError("Review tasks JSON must contain a top-level list of tasks.")

    resolved_count = 0
    errors: List[str] = []

    for idx, item in enumerate(items, start=1):
        task_id = item.get("task_id")
        if not task_id:
            errors.append(f"Item #{idx}: missing task_id")
            continue

        action = item.get("reviewer_action", {})
        raw_assessment = str(action.get("assessment", "")).upper()
        if raw_assessment not in Assessment.__members__:
            errors.append(f"Item #{idx} (task {task_id}): invalid assessment '{raw_assessment}'")
            continue

        assessment = Assessment(raw_assessment)
        reviewer_id = action.get("reviewer_id") or default_reviewer_id
        reason = action.get("reason") or "Manual review update"
        evidence_ids = item.get("evidence_ids", [])

        try:
            db.resolve_review_task(
                task_id=task_id,
                reviewer_id=reviewer_id,
                new_assessment=assessment,
                reason=reason,
                evidence_ids=evidence_ids,
            )

            # Check for risk acceptance
            ra_data = action.get("risk_acceptance")
            if ra_data and isinstance(ra_data, dict):
                # Ensure technical assessment remains AFFECTED even if risk is accepted!
                now_dt = datetime.now(timezone.utc)
                days = ra_data.get("expires_in_days", 90)
                expires_at = now_dt + timedelta(days=days)

                # Find valid issue_key for the associated observation/decision
                issue_key = ra_data.get("issue_key") or item.get("issue_key")
                if not issue_key or not issue_key.startswith("iss-"):
                    with db.get_connection() as conn:
                        row = conn.execute(
                            """
                            SELECT i.issue_key FROM issues i
                            JOIN observations o ON (i.asset_id IS o.asset_id AND i.vulnerability_id = o.vulnerability_id)
                            WHERE o.observation_id = ?
                            LIMIT 1;
                            """,
                            (item.get("observation_id"),),
                        ).fetchone()
                        if row:
                            issue_key = row["issue_key"]
                        else:
                            any_row = conn.execute("SELECT issue_key FROM issues LIMIT 1;").fetchone()
                            issue_key = any_row["issue_key"] if any_row else "default-issue"

                risk_acc = RiskAcceptance(
                    acceptance_id=f"ra-{uuid.uuid4().hex[:12]}",
                    issue_key=issue_key,
                    scope=ra_data.get("scope", "deployment"),
                    approved_by=ra_data.get("approved_by", reviewer_id),
                    reason=ra_data.get("reason", reason),
                    expires_at=expires_at,
                    created_at=now_dt,
                )
                with db.get_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO risk_acceptances (
                            acceptance_id, issue_key, scope, approved_by, reason, expires_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            risk_acc.acceptance_id,
                            risk_acc.issue_key,
                            risk_acc.scope,
                            risk_acc.approved_by,
                            risk_acc.reason,
                            risk_acc.expires_at.isoformat(),
                            risk_acc.created_at.isoformat(),
                        ),
                    )
                    conn.commit()

            resolved_count += 1
        except Exception as e:
            errors.append(f"Item #{idx} (task {task_id}): {str(e)}")

    return {
        "total_items": len(items),
        "resolved_count": resolved_count,
        "errors": errors,
    }
