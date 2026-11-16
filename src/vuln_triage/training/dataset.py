from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from vuln_triage.storage.sqlite import Database


def export_dataset(
    db: Database,
    output_path: str | Path,
    selection: str = "human-verified",
) -> Dict[str, Any]:
    """
    Exports audited or rule-verified triage dataset for offline training or evaluation.
    Enforces separation between human_verified and synthetic/candidate data.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with db.get_connection() as conn:
        if selection == "human-verified":
            rows = conn.execute(
                """
                SELECT a.audit_id, a.decision_id, a.reviewer_id, a.reviewed_at, a.assessment,
                       a.reason, a.evidence_ids_json,
                       d.occurrence_key, d.fingerprint, d.priority, d.policy_version,
                       o.ecosystem, o.package_name, o.package_version, o.vulnerability_id,
                       o.asset_id, o.deployment_id
                FROM audit_events a
                JOIN decisions d ON a.decision_id = d.decision_id
                JOIN observations o ON d.observation_id = o.observation_id
                ORDER BY a.reviewed_at ASC;
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT d.decision_id, d.occurrence_key, d.fingerprint, d.assessment,
                       d.priority, d.policy_version, d.created_at,
                       o.ecosystem, o.package_name, o.package_version, o.vulnerability_id,
                       o.asset_id, o.deployment_id
                FROM decisions d
                JOIN observations o ON d.observation_id = o.observation_id
                ORDER BY d.created_at ASC;
                """
            ).fetchall()

    records: List[Dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        item["provenance"] = "human_verified" if "audit_id" in item else "rule_verified"
        if "evidence_ids_json" in item and item["evidence_ids_json"]:
            item["evidence_ids"] = json.loads(item["evidence_ids_json"])
        records.append(item)

    manifest = {
        "manifest_version": "1.0.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "selection_mode": selection,
        "sample_count": len(records),
        "records": records,
    }

    out_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return {
        "sample_count": len(records),
        "output_path": str(out_file),
    }
