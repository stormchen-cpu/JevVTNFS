from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid

from vuln_triage.domain.models import (
    AdvisorySnapshot,
    Assessment,
    AuditEvent,
    DeploymentSnapshot,
    FindingObservation,
    PackageRef,
    PolicyDecision,
    Prediction,
    ProposedAction,
    RiskAcceptance,
    RunMode,
)
from vuln_triage.ingest.normalize import parse_iso_datetime
from vuln_triage.ingest.readers import ImportResult
from vuln_triage.privacy.egress import EgressEvent


class Database:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def init_db(self) -> None:
        """Applies all migrations in sorted order."""
        migrations_dir = Path(__file__).parent / "migrations"
        migration_files = sorted(migrations_dir.glob("*.sql"))

        with self.get_connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);"
            )
            applied = {
                row["version"]
                for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
            }

            for m_file in migration_files:
                # e.g., 001_initial.sql -> version 1
                prefix = m_file.name.split("_")[0]
                version = int(prefix)
                if version not in applied:
                    sql_content = m_file.read_text(encoding="utf-8")
                    conn.executescript(sql_content)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?);",
                        (version, datetime.now(timezone.utc).isoformat()),
                    )
            conn.commit()

    def get_import_by_hash(self, content_hash: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM imports WHERE content_hash = ? LIMIT 1;", (content_hash,)
            ).fetchone()
            return dict(row) if row else None

    def save_import(self, result: ImportResult) -> str:
        import_id = f"imp-{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO imports (import_id, source, kind, source_path, content_hash, valid_count, failed_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    import_id,
                    result.source,
                    result.kind,
                    result.source_path,
                    result.content_hash,
                    result.valid_count,
                    result.failed_count,
                    now_str,
                ),
            )

            if result.kind == "findings":
                for obs in result.observations:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO observations (
                            observation_id, import_id, source, source_finding_id, observed_at,
                            ecosystem, package_name, package_version, vulnerability_id,
                            asset_id, deployment_id, dependency_path, scanner_severity,
                            raw_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            obs.observation_id,
                            import_id,
                            obs.source,
                            obs.source_finding_id,
                            obs.observed_at.isoformat(),
                            obs.package.ecosystem,
                            obs.package.name,
                            obs.package.version,
                            obs.vulnerability_id,
                            obs.asset_id,
                            obs.deployment_id,
                            obs.package.dependency_path,
                            obs.scanner_severity,
                            json.dumps(obs.raw_payload or {}, ensure_ascii=False),
                            now_str,
                        ),
                    )

            elif result.kind == "deployments":
                for dep in result.deployments:
                    identifier = f"{dep.asset_id}:{dep.deployment_id}"
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO snapshots (
                            snapshot_id, snapshot_type, identifier, content_hash, data_json, observed_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            dep.snapshot_id,
                            "deployment",
                            identifier,
                            result.content_hash,
                            json.dumps(dep.model_dump(mode="json"), ensure_ascii=False),
                            dep.observed_at.isoformat(),
                            now_str,
                        ),
                    )

            elif result.kind == "advisories":
                for adv in result.advisories:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO snapshots (
                            snapshot_id, snapshot_type, identifier, content_hash, data_json, observed_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            f"adv-{adv.advisory_id}",
                            "advisory",
                            adv.advisory_id,
                            adv.content_hash,
                            json.dumps(adv.model_dump(mode="json"), ensure_ascii=False),
                            adv.retrieved_at.isoformat(),
                            now_str,
                        ),
                    )

            conn.commit()
        return import_id

    def get_deployment_snapshot(
        self, asset_id: Optional[str], deployment_id: Optional[str]
    ) -> Optional[DeploymentSnapshot]:
        if not asset_id or not deployment_id:
            return None
        identifier = f"{asset_id}:{deployment_id}"
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM snapshots WHERE snapshot_type = 'deployment' AND identifier = ? ORDER BY observed_at DESC LIMIT 1;",
                (identifier,),
            ).fetchone()
            if not row:
                return None
            data = json.loads(row["data_json"])
            data["observed_at"] = parse_iso_datetime(data["observed_at"])
            return DeploymentSnapshot(**data)

    def get_advisory_snapshot(self, vulnerability_id: str) -> Optional[AdvisorySnapshot]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM snapshots WHERE snapshot_type = 'advisory' AND identifier = ? ORDER BY observed_at DESC LIMIT 1;",
                (vulnerability_id.upper(),),
            ).fetchone()
            if not row:
                return None
            data = json.loads(row["data_json"])
            data["retrieved_at"] = parse_iso_datetime(data["retrieved_at"])
            return AdvisorySnapshot(**data)

    def get_observations(self, import_id: Optional[str] = None) -> List[FindingObservation]:
        with self.get_connection() as conn:
            if import_id:
                rows = conn.execute(
                    "SELECT * FROM observations WHERE import_id = ? ORDER BY observed_at ASC;",
                    (import_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM observations ORDER BY observed_at ASC;"
                ).fetchall()

            observations: List[FindingObservation] = []
            for r in rows:
                raw_payload = json.loads(r["raw_json"]) if r["raw_json"] else {}
                package = PackageRef(
                    ecosystem=r["ecosystem"],
                    name=r["package_name"],
                    version=r["package_version"],
                    purl=raw_payload.get("purl"),
                    dependency_path=r["dependency_path"],
                )
                obs = FindingObservation(
                    observation_id=r["observation_id"],
                    source=r["source"],
                    source_finding_id=r["source_finding_id"],
                    observed_at=parse_iso_datetime(r["observed_at"]),
                    asset_id=r["asset_id"],
                    deployment_id=r["deployment_id"],
                    package=package,
                    vulnerability_id=r["vulnerability_id"],
                    raw_ref=f"obs:{r['observation_id']}",
                    scanner_severity=r["scanner_severity"],
                    raw_payload=raw_payload,
                )
                observations.append(obs)
            return observations

    def get_decision_by_key(self, decision_key: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM decisions WHERE decision_key = ? LIMIT 1;",
                (decision_key,),
            ).fetchone()
            return dict(row) if row else None

    def save_triage_decision(
        self,
        run_id: str,
        batch_id: str,
        observation: FindingObservation,
        decision: PolicyDecision,
        mode: RunMode,
        occurrence_key: str,
        decision_key: str,
        fingerprint: str,
        issue_key: str,
    ) -> None:
        """
        Saves run status, decision, review task (if human review needed),
        and updates issue/suppression within a single atomic transaction.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        expires_at_str = decision.expires_at.isoformat() if decision.expires_at else None

        with self.get_connection() as conn:
            # 1. Update or Insert issue
            conn.execute(
                """
                INSERT INTO issues (issue_key, asset_id, vulnerability_id, status, first_seen, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(issue_key) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at;
                """,
                (
                    issue_key,
                    observation.asset_id,
                    observation.vulnerability_id,
                    "OPEN",
                    observation.observed_at.isoformat(),
                    now_str,
                    now_str,
                ),
            )

            # 2. Insert or update triage_run
            conn.execute(
                """
                INSERT OR REPLACE INTO triage_runs (
                    run_id, batch_id, observation_id, mode, status, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    run_id,
                    batch_id,
                    observation.observation_id,
                    mode.value,
                    "SUCCEEDED",
                    now_str,
                    now_str,
                ),
            )

            # 3. Insert decision (idempotent on decision_key)
            conn.execute(
                """
                INSERT OR REPLACE INTO decisions (
                    decision_id, run_id, observation_id, occurrence_key, decision_key,
                    fingerprint, assessment, priority, proposed_action, reason_codes_json,
                    evidence_ids_json, policy_version, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    decision.decision_id,
                    run_id,
                    observation.observation_id,
                    occurrence_key,
                    decision_key,
                    fingerprint,
                    decision.assessment.value,
                    decision.priority,
                    decision.proposed_action.value,
                    json.dumps(decision.reason_codes, ensure_ascii=False),
                    json.dumps(decision.evidence_ids, ensure_ascii=False),
                    decision.policy_version,
                    expires_at_str,
                    now_str,
                ),
            )

            # 4. If proposed action is HUMAN_REVIEW, insert review task
            if decision.proposed_action == ProposedAction.HUMAN_REVIEW:
                task_id = f"rev-{uuid.uuid4().hex[:12]}"
                conn.execute(
                    """
                    INSERT INTO review_tasks (
                        task_id, decision_id, observation_id, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        task_id,
                        decision.decision_id,
                        observation.observation_id,
                        "OPEN",
                        now_str,
                        now_str,
                    ),
                )

            # 5. If ACTIVE mode and assessment is NOT_AFFECTED and SUPPRESS_UNTIL, create suppression
            if mode == RunMode.ACTIVE and decision.assessment == Assessment.NOT_AFFECTED and expires_at_str:
                suppression_id = f"sup-{uuid.uuid4().hex[:12]}"
                conn.execute(
                    """
                    INSERT INTO suppressions (
                        suppression_id, issue_key, occurrence_key, status, reason, expires_at, evidence_fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        suppression_id,
                        issue_key,
                        occurrence_key,
                        "ACTIVE",
                        ";".join(decision.reason_codes),
                        expires_at_str,
                        fingerprint,
                        now_str,
                    ),
                )

            conn.commit()

    def get_open_review_tasks(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT r.task_id, r.decision_id, r.status, r.created_at,
                       d.assessment, d.priority, d.proposed_action, d.reason_codes_json, d.evidence_ids_json,
                       o.observation_id, o.asset_id, o.deployment_id, o.ecosystem, o.package_name, o.package_version, o.vulnerability_id,
                       i.issue_key
                FROM review_tasks r
                JOIN decisions d ON r.decision_id = d.decision_id
                JOIN observations o ON r.observation_id = o.observation_id
                LEFT JOIN issues i ON (i.asset_id IS o.asset_id AND i.vulnerability_id = o.vulnerability_id)
                WHERE r.status = 'OPEN'
                ORDER BY r.created_at ASC;
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def resolve_review_task(
        self,
        task_id: str,
        reviewer_id: str,
        new_assessment: Assessment,
        reason: str,
        evidence_ids: List[str],
    ) -> AuditEvent:
        now_str = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            task = conn.execute(
                "SELECT * FROM review_tasks WHERE task_id = ?;", (task_id,)
            ).fetchone()
            if not task:
                raise ValueError(f"Review task '{task_id}' not found.")
            if task["status"] == "RESOLVED":
                raise ValueError(f"Review task '{task_id}' has already been resolved.")

            decision_id = task["decision_id"]
            audit_id = f"aud-{uuid.uuid4().hex[:12]}"

            # Record AuditEvent
            conn.execute(
                """
                INSERT INTO audit_events (
                    audit_id, decision_id, reviewer_id, reviewed_at, assessment, reason, evidence_ids_json, supersedes_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    audit_id,
                    decision_id,
                    reviewer_id,
                    now_str,
                    new_assessment.value,
                    reason,
                    json.dumps(evidence_ids, ensure_ascii=False),
                    decision_id,
                ),
            )

            # Update review task status
            conn.execute(
                """
                UPDATE review_tasks
                SET status = 'RESOLVED', assigned_to = ?, resolution_notes = ?, updated_at = ?
                WHERE task_id = ?;
                """,
                (reviewer_id, reason, now_str, task_id),
            )

            # Update decision assessment
            conn.execute(
                """
                UPDATE decisions
                SET assessment = ?
                WHERE decision_id = ?;
                """,
                (new_assessment.value, decision_id),
            )

            conn.commit()

        return AuditEvent(
            audit_id=audit_id,
            decision_id=decision_id,
            reviewer_id=reviewer_id,
            reviewed_at=datetime.fromisoformat(now_str),
            assessment=new_assessment,
            reason=reason,
            evidence_ids=evidence_ids,
            supersedes_id=decision_id,
        )

    def save_egress_event(self, event: EgressEvent) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO egress_events (
                    event_id, run_id, provider, model, request_hash, status,
                    allowed_fields_json, stripped_fields_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.event_id,
                    event.run_id,
                    event.provider,
                    event.model,
                    event.request_hash,
                    event.status,
                    json.dumps(event.allowed_fields, ensure_ascii=False),
                    json.dumps(event.stripped_fields, ensure_ascii=False),
                    event.created_at,
                ),
            )
            conn.commit()

    def get_decisions_for_reporting(self, batch_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            query = """
                SELECT d.decision_id, d.run_id, d.occurrence_key, d.assessment, d.priority,
                       d.proposed_action, d.reason_codes_json, d.created_at,
                       o.observation_id, o.asset_id, o.deployment_id, o.ecosystem,
                       o.package_name, o.package_version, o.vulnerability_id, o.scanner_severity,
                       t.batch_id, t.mode
                FROM decisions d
                JOIN observations o ON d.observation_id = o.observation_id
                JOIN triage_runs t ON d.run_id = t.run_id
            """
            params: List[Any] = []
            if batch_id:
                query += " WHERE t.batch_id = ?"
                params.append(batch_id)
            query += " ORDER BY d.created_at DESC;"

            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_suppressions_for_issue(self, issue_key: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM suppressions WHERE issue_key = ? AND status = 'ACTIVE';",
                (issue_key,),
            ).fetchall()
            return [dict(r) for r in rows]

    def revoke_suppression(self, suppression_id: str, reason: str) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE suppressions SET status = 'REVOKED', revoked_at = ?, reason = ? WHERE suppression_id = ?;",
                (now_str, reason, suppression_id),
            )
            conn.commit()
