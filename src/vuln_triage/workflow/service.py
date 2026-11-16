from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from vuln_triage.config import RootConfig
from vuln_triage.decision.api_backend import ApiBackend
from vuln_triage.decision.backend import DecisionBackend, FakeBackend
from vuln_triage.decision.state_builder import build_decision_input
from vuln_triage.domain.identity import (
    compute_decision_key,
    compute_issue_key,
    compute_occurrence_key,
)
from vuln_triage.domain.models import (
    EvidenceBundle,
    FindingObservation,
    PolicyDecision,
    Prediction,
    RunMode,
)
from vuln_triage.evidence.assembler import assemble_evidence
from vuln_triage.policy.engine import evaluate_policy
from vuln_triage.privacy.egress import EgressEvent, EgressGateway
from vuln_triage.storage.sqlite import Database


class BatchRunSummary(BaseModel):
    batch_id: str
    mode: str
    total_processed: int = 0
    succeeded: int = 0
    skipped_idempotent: int = 0
    failed: int = 0
    failures: List[Dict[str, Any]] = Field(default_factory=list)
    decisions: List[Dict[str, Any]] = Field(default_factory=list)


class ReevaluationResult(BaseModel):
    issue_key: str
    cause: str
    revoked_suppressions: int = 0
    reevaluated_count: int = 0
    decisions: List[Dict[str, Any]] = Field(default_factory=list)


class TriageService:
    def __init__(
        self,
        config: RootConfig,
        db: Optional[Database] = None,
        backend: Optional[DecisionBackend] = None,
    ):
        self.config = config
        self.db = db or Database(config.app.database_path)
        self.egress_gateway = EgressGateway(config.egress)

        if backend is not None:
            self.backend = backend
        else:
            if config.backend.type == "api":
                self.backend = ApiBackend(config.backend)
            elif config.backend.type == "local":
                from vuln_triage.decision.local_backend import LocalDecisionBackend
                self.backend = LocalDecisionBackend(config.app.models_dir)
            else:
                self.backend = FakeBackend()

    def run_batch(
        self,
        batch_id: str,
        mode: RunMode = RunMode.SHADOW,
        import_id: Optional[str] = None,
    ) -> BatchRunSummary:
        observations = self.db.get_observations(import_id=import_id)
        summary = BatchRunSummary(batch_id=batch_id, mode=mode.value)

        for obs in observations:
            summary.total_processed += 1
            run_id = f"run-{uuid.uuid4().hex[:12]}"
            try:
                # 1. Fetch relevant snapshots
                deployment = self.db.get_deployment_snapshot(obs.asset_id, obs.deployment_id)
                advisory = self.db.get_advisory_snapshot(obs.vulnerability_id)

                # 2. Assemble evidence bundle
                bundle = assemble_evidence(
                    finding=obs,
                    deployment=deployment,
                    advisory=advisory,
                    policy_config=self.config.policy,
                )

                # 3. Compute keys
                env = deployment.environment if deployment else "unassigned-env"
                issue_key = compute_issue_key(
                    asset_id=obs.asset_id,
                    environment=env,
                    dependency_path=obs.package.dependency_path,
                    vulnerability_id=obs.vulnerability_id,
                )
                occurrence_key = compute_occurrence_key(
                    issue_key=issue_key,
                    deployment_id=obs.deployment_id,
                    package_version=obs.package.version,
                )
                model_rev = getattr(self.backend, "model_revision", "default")
                decision_key = compute_decision_key(
                    occurrence_key=occurrence_key,
                    fingerprint=bundle.fingerprint,
                    policy_version=self.config.policy.version,
                    model_version=model_rev,
                )

                # 4. Check idempotency
                existing_decision = self.db.get_decision_by_key(decision_key)
                if existing_decision:
                    summary.skipped_idempotent += 1
                    summary.decisions.append(existing_decision)
                    continue

                # 5. Prepare egress payload
                egress_payload = self.egress_gateway.prepare(bundle)

                # 6. Build decision input snapshot & run prediction
                decision_input = build_decision_input(bundle)

                # Save egress audit event
                egress_event = EgressEvent(
                    event_id=f"egr-ev-{uuid.uuid4().hex[:12]}",
                    run_id=run_id,
                    provider=getattr(self.backend, "backend_id", "local"),
                    model=model_rev,
                    request_hash=egress_payload.output_hash,
                    status="BLOCKED" if egress_payload.is_blocked else "ALLOWED",
                    allowed_fields=egress_payload.allowed_fields,
                    stripped_fields=egress_payload.stripped_fields,
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                self.db.save_egress_event(egress_event)

                prediction: Optional[Prediction] = None
                if not egress_payload.is_blocked:
                    prediction = self.backend.predict(decision_input, egress_payload)

                # 7. Evaluate Policy
                decision = evaluate_policy(
                    evidence=bundle,
                    prediction=prediction,
                    policy=self.config.policy,
                    mode=mode,
                )

                # 8. Save result in atomic transaction
                self.db.save_triage_decision(
                    run_id=run_id,
                    batch_id=batch_id,
                    observation=obs,
                    decision=decision,
                    mode=mode,
                    occurrence_key=occurrence_key,
                    decision_key=decision_key,
                    fingerprint=bundle.fingerprint,
                    issue_key=issue_key,
                )

                summary.succeeded += 1
                summary.decisions.append({
                    "decision_id": decision.decision_id,
                    "observation_id": obs.observation_id,
                    "vulnerability_id": obs.vulnerability_id,
                    "assessment": decision.assessment.value,
                    "priority": decision.priority,
                    "proposed_action": decision.proposed_action.value,
                })

            except Exception as e:
                summary.failed += 1
                summary.failures.append({
                    "observation_id": obs.observation_id,
                    "vulnerability_id": obs.vulnerability_id,
                    "error": str(e),
                })

        return summary

    def reevaluate(self, issue_key: str, cause: str) -> ReevaluationResult:
        """
        Reevaluates observations for an issue when deployments or advisories change.
        Revokes existing active suppressions if necessary.
        """
        result = ReevaluationResult(issue_key=issue_key, cause=cause)

        # 1. Revoke active suppressions for this issue
        active_suppressions = self.db.get_suppressions_for_issue(issue_key)
        for sup in active_suppressions:
            self.db.revoke_suppression(
                suppression_id=sup["suppression_id"],
                reason=f"Reassessment triggered by {cause}",
            )
            result.revoked_suppressions += 1

        # 2. Re-run triage for relevant observations
        all_obs = self.db.get_observations()
        matched_obs: List[FindingObservation] = []
        for o in all_obs:
            dep = self.db.get_deployment_snapshot(o.asset_id, o.deployment_id)
            env = dep.environment if dep else "unassigned-env"
            curr_issue_key = compute_issue_key(
                asset_id=o.asset_id,
                environment=env,
                dependency_path=o.package.dependency_path,
                vulnerability_id=o.vulnerability_id,
            )
            if curr_issue_key == issue_key:
                matched_obs.append(o)

        for obs in matched_obs:
            run_id = f"reeval-run-{uuid.uuid4().hex[:12]}"
            deployment = self.db.get_deployment_snapshot(obs.asset_id, obs.deployment_id)
            advisory = self.db.get_advisory_snapshot(obs.vulnerability_id)

            bundle = assemble_evidence(
                finding=obs,
                deployment=deployment,
                advisory=advisory,
                policy_config=self.config.policy,
            )
            occurrence_key = compute_occurrence_key(
                issue_key=issue_key,
                deployment_id=obs.deployment_id,
                package_version=obs.package.version,
            )
            model_rev = getattr(self.backend, "model_revision", "default")
            # Force new decision key with timestamp suffix to record re-evaluation history
            now_ts = int(datetime.now(timezone.utc).timestamp())
            decision_key = f"{compute_decision_key(occurrence_key, bundle.fingerprint, self.config.policy.version, model_rev)}-{now_ts}"

            egress_payload = self.egress_gateway.prepare(bundle)
            prediction: Optional[Prediction] = None
            if not egress_payload.is_blocked:
                decision_input = build_decision_input(bundle)
                prediction = self.backend.predict(decision_input, egress_payload)

            decision = evaluate_policy(
                evidence=bundle,
                prediction=prediction,
                policy=self.config.policy,
                mode=RunMode.SHADOW,
            )

            self.db.save_triage_decision(
                run_id=run_id,
                batch_id=f"reeval-{cause}",
                observation=obs,
                decision=decision,
                mode=RunMode.SHADOW,
                occurrence_key=occurrence_key,
                decision_key=decision_key,
                fingerprint=bundle.fingerprint,
                issue_key=issue_key,
            )

            result.reevaluated_count += 1
            result.decisions.append({
                "decision_id": decision.decision_id,
                "observation_id": obs.observation_id,
                "assessment": decision.assessment.value,
                "proposed_action": decision.proposed_action.value,
            })

        return result
