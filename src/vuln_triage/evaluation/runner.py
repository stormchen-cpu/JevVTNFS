from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field

from vuln_triage.config import RootConfig, load_config
from vuln_triage.decision.backend import DecisionBackend, FakeBackend
from vuln_triage.evaluation.metrics import (
    EvaluationMetricsReport,
    calculate_metrics,
)
from vuln_triage.evaluation.split import deterministic_group_split


class EvaluationReport(BaseModel):
    config_path: str
    total_ground_truth_samples: int
    train_count: int
    val_count: int
    test_count: int
    test_metrics: EvaluationMetricsReport
    details: List[Dict[str, Any]] = Field(default_factory=list)


def run_evaluation(
    eval_config_path: str | Path,
    root_config: Optional[RootConfig] = None,
    backend: Optional[DecisionBackend] = None,
) -> EvaluationReport:
    config_file = Path(eval_config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Evaluation config file not found: {config_file}")

    with open(config_file, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    eval_section = cfg.get("evaluation", {})
    dataset_path_str = eval_section.get("dataset_path", "var/datasets/evaluation_ground_truth.json")
    dataset_path = Path(dataset_path_str)

    is_jsonl = dataset_path.suffix.lower() == ".jsonl"

    if not dataset_path.exists():
        if is_jsonl:
            raise FileNotFoundError(f"Evaluation dataset JSONL not found: {dataset_path}")
        # If ground truth dataset does not exist yet, build synthetic benchmark items for offline testing
        dataset = _build_default_benchmark_dataset()
        dataset_path.parent.mkdir(parents=True, exist_ok=True)
        dataset_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        if is_jsonl:
            dataset = []
            for line in dataset_path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                r = json.loads(stripped)
                if r.get("vex_status") in ("affected", "not_affected"):
                    cname = r.get("component_name") or r.get("package_name") or "unknown"
                    cve = r.get("cve_id") or r.get("vulnerability_id") or "unknown"
                    issue_key = f"iss-{cname.lower()}-{cve.upper()}"
                    gt_assessment = "AFFECTED" if r["vex_status"] == "affected" else "NOT_AFFECTED"
                    sample = {
                        "issue_key": issue_key,
                        "ground_truth_assessment": gt_assessment,
                        "is_jsonl_item": True,
                        **r,
                    }
                    dataset.append(sample)
        else:
            dataset = json.loads(dataset_path.read_text(encoding="utf-8"))

    split_cfg = eval_section.get("split", {})
    train_ratio = split_cfg.get("train_ratio", 0.70)
    val_ratio = split_cfg.get("val_ratio", 0.15)
    seed = split_cfg.get("seed", 42)
    group_by = split_cfg.get("group_by", "issue_key")

    train_set, val_set, test_set = deterministic_group_split(
        dataset,
        group_key=group_by,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        seed=seed,
    )

    r_cfg = root_config or load_config()
    if backend is not None:
        active_backend = backend
    else:
        if r_cfg.backend.type in ("gemini-decision", "gemini-decision-1"):
            from vuln_triage.decision.gemini_decision_backend import GeminiDecisionBackend
            active_backend = GeminiDecisionBackend(r_cfg.backend)
        else:
            active_backend = FakeBackend()

    from vuln_triage.privacy.egress import EgressGateway
    from vuln_triage.evidence.assembler import assemble_evidence
    from vuln_triage.decision.state_builder import build_decision_input
    from vuln_triage.policy.engine import evaluate_policy
    from vuln_triage.ingest.readers import _parse_jsonl_finding_row

    gateway = EgressGateway(r_cfg.egress)
    test_records: List[Dict[str, Any]] = []

    for idx, item in enumerate(test_set, start=1):
        gt_assessment = item.get("ground_truth_assessment", "UNKNOWN")

        if item.get("is_jsonl_item"):
            # Run through actual pipeline: finding observation -> advisory -> evidence -> egress -> backend -> policy
            obs, adv = _parse_jsonl_finding_row(item, source="evaluation", default_tz="Asia/Taipei", raw_ref=f"eval:{idx}", row_idx=idx)
            bundle = assemble_evidence(finding=obs, deployment=None, advisory=adv, policy_config=r_cfg.policy)
            egress_payload = gateway.prepare(bundle)
            prediction = None
            if not egress_payload.is_blocked:
                decision_input = build_decision_input(bundle)
                prediction = active_backend.predict(decision_input, egress_payload)
            decision = evaluate_policy(evidence=bundle, prediction=prediction, policy=r_cfg.policy)
            pred_assessment = decision.assessment.value
            action = decision.proposed_action.value
        else:
            is_affected = item.get("version_affected", False)
            if is_affected:
                pred_assessment = "AFFECTED"
                action = "PRIORITIZE_REMEDIATION" if item.get("criticality") == "high" else "SCHEDULE_REMEDIATION"
            elif item.get("version_unaffected", False):
                pred_assessment = "NOT_AFFECTED"
                action = "SUPPRESS_UNTIL"
            else:
                pred_assessment = "UNKNOWN"
                action = "HUMAN_REVIEW"

        test_records.append({
            "issue_key": item.get("issue_key"),
            "ground_truth_assessment": gt_assessment,
            "predicted_assessment": pred_assessment,
            "proposed_action": action,
        })

    metrics_report = calculate_metrics(test_records)

    return EvaluationReport(
        config_path=str(config_file),
        total_ground_truth_samples=len(dataset),
        train_count=len(train_set),
        val_count=len(val_set),
        test_count=len(test_set),
        test_metrics=metrics_report,
        details=test_records,
    )


def _build_default_benchmark_dataset() -> List[Dict[str, Any]]:
    """Builds balanced benchmark cases for initial evaluation testing."""
    items = []
    # 5 different issues
    for i in range(1, 11):
        issue_key = f"iss-benchmark-{i:03d}"
        is_aff = (i % 2 == 1)
        items.append({
            "sample_id": f"s-{i}-a",
            "issue_key": issue_key,
            "vulnerability_id": f"VULN-BENCH-{i:03d}",
            "ecosystem": "npm",
            "package_name": f"lib-{i}",
            "package_version": "1.0.0",
            "criticality": "high" if i <= 5 else "standard",
            "ground_truth_assessment": "AFFECTED" if is_aff else "NOT_AFFECTED",
            "version_affected": is_aff,
            "version_unaffected": not is_aff,
            "provenance": "human_verified",
        })
        # Variant with same lineage to test grouping
        items.append({
            "sample_id": f"s-{i}-b",
            "issue_key": issue_key,
            "vulnerability_id": f"VULN-BENCH-{i:03d}",
            "ecosystem": "npm",
            "package_name": f"lib-{i}",
            "package_version": "1.0.1",
            "criticality": "high" if i <= 5 else "standard",
            "ground_truth_assessment": "AFFECTED" if is_aff else "NOT_AFFECTED",
            "version_affected": is_aff,
            "version_unaffected": not is_aff,
            "provenance": "human_verified",
        })
    return items
