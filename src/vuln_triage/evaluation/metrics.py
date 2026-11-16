from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class MetricResult(BaseModel):
    name: str
    numerator: int
    denominator: int
    rate: Optional[float] = None
    note: Optional[str] = None


class EvaluationMetricsReport(BaseModel):
    total_samples: int
    metrics: Dict[str, MetricResult]


def calculate_metrics(
    eval_records: List[Dict[str, Any]]
) -> EvaluationMetricsReport:
    """
    Computes key metrics defined in SYSTEM_DESIGN.md Section 12:
    - 真漏洞漏判率 (false_negative_rate):
        Cases that were ground truth AFFECTED but got suppressed / NOT_AFFECTED
        divided by all ground truth AFFECTED cases.
    - 抑制案例錯誤率 (suppression_error_rate):
        Suppressed cases that were actually ground truth AFFECTED
        divided by all suppressed cases.
    - 自動處理覆蓋率 (automated_coverage):
        Cases where proposed_action != HUMAN_REVIEW
        divided by total cases.
    - 工作量下降 (workload_reduction):
        1 - (cases sent to HUMAN_REVIEW / total cases).
    """
    total = len(eval_records)
    if total == 0:
        return EvaluationMetricsReport(
            total_samples=0,
            metrics={},
        )

    # Counts
    confirmed_affected = 0
    erroneously_suppressed = 0
    total_suppressed = 0
    auto_handled = 0
    sent_to_human_review = 0

    for rec in eval_records:
        gt_assessment = str(rec.get("ground_truth_assessment", "")).upper()
        predicted_action = str(rec.get("proposed_action", "")).upper()
        predicted_assessment = str(rec.get("predicted_assessment", "")).upper()

        is_suppressed = (
            predicted_action == "SUPPRESS_UNTIL"
            or predicted_assessment == "NOT_AFFECTED"
        )

        if gt_assessment == "AFFECTED":
            confirmed_affected += 1
            if is_suppressed:
                erroneously_suppressed += 1

        if is_suppressed:
            total_suppressed += 1

        if predicted_action == "HUMAN_REVIEW":
            sent_to_human_review += 1
        else:
            auto_handled += 1

    # 1. False negative rate
    fn_rate = (
        (erroneously_suppressed / confirmed_affected)
        if confirmed_affected > 0
        else None
    )
    fn_metric = MetricResult(
        name="false_negative_rate",
        numerator=erroneously_suppressed,
        denominator=confirmed_affected,
        rate=fn_rate,
        note="None if no confirmed affected cases exist." if confirmed_affected == 0 else None,
    )

    # 2. Suppression error rate
    ser_rate = (
        (erroneously_suppressed / total_suppressed)
        if total_suppressed > 0
        else None
    )
    ser_metric = MetricResult(
        name="suppression_error_rate",
        numerator=erroneously_suppressed,
        denominator=total_suppressed,
        rate=ser_rate,
        note="None if no cases were suppressed." if total_suppressed == 0 else None,
    )

    # 3. Automated coverage
    cov_rate = auto_handled / total
    cov_metric = MetricResult(
        name="automated_coverage",
        numerator=auto_handled,
        denominator=total,
        rate=cov_rate,
    )

    # 4. Workload reduction
    workload_rate = (total - sent_to_human_review) / total
    workload_metric = MetricResult(
        name="workload_reduction",
        numerator=(total - sent_to_human_review),
        denominator=total,
        rate=workload_rate,
    )

    return EvaluationMetricsReport(
        total_samples=total,
        metrics={
            "false_negative_rate": fn_metric,
            "suppression_error_rate": ser_metric,
            "automated_coverage": cov_metric,
            "workload_reduction": workload_metric,
        },
    )
