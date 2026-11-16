from __future__ import annotations

import pytest

from vuln_triage.evaluation.metrics import calculate_metrics
from vuln_triage.evaluation.split import deterministic_group_split


def test_deterministic_group_split_zero_leakage():
    # 20 samples belonging to 5 distinct issues
    items = []
    for issue_idx in range(5):
        issue_key = f"issue-{issue_idx:02d}"
        for sample_idx in range(4):
            items.append({
                "sample_id": f"s-{issue_idx}-{sample_idx}",
                "issue_key": issue_key,
                "data": f"content-{sample_idx}",
            })

    train, val, test = deterministic_group_split(
        items,
        group_key="issue_key",
        train_ratio=0.60,
        val_ratio=0.20,
        seed=123,
    )

    train_issues = {x["issue_key"] for x in train}
    val_issues = {x["issue_key"] for x in val}
    test_issues = {x["issue_key"] for x in test}

    # Strict mutual exclusivity between partitions
    assert len(train_issues & val_issues) == 0
    assert len(train_issues & test_issues) == 0
    assert len(val_issues & test_issues) == 0

    # Total samples conserved
    assert len(train) + len(val) + len(test) == len(items)


def test_metrics_calculation_and_zero_division():
    # Scenario: 2 confirmed affected, 1 correctly prioritized, 1 erroneously suppressed
    records = [
        {
            "ground_truth_assessment": "AFFECTED",
            "predicted_assessment": "AFFECTED",
            "proposed_action": "PRIORITIZE_REMEDIATION",
        },
        {
            "ground_truth_assessment": "AFFECTED",
            "predicted_assessment": "NOT_AFFECTED",
            "proposed_action": "SUPPRESS_UNTIL",  # Erroneous suppression!
        },
        {
            "ground_truth_assessment": "NOT_AFFECTED",
            "predicted_assessment": "NOT_AFFECTED",
            "proposed_action": "SUPPRESS_UNTIL",  # Correct suppression
        },
    ]

    report = calculate_metrics(records)
    fn_metric = report.metrics["false_negative_rate"]
    assert fn_metric.numerator == 1
    assert fn_metric.denominator == 2
    assert fn_metric.rate == 0.50

    ser_metric = report.metrics["suppression_error_rate"]
    assert ser_metric.numerator == 1
    assert ser_metric.denominator == 2
    assert ser_metric.rate == 0.50

    cov_metric = report.metrics["automated_coverage"]
    assert cov_metric.rate == 1.0  # none sent to human review

    # Zero division test
    empty_report = calculate_metrics([])
    assert empty_report.total_samples == 0

    no_affected_report = calculate_metrics([
        {"ground_truth_assessment": "NOT_AFFECTED", "predicted_assessment": "UNKNOWN", "proposed_action": "HUMAN_REVIEW"}
    ])
    assert no_affected_report.metrics["false_negative_rate"].rate is None
