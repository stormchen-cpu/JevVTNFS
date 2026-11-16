from __future__ import annotations

from pathlib import Path
from click.testing import CliRunner
import pytest

from vuln_triage.cli import main
from vuln_triage.reporting.export import sanitize_csv_cell


def test_sanitize_csv_cell_injection_defense():
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert sanitize_csv_cell("-5") == "'-5"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("\tTAB") == "'\tTAB"
    assert sanitize_csv_cell("normal_text") == "normal_text"
    assert sanitize_csv_cell(None) == ""


def test_cli_full_end_to_end_workflow(tmp_path: Path):
    runner = CliRunner()
    config_file = tmp_path / "app.yaml"
    db_file = tmp_path / "var/triage.db"
    report_file = tmp_path / "var/reports/report.csv"
    review_file = tmp_path / "var/review.json"
    dataset_file = tmp_path / "var/datasets/export.json"

    config_content = f"""
app:
  database_path: "{db_file}"
  raw_dir: "{tmp_path}/var/raw"
  reports_dir: "{tmp_path}/var/reports"
  datasets_dir: "{tmp_path}/var/datasets"
  models_dir: "{tmp_path}/var/models"
  default_timezone: "Asia/Taipei"
policy_file: "configs/policy.example.yaml"
egress_file: "configs/egress.example.yaml"
backend:
  type: "fake"
"""
    config_file.write_text(config_content, encoding="utf-8")

    # 1. triage init
    res_init = runner.invoke(main, ["-c", str(config_file), "init"])
    assert res_init.exit_code == 0, res_init.output
    assert "Initialized database schema" in res_init.output

    # 2. triage import deployments
    res_imp_dep = runner.invoke(
        main, ["-c", str(config_file), "import", "examples/products.json", "--kind", "deployments"]
    )
    assert res_imp_dep.exit_code == 0, res_imp_dep.output
    assert "Import completed [deployments]" in res_imp_dep.output

    # 3. triage import advisories
    res_imp_adv = runner.invoke(
        main, ["-c", str(config_file), "import", "examples/advisories.json", "--kind", "advisories"]
    )
    assert res_imp_adv.exit_code == 0, res_imp_adv.output
    assert "Import completed [advisories]" in res_imp_adv.output

    # 4. triage import findings
    res_imp_find = runner.invoke(
        main, ["-c", str(config_file), "import", "examples/findings.csv", "--kind", "findings"]
    )
    assert res_imp_find.exit_code == 0, res_imp_find.output
    assert "Import completed [findings]" in res_imp_find.output

    # 5. triage run (shadow mode)
    res_run = runner.invoke(
        main, ["-c", str(config_file), "run", "--batch", "e2e-batch", "--mode", "shadow"]
    )
    assert res_run.exit_code == 0, res_run.output
    assert "Batch 'e2e-batch' execution completed in mode [shadow]" in res_run.output

    # 6. triage report
    res_report = runner.invoke(
        main,
        [
            "-c",
            str(config_file),
            "report",
            "--batch",
            "e2e-batch",
            "--format",
            "csv",
            "--output",
            str(report_file),
        ],
    )
    assert res_report.exit_code == 0, res_report.output
    assert report_file.exists()
    report_text = report_file.read_text(encoding="utf-8")
    assert "VULN-DEMO-001" in report_text

    # 7. triage review export
    res_rev_exp = runner.invoke(
        main, ["-c", str(config_file), "review", "export", "--output", str(review_file)]
    )
    assert res_rev_exp.exit_code == 0, res_rev_exp.output
    assert review_file.exists()

    # 8. triage review import
    res_rev_imp = runner.invoke(
        main, ["-c", str(config_file), "review", "import", str(review_file)]
    )
    assert res_rev_imp.exit_code == 0, res_rev_imp.output
    assert "Review import finished" in res_rev_imp.output

    # 9. triage dataset export
    res_data_exp = runner.invoke(
        main, ["-c", str(config_file), "dataset", "export", "--output", str(dataset_file)]
    )
    assert res_data_exp.exit_code == 0, res_data_exp.output
    assert dataset_file.exists()

    # 10. triage evaluate
    eval_cfg = tmp_path / "eval.yaml"
    eval_cfg.write_text(
        f"""
evaluation:
  dataset_path: "{tmp_path}/var/datasets/eval_data.json"
  split:
    train_ratio: 0.60
    val_ratio: 0.20
    test_ratio: 0.20
    group_by: "issue_key"
""",
        encoding="utf-8",
    )
    res_eval = runner.invoke(main, ["-c", str(config_file), "evaluate", "--config", str(eval_cfg)])
    assert res_eval.exit_code == 0, res_eval.output
    assert "Evaluation Report" in res_eval.output
