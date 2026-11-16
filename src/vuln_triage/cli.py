from __future__ import annotations

from pathlib import Path
import sys
from typing import Optional
import click

from vuln_triage.config import RootConfig, load_config
from vuln_triage.domain.models import RunMode
from vuln_triage.evaluation.runner import run_evaluation
from vuln_triage.ingest.readers import (
    import_advisories,
    import_deployments,
    import_findings,
)
from vuln_triage.reporting.export import export_report
from vuln_triage.review.service import export_review_tasks, import_review_tasks
from vuln_triage.storage.sqlite import Database
from vuln_triage.training.dataset import export_dataset
from vuln_triage.training.release import activate_release
from vuln_triage.workflow.service import TriageService


@click.group()
@click.option("--config", "-c", "config_path", default=None, help="Path to app configuration YAML.")
@click.pass_context
def main(ctx: click.Context, config_path: Optional[str]) -> None:
    """漏洞分流與雜訊過濾系統 (vuln_triage) CLI"""
    ctx.ensure_object(dict)
    cfg = load_config(config_path)
    ctx.obj["config"] = cfg
    ctx.obj["db"] = Database(cfg.app.database_path)


@main.command("init")
@click.pass_context
def cmd_init(ctx: click.Context) -> None:
    """初始化執行目錄與資料庫綱要"""
    cfg: RootConfig = ctx.obj["config"]
    db: Database = ctx.obj["db"]

    # Create directories
    for dir_path in [
        cfg.app.raw_dir,
        cfg.app.reports_dir,
        cfg.app.datasets_dir,
        cfg.app.models_dir,
    ]:
        Path(dir_path).mkdir(parents=True, exist_ok=True)

    db.init_db()
    click.echo(f"Initialized database schema at {cfg.app.database_path}")
    click.echo("Runtime directories created in var/")


@main.command("import")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--kind",
    type=click.Choice(["findings", "deployments", "advisories"], case_sensitive=False),
    default="findings",
    show_default=True,
    help="Type of data to import.",
)
@click.option("--source", default="generic", show_default=True, help="Data source identifier.")
@click.pass_context
def cmd_import(ctx: click.Context, path: str, kind: str, source: str) -> None:
    """匯入掃描結果、部署快照或漏洞公告"""
    cfg: RootConfig = ctx.obj["config"]
    db: Database = ctx.obj["db"]
    db.init_db()

    target_path = Path(path)
    kind_lower = kind.lower()

    if kind_lower == "findings":
        res = import_findings(target_path, source=source, default_tz=cfg.app.default_timezone)
    elif kind_lower == "deployments":
        res = import_deployments(target_path, default_tz=cfg.app.default_timezone)
    elif kind_lower == "advisories":
        res = import_advisories(target_path, default_tz=cfg.app.default_timezone)
    else:
        click.echo(f"Unknown import kind: {kind}", err=True)
        sys.exit(1)

    import_id = db.save_import(res)
    click.echo(
        f"Import completed [{kind_lower}]: {res.valid_count} valid, {res.failed_count} failed. Import ID: {import_id}"
    )

    if res.failed_count > 0:
        click.echo(f"Warning: {res.failed_count} rows failed validation:", err=True)
        for failure in res.failures[:5]:
            click.echo(f"  - Row {failure.row_number}: {failure.error_message}", err=True)
        if res.valid_count == 0:
            sys.exit(1)


@main.command("run")
@click.option("--batch", "-b", "batch_id", default="default-batch", show_default=True, help="Batch identifier.")
@click.option(
    "--mode",
    type=click.Choice(["shadow", "active"], case_sensitive=False),
    default="shadow",
    show_default=True,
    help="Execution mode (shadow: record suggestions only; active: enable automated suppressions).",
)
@click.option("--import-id", default=None, help="Filter by specific import ID.")
@click.option("--limit", type=int, default=None, help="Maximum number of observations to process.")
@click.option(
    "--all",
    "process_all",
    is_flag=True,
    default=False,
    help="Process all observations including already labeled ground-truth items.",
)
@click.pass_context
def cmd_run(
    ctx: click.Context,
    batch_id: str,
    mode: str,
    import_id: Optional[str],
    limit: Optional[int],
    process_all: bool,
) -> None:
    """執行漏洞分流評估與處置建議"""
    cfg: RootConfig = ctx.obj["config"]
    db: Database = ctx.obj["db"]
    db.init_db()

    service = TriageService(cfg, db=db)
    run_mode = RunMode(mode.lower())
    vex_filter = None if process_all else "under_investigation"

    summary = service.run_batch(
        batch_id=batch_id,
        mode=run_mode,
        import_id=import_id,
        vex_status_filter=vex_filter,
        limit=limit,
    )


    click.echo(f"Batch '{batch_id}' execution completed in mode [{mode}]:")
    click.echo(f"  - Total processed: {summary.total_processed}")
    click.echo(f"  - Succeeded:       {summary.succeeded}")
    click.echo(f"  - Idempotent skip: {summary.skipped_idempotent}")
    click.echo(f"  - Failed:          {summary.failed}")

    if summary.failed > 0:
        click.echo("Errors encountered during batch run:", err=True)
        for f in summary.failures:
            click.echo(f"  - Obs {f['observation_id']}: {f['error']}", err=True)
        sys.exit(2)


@main.group("review")
def review_group() -> None:
    """人工審核任務管理"""
    pass


@review_group.command("export")
@click.option("--status", default="open", show_default=True, help="Task status filter (open, resolved).")
@click.option("--output", "-o", default="var/review.json", show_default=True, help="Output JSON path.")
@click.pass_context
def cmd_review_export(ctx: click.Context, status: str, output: str) -> None:
    """匯出待人工審核清單"""
    db: Database = ctx.obj["db"]
    count = export_review_tasks(db, output_path=output, status=status.upper())
    click.echo(f"Exported {count} review tasks with status '{status}' to {output}")


@review_group.command("import")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--reviewer", default="security_lead", show_default=True, help="Reviewer identity.")
@click.pass_context
def cmd_review_import(ctx: click.Context, file_path: str, reviewer: str) -> None:
    """匯入完成的人工審核結果"""
    db: Database = ctx.obj["db"]
    res = import_review_tasks(db, input_path=file_path, default_reviewer_id=reviewer)
    click.echo(f"Review import finished: {res['resolved_count']}/{res['total_items']} tasks resolved.")
    if res["errors"]:
        click.echo("Validation errors during review import:", err=True)
        for err in res["errors"]:
            click.echo(f"  - {err}", err=True)
        sys.exit(1)


@main.command("report")
@click.option("--batch", "-b", "batch_id", default=None, help="Batch identifier filter.")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["csv", "json"], case_sensitive=False),
    default="csv",
    show_default=True,
    help="Report output format.",
)
@click.option("--output", "-o", default=None, help="Output file path (defaults to var/reports/report.<format>).")
@click.pass_context
def cmd_report(ctx: click.Context, batch_id: Optional[str], output_format: str, output: Optional[str]) -> None:
    """匯出漏洞分流報表（含 CSV 公式注入防護）"""
    cfg: RootConfig = ctx.obj["config"]
    db: Database = ctx.obj["db"]

    fmt = output_format.lower()
    target_output = output or f"{cfg.app.reports_dir}/triage_report.{fmt}"

    report_path = export_report(db, target_output, batch_id=batch_id, output_format=fmt)
    click.echo(f"Report successfully generated at: {report_path}")


@main.command("reevaluate")
@click.option("--issue", "-i", "issue_key", required=True, help="Issue key to re-evaluate.")
@click.option("--reason", "-r", "reason", default="deployment_changed", show_default=True, help="Reason for reassessment.")
@click.pass_context
def cmd_reevaluate(ctx: click.Context, issue_key: str, reason: str) -> None:
    """依據最新部署或漏洞公告重新評估指定案件"""
    cfg: RootConfig = ctx.obj["config"]
    db: Database = ctx.obj["db"]

    service = TriageService(cfg, db=db)
    res = service.reevaluate(issue_key=issue_key, cause=reason)

    click.echo(f"Re-evaluation complete for issue {issue_key}:")
    click.echo(f"  - Revoked suppressions: {res.revoked_suppressions}")
    click.echo(f"  - Re-evaluated observations: {res.reevaluated_count}")


@main.group("dataset")
def dataset_group() -> None:
    """離線資料集管理"""
    pass


@dataset_group.command("export")
@click.option(
    "--selection",
    type=click.Choice(["human-verified", "all"], case_sensitive=False),
    default="human-verified",
    show_default=True,
    help="Dataset selection filter.",
)
@click.option("--output", "-o", default="var/datasets/export_dataset.json", show_default=True, help="Output path.")
@click.pass_context
def cmd_dataset_export(ctx: click.Context, selection: str, output: str) -> None:
    """匯出經審核之訓練/評估資料集"""
    db: Database = ctx.obj["db"]
    res = export_dataset(db, output_path=output, selection=selection.lower())
    click.echo(f"Exported {res['sample_count']} samples to {res['output_path']}")


@main.command("evaluate")
@click.option("--config", "-c", "eval_config", default="configs/evaluation.example.yaml", show_default=True, help="Evaluation config path.")
@click.pass_context
def cmd_evaluate(ctx: click.Context, eval_config: str) -> None:
    """執行離線評估報告 (計算漏判率、抑制錯誤率、工作量下降)"""
    cfg: RootConfig = ctx.obj["config"]
    report = run_evaluation(eval_config, root_config=cfg)

    click.echo("=" * 60)
    click.echo(f"Evaluation Report ({report.config_path})")
    click.echo(f"Total Samples: {report.total_ground_truth_samples} (Train: {report.train_count}, Val: {report.val_count}, Test: {report.test_count})")
    click.echo("-" * 60)
    for name, m in report.test_metrics.metrics.items():
        rate_str = f"{m.rate * 100:.2f}%" if m.rate is not None else "N/A"
        click.echo(f"  {name:25s}: {rate_str:8s} ({m.numerator}/{m.denominator}) {f'[{m.note}]' if m.note else ''}")
    click.echo("=" * 60)


@main.command("train")
@click.option("--config", "-c", "train_config", default="configs/training.example.yaml", help="Training config YAML.")
def cmd_train(train_config: str) -> None:
    """本地模型訓練準備 (M4 準備: Unsloth FastDecisionModel 訓練與校準)"""
    from vuln_triage.training.train_unsloth import run_unsloth_training_pipeline
    click.echo(f"Validating training configuration: {train_config}")
    res = run_unsloth_training_pipeline(train_config)
    click.echo(f"Unsloth Decision Model pipeline completed: {res['status']}")
    click.echo(f"  - Model directory: {res['model_path']}")
    click.echo(f"  - Calibrated temperature: {res['calibration']['temperature']}")
    click.echo(f"  - Release manifest: {res['release_manifest']['release_id']}")


@main.group("release")
def release_group() -> None:
    """模型發布與回復管理"""
    pass


@release_group.command("activate")
@click.option("--manifest", "-m", "manifest_path", required=True, help="Path to release manifest JSON.")
def cmd_release_activate(manifest_path: str) -> None:
    """啟用指定版本之模型與政策發布清單"""
    rel = activate_release(manifest_path)
    click.echo(f"Activated release: {rel.release_id} (Model: {rel.model_revision}, Policy: {rel.policy_version})")


if __name__ == "__main__":
    main()
