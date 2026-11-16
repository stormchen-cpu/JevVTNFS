from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from vuln_triage.storage.sqlite import Database


def sanitize_csv_cell(value: Any) -> str:
    """
    Prevents CSV Formula Injection (CWE-1236).
    If a string starts with '=', '+', '-', '@', tab, or carriage return,
    prefix with a single quote to prevent spreadsheet formula execution.
    """
    if value is None:
        return ""
    str_val = str(value)
    if str_val and str_val[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{str_val}"
    return str_val


def export_report(
    db: Database,
    output_path: str | Path,
    batch_id: Optional[str] = None,
    output_format: str = "csv",
) -> str:
    decisions = db.get_decisions_for_reporting(batch_id=batch_id)
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if output_format.lower() == "json":
        formatted = []
        for d in decisions:
            item = dict(d)
            if "reason_codes_json" in item and item["reason_codes_json"]:
                item["reason_codes"] = json.loads(item["reason_codes_json"])
            formatted.append(item)
        content = json.dumps(formatted, indent=2, ensure_ascii=False)
        out_file.write_text(content, encoding="utf-8")
        return str(out_file)

    elif output_format.lower() == "csv":
        fieldnames = [
            "decision_id",
            "batch_id",
            "mode",
            "observation_id",
            "asset_id",
            "deployment_id",
            "ecosystem",
            "package_name",
            "package_version",
            "vulnerability_id",
            "scanner_severity",
            "assessment",
            "priority",
            "proposed_action",
            "reason_codes",
            "created_at",
        ]

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()

        for d in decisions:
            reason_codes_list = []
            if d.get("reason_codes_json"):
                try:
                    reason_codes_list = json.loads(d["reason_codes_json"])
                except Exception:
                    reason_codes_list = [d["reason_codes_json"]]

            row = {
                "decision_id": sanitize_csv_cell(d.get("decision_id")),
                "batch_id": sanitize_csv_cell(d.get("batch_id")),
                "mode": sanitize_csv_cell(d.get("mode")),
                "observation_id": sanitize_csv_cell(d.get("observation_id")),
                "asset_id": sanitize_csv_cell(d.get("asset_id")),
                "deployment_id": sanitize_csv_cell(d.get("deployment_id")),
                "ecosystem": sanitize_csv_cell(d.get("ecosystem")),
                "package_name": sanitize_csv_cell(d.get("package_name")),
                "package_version": sanitize_csv_cell(d.get("package_version")),
                "vulnerability_id": sanitize_csv_cell(d.get("vulnerability_id")),
                "scanner_severity": sanitize_csv_cell(d.get("scanner_severity")),
                "assessment": sanitize_csv_cell(d.get("assessment")),
                "priority": sanitize_csv_cell(d.get("priority")),
                "proposed_action": sanitize_csv_cell(d.get("proposed_action")),
                "reason_codes": sanitize_csv_cell("; ".join(reason_codes_list)),
                "created_at": sanitize_csv_cell(d.get("created_at")),
            }
            writer.writerow(row)

        out_file.write_text(buf.getvalue(), encoding="utf-8")
        return str(out_file)
    else:
        raise ValueError(f"Unsupported report format: {output_format}. Supported: csv, json")
