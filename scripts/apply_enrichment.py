"""Apply cached GigaCRA & NVD enrichment into triage.db and build expanded Ground Truth dataset.

Usage:
    .venv/Scripts/python.exe scripts/apply_enrichment.py
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from vuln_triage.config import load_config
from vuln_triage.domain.identity import compute_sha256
from vuln_triage.domain.models import AdvisorySnapshot, DeploymentSnapshot
from vuln_triage.ingest.readers import ImportResult, _extract_trigger_conditions
from vuln_triage.storage.sqlite import Database

CACHE_DIR = Path("var/raw/enrichment_cache")
ASSETS_PATH = CACHE_DIR / "gigacra_assets.jsonl"
BY_MODEL_PATH = CACHE_DIR / "gigacra_by_model.jsonl"
NVD_PATH = CACHE_DIR / "nvd_cves.jsonl"
GT_OUT_PATH = Path("var/datasets/gigacra_ground_truth.jsonl")


def norm_name(s: str) -> str:
    return re.sub(r"[-_.\s]+", "", s.strip().lower())


def parse_cpe23(cpe: str) -> Optional[Tuple[str, str, str, str]]:
    """Returns (part, vendor, product, version) from CPE 2.3 string."""
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[2], parts[3].lower(), parts[4].lower(), parts[5]


def extract_nvd_ranges_for_package(
    nvd_record: Dict[str, Any],
    package_name: str,
    gigacra_cpes: Set[str],
) -> List[Dict[str, Any]]:
    """Extracts conservative OSV-style affected_ranges matching package_name or GigaCRA CPEs."""
    pkg_l = package_name.strip().lower()
    pkg_n = norm_name(package_name)
    aliases = {pkg_l, pkg_n}
    if pkg_l in ("curl", "libcurl"):
        aliases.update({"curl", "libcurl"})

    target_vp: Set[Tuple[str, str]] = set()
    for gc in gigacra_cpes:
        parsed = parse_cpe23(gc)
        if parsed:
            _, v, p, _ = parsed
            target_vp.add((v, p))

    ranges: List[Dict[str, Any]] = []
    seen_keys: Set[str] = set()

    for conf in nvd_record.get("configurations", []):
        for node in conf.get("nodes", []):
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                criteria = match.get("criteria", "")
                parsed = parse_cpe23(criteria)
                if not parsed:
                    continue
                part, vendor, product, cpe_ver = parsed
                if part == "o" and "linux" not in pkg_l and "kernel" not in pkg_l:
                    continue

                matched = (
                    (vendor, product) in target_vp
                    or product in aliases
                    or norm_name(product) in aliases
                )
                if not matched:
                    continue

                events: List[Dict[str, str]] = []
                if match.get("versionStartIncluding"):
                    events.append({"introduced": str(match["versionStartIncluding"])})
                if match.get("versionStartExcluding"):
                    events.append({"introduced_exclusive": str(match["versionStartExcluding"])})
                if match.get("versionEndExcluding"):
                    events.append({"fixed": str(match["versionEndExcluding"])})
                if match.get("versionEndIncluding"):
                    events.append({"last_affected": str(match["versionEndIncluding"])})

                if not events:
                    if cpe_ver not in ("*", "-", ""):
                        events.append({"exact_version": str(cpe_ver)})
                    else:
                        # No bounded version range in this cpeMatch
                        continue

                key = json.dumps(events, sort_keys=True)
                if key not in seen_keys:
                    seen_keys.add(key)
                    ranges.append({"events": events, "cpe_criteria": criteria})

    return ranges


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if not path.exists():
        return items
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def main() -> None:
    cfg = load_config()
    db = Database(cfg.app.database_path)
    now = datetime.now(timezone.utc)

    assets_records = {r["cve_id"]: r["data"] for r in load_jsonl(ASSETS_PATH) if r.get("ok")}
    nvd_records = {r["cve_id"]: r for r in load_jsonl(NVD_PATH) if r.get("ok")}
    by_model_records = [r for r in load_jsonl(BY_MODEL_PATH) if r.get("ok")]

    print(f"Loaded caches: gigacra_assets={len(assets_records)}, by_model={len(by_model_records)}, nvd={len(nvd_records)}")

    # Index component metadata by (cve_id, component_name_lower) and by component_name_lower
    comp_fw_types: Dict[str, Set[str]] = defaultdict(set)
    comp_types: Dict[str, Set[str]] = defaultdict(set)
    comp_cpes_by_pkg: Dict[str, Set[str]] = defaultdict(set)
    comp_cpes_by_cve_pkg: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    pkg_has_prod: Dict[str, bool] = defaultdict(bool)

    # Also collect expanded Ground Truth items from GigaCRA by-model
    gt_items: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for cve_id, data in assets_records.items():
        for p in data.get("affected_products", []):
            cname = (p.get("affected_component_name") or "").strip().lower()
            cpe = p.get("affected_component_cpe")
            if cname:
                pkg_has_prod[cname] = True
                if cpe:
                    comp_cpes_by_pkg[cname].add(cpe)
                    comp_cpes_by_cve_pkg[(cve_id, cname)].add(cpe)
        for pt in data.get("affected_parts", []):
            cname = (pt.get("affected_component_name") or "").strip().lower()
            cpe = pt.get("affected_component_cpe")
            fw = pt.get("fw_type")
            if cname:
                pkg_has_prod[cname] = True
                if fw:
                    comp_fw_types[cname].add(str(fw))
                if cpe:
                    comp_cpes_by_pkg[cname].add(cpe)
                    comp_cpes_by_cve_pkg[(cve_id, cname)].add(cpe)

    for bm in by_model_records:
        mname = bm["model_name"]
        for it in bm.get("data", {}).get("items", []):
            ac = it.get("affected_component") or {}
            vuln = it.get("vulnerability") or {}
            cve_id = vuln.get("cve_id")
            cname = (ac.get("name") or "").strip()
            cname_l = cname.lower()
            if cname_l:
                if ac.get("firmware_type"):
                    comp_fw_types[cname_l].add(str(ac["firmware_type"]))
                if ac.get("component_type"):
                    comp_types[cname_l].add(str(ac["component_type"]))

            vex_st = it.get("vex_status")
            issue_st = it.get("issue_status")
            if cve_id and cname and vex_st in ("affected", "not_affected") and issue_st in ("confirmed_vulnerability", "dismissed_not_affected"):
                cver = ac.get("version") or ""
                key = (mname, cve_id, cname_l)
                if key not in gt_items:
                    gt_items[key] = {
                        "product_name": mname,
                        "firmware_type": ac.get("firmware_type"),
                        "component_type": ac.get("component_type"),
                        "vex_status": vex_st,
                        "issue_status": issue_st,
                        "issue_rationale": it.get("issue_rationale"),
                        "justification": it.get("justification"),
                        "component_name": cname,
                        "component_version": cver,
                        "vulnerability_id": vuln.get("id") or cve_id,
                        "cve_id": cve_id,
                        "euvd_id": vuln.get("euvd_id"),
                        "severity": vuln.get("severity"),
                        "cvss_score": vuln.get("cvss_score"),
                        "is_actively_exploited": vuln.get("is_actively_exploited"),
                        "description": vuln.get("description") or "",
                    }

    # 1. Inspect DB observations to map (asset_id, deployment_id) -> package_name & CVEs
    obs_list = db.get_observations()
    pkg_by_cve: Dict[str, Set[str]] = defaultdict(set)
    cves_by_deploy: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    deploy_pkgs: Dict[Tuple[str, str], Set[Tuple[str, Optional[str], str]]] = defaultdict(set)
    for o in obs_list:
        pkg_by_cve[o.vulnerability_id].add(o.package.name)
        if o.asset_id and o.deployment_id:
            deploy_pkgs[(o.asset_id, o.deployment_id)].add(
                (o.package.name, o.package.version, o.package.ecosystem)
            )
            cves_by_deploy[(o.asset_id, o.deployment_id)].add(o.vulnerability_id)

    # Pre-extract NVD CPE targets (vendor:product[:target_sw]) for non-OS vulnerable nodes
    nvd_targets_by_cve: Dict[str, List[str]] = {}
    for cve_id, nvd_rec in nvd_records.items():
        targets: Set[str] = set()
        for conf in nvd_rec.get("configurations", []):
            for node in conf.get("nodes", []):
                if node.get("negate"):
                    continue
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", True):
                        continue
                    parts = match.get("criteria", "").split(":")
                    if len(parts) >= 11 and parts[0] == "cpe" and parts[1] == "2.3":
                        part, vendor, product, target_sw = parts[2], parts[3], parts[4], parts[10]
                        if part == "o":
                            continue
                        label = f"{vendor}:{product}:{target_sw}" if target_sw not in ("*", "-", "") else f"{vendor}:{product}"
                        targets.add(label)
        if targets:
            nvd_targets_by_cve[cve_id] = sorted(targets)[:8]

    # 2. Build & import DeploymentSnapshots
    deployments: List[DeploymentSnapshot] = []
    for idx, ((asset_id, deployment_id), pkgs) in enumerate(sorted(deploy_pkgs.items()), start=1):
        components = []
        all_fw: Set[str] = set()
        any_prod = False
        for pname, pver, eco in sorted(pkgs):
            pl = pname.lower()
            fws = sorted(comp_fw_types.get(pl, set()))
            cts = sorted(comp_types.get(pl, set()))
            cpes = sorted(comp_cpes_by_pkg.get(pl, set()))
            all_fw.update(fws)
            if pkg_has_prod.get(pl):
                any_prod = True
            components.append({
                "name": pname,
                "version": pver,
                "ecosystem": eco,
                "firmware_type": fws[0] if len(fws) == 1 else (",".join(fws) if fws else None),
                "component_type": cts[0] if cts else None,
                "cpe": cpes[0] if cpes else None,
            })
        dep_cpes = {
            cve_id: nvd_targets_by_cve[cve_id]
            for cve_id in sorted(cves_by_deploy.get((asset_id, deployment_id), set()))
            if cve_id in nvd_targets_by_cve
        }
        dep_cfg: Dict[str, Any] = {}
        if all_fw:
            dep_cfg["firmware_types"] = sorted(all_fw)
        if dep_cpes:
            dep_cfg["nvd_cpe_targets_by_cve"] = dep_cpes

        dep = DeploymentSnapshot(
            snapshot_id=f"snap-gigacra-{idx:04d}",
            asset_id=asset_id,
            deployment_id=deployment_id,
            environment="production" if any_prod else "unknown",
            criticality="standard",
            components=components,
            configuration=dep_cfg,
            observed_at=now,
        )
        deployments.append(dep)

    dep_bytes = json.dumps([d.model_dump(mode="json") for d in deployments], sort_keys=True).encode("utf-8")
    dep_imp = ImportResult(
        kind="deployments",
        source="gigacra_api",
        source_path=str(ASSETS_PATH),
        content_hash=compute_sha256(dep_bytes),
        valid_count=len(deployments),
        deployments=deployments,
    )
    dep_imp_id = db.save_import(dep_imp)
    print(f"Saved {len(deployments)} DeploymentSnapshots (import_id={dep_imp_id})")

    # 3. Merge NVD affected_ranges into existing AdvisorySnapshots
    updated_advisories: List[AdvisorySnapshot] = []
    cves_with_ranges = 0
    cves_awaiting_or_empty = 0

    for cve_id, pkg_names in sorted(pkg_by_cve.items()):
        existing = db.get_advisory_snapshot(cve_id)
        if not existing:
            continue
        nvd_rec = nvd_records.get(cve_id)
        merged_ranges: List[Dict[str, Any]] = []
        if nvd_rec:
            for pname in pkg_names:
                cpes = comp_cpes_by_cve_pkg.get((cve_id, pname.lower()), set()) | comp_cpes_by_pkg.get(pname.lower(), set())
                merged_ranges.extend(extract_nvd_ranges_for_package(nvd_rec, pname, cpes))

        # Deduplicate ranges
        unique_ranges: List[Dict[str, Any]] = []
        seen_ev: Set[str] = set()
        for r in merged_ranges:
            k = json.dumps(r["events"], sort_keys=True)
            if k not in seen_ev:
                seen_ev.add(k)
                unique_ranges.append(r)

        if unique_ranges:
            cves_with_ranges += 1
        else:
            cves_awaiting_or_empty += 1

        adv_dict = existing.model_dump()
        adv_dict["affected_ranges"] = unique_ranges
        merged_triggers = list(existing.trigger_conditions or [])
        for t in _extract_trigger_conditions(existing.description or ""):
            if t not in merged_triggers:
                merged_triggers.append(t)
        adv_dict["trigger_conditions"] = merged_triggers
        adv_dict["retrieved_at"] = now
        adv_dict["source_uri"] = f"nvd:{cve_id}" if nvd_rec else existing.source_uri
        adv_dict["content_hash"] = compute_sha256(
            json.dumps({**adv_dict, "retrieved_at": now.isoformat()}, sort_keys=True, default=str)
        )
        updated_advisories.append(AdvisorySnapshot(**adv_dict))

    adv_bytes = json.dumps([a.model_dump(mode="json") for a in updated_advisories], sort_keys=True, default=str).encode("utf-8")
    adv_imp = ImportResult(
        kind="advisories",
        source="nvd_v2_enrichment",
        source_path=str(NVD_PATH),
        content_hash=compute_sha256(adv_bytes),
        valid_count=len(updated_advisories),
        advisories=updated_advisories,
    )
    adv_imp_id = db.save_import(adv_imp)
    print(
        f"Updated {len(updated_advisories)} AdvisorySnapshots (import_id={adv_imp_id}): "
        f"with_nvd_ranges={cves_with_ranges}, without_ranges={cves_awaiting_or_empty}"
    )

    # 4. Write expanded Ground Truth JSONL from GigaCRA by-model
    GT_OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with GT_OUT_PATH.open("w", encoding="utf-8") as f:
        for item in gt_items.values():
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    aff_cnt = sum(1 for x in gt_items.values() if x["vex_status"] == "affected")
    na_cnt = sum(1 for x in gt_items.values() if x["vex_status"] == "not_affected")
    print(f"Wrote GigaCRA expanded Ground Truth to {GT_OUT_PATH}: total={len(gt_items)} (affected={aff_cnt}, not_affected={na_cnt})")


if __name__ == "__main__":
    main()
