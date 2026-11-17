"""Fetch and cache enrichment data from GigaCRA and NVD API v2.0.

Usage:
    $env:NVD_API_KEY = "<your-nvd-key>"
    .venv/Scripts/python.exe scripts/fetch_enrichment_cache.py
"""
from __future__ import annotations

import json
import os
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

DB_PATH = Path("var/triage.db")
CACHE_DIR = Path("var/raw/enrichment_cache")
GIGACRA_BASE = "https://gigacra.gigacomputing.com/api/v1"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def load_cached_keys(jsonl_path: Path, key_field: str) -> Set[str]:
    done: Set[str] = set()
    if not jsonl_path.exists():
        return done
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if key_field in obj:
                    done.add(str(obj[key_field]))
            except json.JSONDecodeError:
                continue
    return done


def http_json(
    url: str,
    *,
    method: str = "GET",
    body: Dict[str, Any] | None = None,
    headers: Dict[str, str] | None = None,
    timeout: int = 20,
    max_retries: int = 3,
) -> Dict[str, Any] | List[Any]:
    ctx = ssl.create_default_context()
    req_headers = {"Accept": "application/json", "User-Agent": "vuln-triage-enrich/1.0"}
    if headers:
        req_headers.update(headers)
    data_bytes = None
    if body is not None:
        req_headers["Content-Type"] = "application/json"
        data_bytes = json.dumps(body).encode("utf-8")

    for attempt in range(max_retries + 1):
        try:
            req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                wait_s = 3.0 * (2**attempt)
                print(f"  [RETRY] HTTP {e.code} for {url}, sleeping {wait_s:.1f}s...", flush=True)
                time.sleep(wait_s)
                continue
            raise
        except Exception as e:
            if attempt < max_retries:
                wait_s = 2.0 * (2**attempt)
                print(f"  [RETRY] {e} for {url}, sleeping {wait_s:.1f}s...", flush=True)
                time.sleep(wait_s)
                continue
            raise
    raise RuntimeError(f"Exhausted retries for {url}")


def fetch_gigacra_assets(cves: List[str], out_path: Path) -> None:
    done = load_cached_keys(out_path, "cve_id")
    remaining = [c for c in cves if c not in done]
    print(f"[GigaCRA assets] total={len(cves)}, cached={len(done)}, remaining={len(remaining)}", flush=True)

    with out_path.open("a", encoding="utf-8") as f:
        for idx, cve in enumerate(remaining, start=1):
            try:
                res = http_json(
                    f"{GIGACRA_BASE}/work-orders/affected-assets",
                    method="POST",
                    body={"cve": cve},
                )
                record = {"cve_id": cve, "ok": True, "data": res}
            except Exception as e:
                record = {"cve_id": cve, "ok": False, "error": str(e)}
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            if idx % 50 == 0 or idx == len(remaining):
                f.flush()
                print(f"  [GigaCRA assets] {idx}/{len(remaining)} done", flush=True)


def fetch_gigacra_by_model_sample(assets_path: Path, out_path: Path) -> None:
    """Fetches /vulnerabilities/by-model for representative models covering all CVEs and statuses."""
    done = load_cached_keys(out_path, "model_name")
    # Greedily select minimal set of product models covering (cve_id, vex_status) pairs
    model_to_pairs: Dict[str, Set[tuple[str, str]]] = {}
    all_pairs: Set[tuple[str, str]] = set()
    with assets_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if not rec.get("ok"):
                continue
            cve = rec["cve_id"]
            for p in rec.get("data", {}).get("affected_products", []):
                mname = p.get("product_name")
                st = p.get("vex_status") or "unknown"
                if mname:
                    pair = (cve, st)
                    all_pairs.add(pair)
                    model_to_pairs.setdefault(mname, set()).add(pair)

    covered: Set[tuple[str, str]] = set()
    for mname in done:
        covered |= model_to_pairs.get(mname, set())

    selected_models: List[str] = []
    # Greedy set cover capped at 120 representative models to keep API load light
    while len(covered) < len(all_pairs) and len(selected_models) + len(done) < 120:
        best_model = None
        best_gain = 0
        for mname, pairs in model_to_pairs.items():
            if mname in done or mname in selected_models:
                continue
            gain = len(pairs - covered)
            if gain > best_gain:
                best_gain = gain
                best_model = mname
        if not best_model or best_gain == 0:
            break
        selected_models.append(best_model)
        covered |= model_to_pairs[best_model]

    print(
        f"[GigaCRA by-model] total_pairs={len(all_pairs)}, covered_with_cap={len(covered)}, "
        f"cached_models={len(done)}, to_fetch={len(selected_models)}",
        flush=True,
    )

    with out_path.open("a", encoding="utf-8") as f:
        for idx, mname in enumerate(selected_models, start=1):
            q = urllib.parse.quote(mname, safe="")
            try:
                res = http_json(f"{GIGACRA_BASE}/vulnerabilities/by-model?model_name={q}&page=1&page_size=10000")
                record = {"model_name": mname, "ok": True, "data": res}
            except Exception as e:
                record = {"model_name": mname, "ok": False, "error": str(e)}
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            if idx % 20 == 0 or idx == len(selected_models):
                f.flush()
                print(f"  [GigaCRA by-model] {idx}/{len(selected_models)} done", flush=True)


def fetch_nvd_cves(cves: List[str], out_path: Path, api_key: str) -> None:
    done = load_cached_keys(out_path, "cve_id")
    remaining = [c for c in cves if c not in done]
    print(f"[NVD v2.0] total={len(cves)}, cached={len(done)}, remaining={len(remaining)}", flush=True)

    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.68 if api_key else 6.2  # Stay safely under 50 req/30s with key

    with out_path.open("a", encoding="utf-8") as f:
        for idx, cve in enumerate(remaining, start=1):
            t0 = time.monotonic()
            url = f"{NVD_BASE}?cveId={urllib.parse.quote(cve)}"
            try:
                res = http_json(url, headers=headers, timeout=25, max_retries=4)
                vulns = res.get("vulnerabilities", []) if isinstance(res, dict) else []
                cve_obj = vulns[0].get("cve") if vulns else None
                record = {
                    "cve_id": cve,
                    "ok": True,
                    "vulnStatus": cve_obj.get("vulnStatus") if cve_obj else None,
                    "configurations": cve_obj.get("configurations", []) if cve_obj else [],
                    "references": cve_obj.get("references", []) if cve_obj else [],
                    "weaknesses": cve_obj.get("weaknesses", []) if cve_obj else [],
                }
            except Exception as e:
                record = {"cve_id": cve, "ok": False, "error": str(e)}
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            if idx % 25 == 0 or idx == len(remaining):
                f.flush()
                print(f"  [NVD v2.0] {idx}/{len(remaining)} done", flush=True)

            elapsed = time.monotonic() - t0
            if idx < len(remaining) and elapsed < delay:
                time.sleep(delay - elapsed)


def main() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    cves = sorted(r[0] for r in conn.execute("SELECT DISTINCT vulnerability_id FROM observations").fetchall())
    conn.close()

    assets_path = CACHE_DIR / "gigacra_assets.jsonl"
    by_model_path = CACHE_DIR / "gigacra_by_model.jsonl"
    nvd_path = CACHE_DIR / "nvd_cves.jsonl"

    fetch_gigacra_assets(cves, assets_path)
    fetch_gigacra_by_model_sample(assets_path, by_model_path)

    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if not api_key:
        print("ERROR: NVD_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(2)
    fetch_nvd_cves(cves, nvd_path, api_key)
    print("All enrichment fetches completed successfully!")


if __name__ == "__main__":
    main()
