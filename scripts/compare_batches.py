"""Compare baseline (v0), GigaCRA+NVD (v1), and prompt/CPE/trigger optimized (v2) triage reports."""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path

BASE_CSV = Path("var/reports/triage_report.csv")
V1_CSV = Path("var/reports/triage_report_enriched.csv")
V2_CSV = Path("var/reports/triage_report_v2.csv")


def load_csv(path: Path):
    with path.open("r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main() -> None:
    base = load_csv(BASE_CSV)
    v1_all = {r["observation_id"]: r for r in load_csv(V1_CSV)} if V1_CSV.exists() else {}
    v2_all = {r["observation_id"]: r for r in load_csv(V2_CSV)} if V2_CSV.exists() else {}

    obs_ids = [r["observation_id"] for r in base]
    v1 = [v1_all[i] for i in obs_ids if i in v1_all]
    v2 = [v2_all[i] for i in obs_ids if i in v2_all]

    print(f"Rows (matched 1:1): v0={len(base)}, v1={len(v1)}, v2={len(v2)}")

    c0 = Counter(r["assessment"] for r in base)
    c1 = Counter(r["assessment"] for r in v1)
    c2 = Counter(r["assessment"] for r in v2)

    print("\n=== 1. Assessment Progression (v0 -> v1 -> v2, n=850) ===")
    for k in ["AFFECTED", "NOT_AFFECTED", "UNKNOWN"]:
        print(
            f"  {k:13s}: {c0[k]:3d} ({c0[k]/850*100:5.2f}%) -> "
            f"{c1[k]:3d} ({c1[k]/850*100:5.2f}%) -> "
            f"{c2[k]:3d} ({c2[k]/850*100:5.2f}%)  [v2-v1: {c2[k]-c1[k]:+d}, v2-v0: {c2[k]-c0[k]:+d}]"
        )

    print("\n=== 2. Transition Matrix (v1 -> v2, n=850) ===")
    trans = Counter((v1_all[i]["assessment"], v2_all[i]["assessment"]) for i in obs_ids if i in v1_all and i in v2_all)
    for (a1, a2), cnt in trans.most_common():
        if a1 != a2:
            print(f"  CHANGED {a1:12s} -> {a2:12s}: {cnt}")
    for (a1, a2), cnt in trans.most_common():
        if a1 == a2:
            print(f"  SAME    {a1:12s} -> {a2:12s}: {cnt}")

    print("\n=== 3. v2 Reason Codes Summary ===")
    rc2 = Counter()
    for r in v2:
        rc = r["reason_codes"]
        rc2["LOW_MODEL_CONFIDENCE (<0.80)" if rc.startswith("LOW_MODEL_CONFIDENCE:") else rc] += 1
    for k, v in rc2.most_common():
        print(f"  {k}: {v} ({v/len(v2)*100:.2f}%)")

    print("\n=== 4. Top Packages Progression (v0 -> v1 -> v2) ===")
    p0, p1, p2 = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
    for r in base:
        p0[r["package_name"]][r["assessment"]] += 1
    for r in v1:
        p1[r["package_name"]][r["assessment"]] += 1
    for r in v2:
        p2[r["package_name"]][r["assessment"]] += 1

    for pkg, cnt0 in sorted(p0.items(), key=lambda x: sum(x[1].values()), reverse=True)[:12]:
        tot = sum(cnt0.values())
        print(
            f"  {pkg:14s} (n={tot:3d}): "
            f"UNK {cnt0['UNKNOWN']:3d}->{p1[pkg]['UNKNOWN']:3d}->{p2[pkg]['UNKNOWN']:3d} | "
            f"AFF {cnt0['AFFECTED']:3d}->{p1[pkg]['AFFECTED']:3d}->{p2[pkg]['AFFECTED']:3d} | "
            f"NOT {cnt0['NOT_AFFECTED']:2d}->{p1[pkg]['NOT_AFFECTED']:2d}->{p2[pkg]['NOT_AFFECTED']:2d}"
        )


if __name__ == "__main__":
    main()
