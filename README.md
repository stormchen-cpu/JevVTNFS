# 漏洞分流與雜訊過濾系統 (vuln_triage)

依據 [SYSTEM_DESIGN.md](file:///home/antigravity/SYSTEM_DESIGN.md) 實作之 SCA 漏洞分流、雜訊過濾、隱私保護與審核評估系統。

## 特色

- **證據可追溯**：每一筆判定綁定明確的 `EvidenceBundle` 與其唯一 `fingerprint` 快照。
- **處置可解釋**：以政策矩陣明確劃分技術判定（`AFFECTED` / `NOT_AFFECTED` / `UNKNOWN` / `FIXED`）與處置動作（`PRIORITIZE_REMEDIATION` / `SCHEDULE_REMEDIATION` / `HUMAN_REVIEW` / `SUPPRESS_UNTIL`）。
- **隱私邊界閘道 (EgressGateway)**：外部 API 呼叫強制經欄位白名單與去識別化遮蔽，未審核自由文字阻擋出站。
- **預設 Shadow Mode**：保存處置建議但不啟動自動抑制，確保不造成漏件風險。
- **零洩漏評估**：以案件譜系（Lineage / `issue_key`）嚴格切分評估資料集。

## 快速上手

```bash
# 初始化環境
uv venv .venv
uv pip install --python .venv -e .

# 初始化資料庫
.venv/bin/triage init

# 匯入資料
.venv/bin/triage import examples/products.json --kind deployments --source manual
.venv/bin/triage import examples/advisories.json --kind advisories --source manual
.venv/bin/triage import examples/findings.csv --kind findings --source generic

# 執行 Shadow 模式分流
.venv/bin/triage run --batch default --mode shadow

# 產出報告
.venv/bin/triage report --batch default --format csv --output var/reports/triage_report.csv
```
