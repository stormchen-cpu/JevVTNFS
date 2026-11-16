# 漏洞分流與雜訊過濾系統 (vuln_triage)

依據 [SYSTEM_DESIGN.md](file:///home/antigravity/SYSTEM_DESIGN.md) 實作之 SCA 漏洞分流、雜訊過濾、隱私保護與審核評估系統。

## 特色

- **證據可追溯**：每一筆判定綁定明確的 `EvidenceBundle` 與其唯一 `fingerprint` 快照。
- **處置可解釋**：以政策矩陣明確劃分技術判定（`AFFECTED` / `NOT_AFFECTED` / `UNKNOWN` / `FIXED`）與處置動作（`PRIORITIZE_REMEDIATION` / `SCHEDULE_REMEDIATION` / `HUMAN_REVIEW` / `SUPPRESS_UNTIL`）。
- **Google `gemini-decision-1` 判定模型架構**：整合 Google Gemini Decisions API，透過 3 個並行原子問題（`overall_assessment`, `is_version_affected`, `requires_specific_trigger`）於一次前向傳播中完成零輸出 Token 判定，具備校準信賴度閘控與離線確定性回退機制。
- **原生 `.jsonl` 資料集與公告自動合成**：原生支援 VEX/CVE 935 筆資料集 (`examples/triage_dataset.jsonl`)，匯入時自動合成 `AdvisorySnapshot` 並納入 SQLite 關聯快照庫。
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

# 匯入 935 筆 VEX/CVE JSONL 資料集（自動合成 Advisories 與 Observations）
.venv/bin/triage import examples/triage_dataset.jsonl --kind findings --source jsonl

# 執行 Shadow 模式分流（預設處理 850 筆 under_investigation，支援 --limit 與 --all）
.venv/bin/triage run --batch default --mode shadow --limit 10

# 執行 85 筆 Ground Truth 離線評估報告（零洩漏分組）
.venv/bin/triage evaluate --config configs/evaluation.example.yaml

# 產出報告
.venv/bin/triage report --batch default --format csv --output var/reports/triage_report.csv
```

