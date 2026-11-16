# 漏洞分流與雜訊過濾系統 (vuln_triage) 使用手冊 (User Guide)

本手冊說明 **漏洞分流與雜訊過濾系統 (`vuln_triage`)** 的安裝設定、資料契約、CLI 指令操作及人工審核流程。

本系統專為軟體套件組成分析（SCA）設計，旨在將掃描結果、部署資訊與漏洞公告轉化為可追溯的客觀證據，產生影響判定與處置建議，並透過人工審核閉環與離線評估持續改進分流品質。

---

## 目錄

1. [系統簡介與核心特色](#1-系統簡介與核心特色)
2. [環境需求與安裝步驟](#2-環境需求與安裝步驟)
3. [系統組態設定 (Configurations)](#3-系統組態設定-configurations)
4. [資料匯入規格與契約 (Data Contracts)](#4-資料匯入規格與契約-data-contracts)
5. [CLI 命令列完整操作教學](#5-cli-命令列完整操作教學)
   - [5.1 系統初始化 (`triage init`)](#51-系統初始化-triage-init)
   - [5.2 匯入資料 (`triage import`)](#52-匯入資料-triage-import)
   - [5.3 執行分流判定 (`triage run`)](#53-執行分流判定-triage-run)
   - [5.4 匯出分流報表 (`triage report`)](#54-匯出分流報表-triage-report)
   - [5.5 人工審核與風險接受 (`triage review`)](#55-人工審核與風險接受-triage-review)
   - [5.6 變更重新評估 (`triage reevaluate`)](#56-變更重新評估-triage-reevaluate)
   - [5.7 評估與資料集管理 (`triage dataset` / `triage evaluate`)](#57-評估與資料集管理-triage-dataset--triage-evaluate)
6. [安全性與隱私邊界 (Security & Privacy)](#6-安全性與隱私邊界-security--privacy)
7. [常見問題與排查 (FAQ & Troubleshooting)](#7-常見問題與排查-faq--troubleshooting)

---

## 1. 系統簡介與核心特色

- **證據可追溯 (Evidence Traceability)**：每一筆分流判定均綁定一份不可變的 `EvidenceBundle` 與其唯一 `fingerprint` 快照，明確保留版本比對、部署屬性及公告來源。
- **處置可解釋 (Explainable Policy)**：嚴格分離技術判定（`AFFECTED`、`NOT_AFFECTED`、`UNKNOWN`、`FIXED`）與處置動作（`PRIORITIZE_REMEDIATION`、`SCHEDULE_REMEDIATION`、`HUMAN_REVIEW`、`SUPPRESS_UNTIL`）。
- **預設 Shadow Mode**：系統預設僅保存處置建議，**不啟用**自動抑制狀態，確保安全告警原樣可見，避免漏件風險。
- **嚴格出站脫敏 (Egress Gateway)**：向外部模型發送請求時，強制進行欄位白名單篩選與敏感資訊（IP、憑證、真實路徑、主機名）過濾；未經審核的自由文字若無法保證安全將直接阻擋出站並轉送人工審核。
- **防 CSV 公式注入 (CWE-1236)**：報表產出時自動對 `=`, `+`, `-`, `@`, `\t`, `\r` 進行安全轉義，防範試算表惡意巨集攻擊。
- **零洩漏評估機制**：依案件譜系（`issue_key`）嚴格分組切分資料集，確保訓練集與測試集之間無交叉洩漏。

---

## 2. 環境需求與安裝步驟

### 2.1 系統需求
- **作業系統**：Linux / macOS / Windows (WSL2)
- **Python 版本**：Python 3.11 或以上
- **套件管理工具**：建議使用 `uv` 或標準 `python3 -m venv`

### 2.2 安裝指引

```bash
# 1. 進入專案目錄
cd /home/antigravity

# 2. 建立虛擬環境 (以 uv 為例)
uv venv .venv
source .venv/bin/activate

# 3. 安裝相依套件與 CLI 工具
uv pip install -e .

# 4. 驗證安裝
triage --help
```

---

## 3. 系統組態設定 (Configurations)

系統設定檔集中於 `configs/` 目錄，支援透過命令列參數 `--config` 或環境變數 `TRIAGE_CONFIG` 覆寫。

### 3.1 主要設定檔
| 設定檔路徑 | 用途說明 |
| --- | --- |
| `configs/app.example.yaml` | 資料庫路徑 (`var/triage.db`)、執行期暫存目錄、預設時區及模型後端類型 |
| `configs/policy.example.yaml` | 處置優先度矩陣（環境 × 重要性 × 嚴重度）、禁止負向排除條件 |
| `configs/egress.example.yaml` | 對外資料出站白名單欄位、敏感正規表達式過濾樣式 |
| `configs/evaluation.example.yaml` | 離線評估資料集切分比例（Train/Val/Test）、分組鍵值與指標清單 |

### 3.2 環境變數
可建立 `.env` 檔案配置：
```bash
# 外部 AI API 金鑰 (選用 - 若使用 api 後端)
TRIAGE_API_KEY=your-api-key-here
TRIAGE_API_BASE_URL=https://api.openai.com/v1
TRIAGE_MODEL_NAME=gpt-4o-mini

# 指定自訂設定檔路徑
TRIAGE_CONFIG=configs/app.example.yaml
```

---

## 4. 資料匯入規格與契約 (Data Contracts)

系統支援三種資料匯入合約：掃描發現 (Findings)、部署快照 (Deployments) 與漏洞公告 (Advisories)。

### 4.1 掃描結果發現 (`findings.csv` / `findings.json` / `triage_dataset.jsonl`)
支援平面 CSV、標準 Findings JSON 陣列，以及 VEX/CVE JSON Lines (`.jsonl`) 格式。

#### 4.1.1 VEX/CVE JSONL 格式 (`examples/triage_dataset.jsonl`)
每行均為獨立的 JSON 物件，包含軟體元件與公開漏洞描述：
```json
{
  "vex_status": "under_investigation",
  "component_name": "busybox",
  "component_version": "1.21.1",
  "vulnerability_id": "1e131f86-b2a4-4129-9ed8-724b56c9c709",
  "cve_id": "CVE-2022-48174",
  "euvd_id": "EUVD-2022-50885",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "is_actively_exploited": false,
  "description": "There is a stack overflow vulnerability in ash.c:6030 in busybox before 1.35...",
  "pv_count": 1407,
  "product_count": 1406,
  "hbom_count": 0
}
```
> **自動公告合成 (Auto-Synthesized Advisories)**：當匯入 `.jsonl` 發現資料時，系統會自動自每行之 `cve_id`、`description`、`cvss_score`、`is_actively_exploited` 等欄位合成 `AdvisorySnapshot`，並於一次 `triage import` 操作中同時寫入 `observations` 與 `snapshots`，免除另外準備公告檔之負擔！

定義資產環境與部署組態（JSON 陣列）：
```json
[
  {
    "snapshot_id": "snap-deploy-demo-1",
    "asset_id": "asset-demo-1",
    "deployment_id": "deploy-demo-1",
    "environment": "production",
    "criticality": "high",
    "artifact_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "components": [
      {
        "name": "demo-package",
        "ecosystem": "npm",
        "version": "1.2.3"
      }
    ],
    "configuration": {
      "network_facing": false,
      "waf_enabled": true
    },
    "observed_at": "2026-10-11T08:30:00+08:00"
  }
]
```

### 4.3 漏洞公告 (`examples/advisories.json`)
定義受影響版本範圍與觸發條件（JSON 陣列）：
```json
[
  {
    "advisory_id": "VULN-DEMO-001",
    "revision": "1",
    "source_uri": "https://advisories.example.com/VULN-DEMO-001",
    "retrieved_at": "2026-10-11T08:00:00+08:00",
    "content_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "ecosystem": "npm",
    "package_name": "demo-package",
    "affected_ranges": [
      {
        "type": "SEMVER",
        "events": [
          {"introduced": "0.0.0"},
          {"fixed": "1.3.0"}
        ]
      }
    ],
    "trigger_conditions": ["Unsafe parseXml invocation"]
  }
]
```

---

## 5. CLI 命令列完整操作教學

### 5.1 系統初始化 (`triage init`)
在初次使用或建立新的資料目錄時執行，建立 `var/` 執行目錄並套用 SQLite 資料表綱要：
```bash
triage init
```
- 建立目錄：`var/raw/`, `var/reports/`, `var/datasets/`, `var/models/`
- 初始化資料庫：`var/triage.db`

---

### 5.2 匯入資料 (`triage import`)
將各類資料檔匯入至資料庫快照。

```bash
# 1. 匯入部署快照
triage import examples/products.json --kind deployments --source manual

# 2. 匯入漏洞公告
triage import examples/advisories.json --kind advisories --source manual

# 3. 匯入掃描結果 (CSV 或 JSON)
triage import examples/findings.csv --kind findings --source generic
```

> **容錯特性**：若掃描檔中包含格式錯誤的列（如時間格式異常），系統會將壞列記錄至失敗清單並印出警告，其餘合法列正常寫入，不中斷匯入。

---

### 5.3 執行分流判定 (`triage run`)
對已匯入的觀測資料進行關聯分析、比對版本規則、調用模型並計算處置建議。

```bash
# 預設：Shadow 模式 (記錄建議，不自動啟用抑制；預設過濾 under_investigation 項目)
triage run --batch batch-2026-11 --mode shadow

# 批次限制筆數處理 (例如先處理前 10 筆進行驗證)
triage run --batch batch-test --mode shadow --limit 10

# 處理全量觀測資料 (包含已標註 affected / not_affected 之標註資料)
triage run --batch batch-full --mode shadow --all

# 開放自動抑制模式 (僅限通過評估後使用)
triage run --batch batch-2026-11 --mode active
```

> **冪等性保證**：若輸入資料與證據未變更，重新執行相同批次時會自動跳過（`Idempotent skip`），絕不產生重複判決。

---

### 5.4 匯出分流報表 (`triage report`)
產出分析結果報表，支援 CSV 與 JSON 格式，內建公式注入防護。

```bash
# 匯出 CSV 報表
triage report --batch batch-2026-11 --format csv --output var/reports/triage_report.csv

# 匯出 JSON 報表
triage report --batch batch-2026-11 --format json --output var/reports/triage_report.json
```


#### 報表核心輸出欄位
- `assessment`：`AFFECTED`（受影響）、`NOT_AFFECTED`（不受影響）、`UNKNOWN`（未知/缺少證據）
- `priority`：`P1`（最高）、`P2`、`P3`、`P4`
- `proposed_action`：
  - `PRIORITIZE_REMEDIATION`：優先修復
  - `SCHEDULE_REMEDIATION`：排程修復
  - `HUMAN_REVIEW`：需人工複核（缺失快照或版本）
  - `SUPPRESS_UNTIL`：建議抑制處理至指定期限
- `reason_codes`：判定理由碼（如 `RULE_VERIFIED_AFFECTED_VERSION`）

---

### 5.5 人工審核與風險接受 (`triage review`)

當觀測結果缺少版本資訊、快照不齊全或存在衝突時，系統會將任務派送至人工審核清單。

```bash
# 1. 匯出待審核任務
triage review export --status open --output var/review.json
```

`var/review.json` 內容範例：
```json
[
  {
    "task_id": "rev-9bf9ebf24df9",
    "decision_id": "dec-a831551f0bac",
    "issue_key": "iss-88ea9cbb07a4b647",
    "vulnerability_id": "VULN-DEMO-001",
    "package_name": "demo-package",
    "system_assessment": "UNKNOWN",
    "reviewer_action": {
      "assessment": "NOT_AFFECTED",
      "reason": "經資安分析師人工確認，該套件僅於測試期引用，生產環境未被載入。",
      "risk_acceptance": null
    }
  }
]
```

審核人員修改 `reviewer_action` 後進行匯入：
```bash
# 2. 匯入審核結果
triage review import var/review.json --reviewer analyst_alice
```

#### 人工風險接受 (Risk Acceptance)
若案件在技術上確實受影響，但業務上決定暫緩修復：
```json
"reviewer_action": {
  "assessment": "AFFECTED",
  "reason": "確認受影響，但已排定於下季重構時一併更新，先行接受短期風險。",
  "risk_acceptance": {
    "scope": "deploy-demo-1",
    "approved_by": "ciso_john",
    "expires_in_days": 60
  }
}
```
> **原則**：風險接受會寫入獨立的 `risk_acceptances` 記錄，但**技術判定仍然維持 `AFFECTED`**，絕不扭曲為假性 `NOT_AFFECTED`。

---

### 5.6 變更重新評估 (`triage reevaluate`)
當部署環境升級或漏洞公告修訂時，觸發重新評估：

```bash
triage reevaluate --issue iss-88ea9cbb07a4b647 --reason deployment_changed
```
- 若發現證據已變更，立即使舊有的自動抑制失效（變更為 `REVOKED`）。
- 依據最新證據產出新判定版本並保留完整變更歷史。

---

### 5.7 評估與資料集管理 (`triage dataset` / `triage evaluate`)

#### 匯出已審核資料集
```bash
triage dataset export --selection human-verified --output var/datasets/ground_truth.json
```

#### 執行離線評估報告
使用固定資料集衡量雜訊過濾模型品質：
```bash
triage evaluate --config configs/evaluation.example.yaml
```

**輸出指標說明**：
- `false_negative_rate`（真漏洞漏判率）：被錯誤抑制的受影響案例數 ÷ 所有確認受影響案例數。
- `suppression_error_rate`（抑制案例錯誤率）：被抑制但其實受影響的案例數 ÷ 所有抑制案例數。
- `automated_coverage`（自動處理覆蓋率）：自動完成處置之案例數 ÷ 總輸入案例數。
- `workload_reduction`（工作量下降率）：相較全量人工審核所節省的複核比例。

---

## 6. 安全性與隱私邊界 (Security & Privacy)

1. **出站網關過濾 (EgressGateway)**：
   - 外部模型無法取得真實資產名稱、IP 位址、內部目錄或使用者名稱。
   - 所有外部傳輸事件皆以雜湊與摘要記錄在 `egress_events` 資料表中，不保存敏感內容或 API Key。
2. **禁止負向排除假設 (Prohibited Exclusions)**：
   - 系統明確禁止僅憑「位於內網」、「啟用了 WAF」或「無檔案上傳端點」就將任意漏洞排除為 `NOT_AFFECTED`。
   - 受影響版本必須具有確定性修復或依賴未安裝證據，方可判定排除。
3. **CSV 注入防護 (CWE-1236)**：
   - 匯出 CSV 時，所有單元格若以 `=`, `+`, `-`, `@`, `\t`, `\r` 開頭，自動加上單引號前綴 `'`，防止試算表軟體執行外部命令。

---

## 7. 常見問題與排查 (FAQ & Troubleshooting)

### Q1: 匯入 CSV 時提示 `lacks timezone` 錯誤？
**原因**：系統要求觀測時間具備確切時區，以利全球多資產時間線關聯。  
**解法**：請確保時間符合 ISO 8601 時區規範（如 `2026-10-11T09:00:00+08:00` 或 `2026-10-11T01:00:00Z`）；或在 `configs/app.example.yaml` 中確認 `default_timezone` 已正確設定。

### Q2: 為什麼很多項目判定為 `UNKNOWN` 且動作為 `HUMAN_REVIEW`？
**原因**：系統在以下情況會主動防禦轉人工：
1. 缺少部署快照（`deployment_snapshot`）或漏洞公告（`advisory_snapshot`）。
2. 掃描結果缺少套件版本（`package_version`）。
3. 套件版本格式特殊，無法以語意化版本比對器正確解析。
4. 外部模型呼叫逾時或引用了不存在的證據代碼。

請透過 `triage review export` 查看具體 `reason_codes`（例如 `MISSING_FIELDS:package_version`）。

### Q3: 如何啟用 Google `gemini-decision-1` 判定模型？
系統預設後端為 `gemini-decision`，支援使用 Google Gemini Decisions API（`POST /v1beta/decisions`）。
若尚未設定 API 金鑰，系統會啟用確定性離線啟發式模型（`fallback_to_mock: true`），100% 離線執行並保證零失敗。

若需啟用線上 `gemini-decision-1` 模型，於 `.env` 中設定：
```bash
export GEMINI_API_KEY=your-gemini-api-key
export TRIAGE_BACKEND_TYPE=gemini-decision
export TRIAGE_MODEL_NAME=gemini-decision-1
export TRIAGE_API_BASE_URL=https://generativelanguage.googleapis.com/v1beta
```

**`gemini-decision-1` 核心判定架構**：
- 在單一次前向傳播中並行評估 3 個原子問題，且不產生輸出文字 Token：
  1. `overall_assessment` (`choice`: `AFFECTED`, `NOT_AFFECTED`, `UNKNOWN`)
  2. `is_version_affected` (`noul`: 版本是否真正落入漏洞受影響範圍)
  3. `requires_specific_trigger` (`noul`: 漏洞利用是否依賴特定非預設組態或平台條件)
- **校準信賴度閘控 (Confidence Gating)**：若模型輸出之信賴度低於政策閥值（預設 `0.80`），系統主動降級為 `UNKNOWN` 並標記 `LOW_MODEL_CONFIDENCE` 送交人工審核，杜絕幻覺造成的漏判風險。

---

*文件更新日期：2026-11-16*

