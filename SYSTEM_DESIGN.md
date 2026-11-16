# 漏洞分流與雜訊過濾系統設計

本專案將掃描結果、部署資訊與漏洞公告整理為可追溯的證據，產生影響判定及處置建議，並透過人工審核驗證能否減少複核工作。第一版先完成資料與評估流程，再依實測結果決定是否微調本地決策模型。

設計日期：2026-10-11。狀態：開發前設計，尚未實作或驗證模型品質。

## 1 需求與第一版範圍

使用者已確認：

- 先接受通用 CSV／JSON，後續再接實際掃描工具。
- 漏洞資料與產品規格可以送外部 AI API，但必須先去識別化。

第一版建議限定套件漏洞分析（SCA）、單機批次作業及少量產品，以 Python 套件、CLI、SQLite 和本地檔案完成。CSV／JSON 匯入支援同一組欄位契約。SAST 原始碼資料流分析、多人網頁介面、工單回寫與多租戶列為後續範圍；通用檔案格式不代表所有掃描類型都能共用同一套判定邏輯。

第一版輸出報告及人工複核清單。Shadow mode 是預設模式：保存建議，實際掃描告警保持原狀。原始資料留在本機；只有經檢查的最小必要欄位能送到外部模型。

驗收重點是證據可追溯、處置可解釋、相同匯入不重複建案、失敗不造成漏件，以及在獨立人工標註資料上衡量減少工作量的效果。

## 2 完整處理流程

1. 匯入掃描檔，驗證欄位，保存原始檔雜湊及每列來源。
2. 正規化套件識別、版本、資產與部署識別；合併重複觀測。
3. 取得部署快照、套件清單、已知設定與版本化漏洞公告。
4. 組成 EvidenceBundle；缺失與衝突保留為 unknown，不以 false 取代。
5. 規則處理可精確驗證的條件；需要語意判斷時，交給 DecisionBackend。
6. 外部模型請求經去識別化與出站檢查；無法安全轉換的資料轉人工複核。
7. 模型回傳候選判斷；驗證其理由代碼與證據引用，再交給政策模組。
8. 政策產生處置建議；工作流程依執行模式決定實際紀錄與複核工作。
9. 人工審核、修正或接受風險；保存完整歷程。
10. 匯出經審核的資料集，離線評估或訓練；合格版本經發布流程才取代舊版。

AI 不負責套件版本排序、資料庫更新、外部資料權限或最終處置。這些行為由可測試的程式規則負責。

## 3 模組與責任

以下是同一個 Python 專案內的模組，不需要各自部署為微服務。

| 模組 | 主要程式 | 主要輸入與輸出 | 核心責任 |
| --- | --- | --- | --- |
| 資料匯入 | ingest/readers.py、normalize.py | CSV／JSON → FindingObservation | 驗證、正規化、來源定位、去重識別 |
| 證據整理 | evidence/assembler.py、rules.py | 觀測與快照 → EvidenceBundle | 合併公告及部署證據、版本比較、缺失與衝突檢查 |
| 對外資料處理 | privacy/egress.py | 證據 → EgressPayload 或拒絕原因 | 白名單、識別替換、自由文字檢查、傳送清單 |
| 決策推論 | decision/backend.py、state_builder.py、api_backend.py | 模型輸入 → Prediction | 統一介面、外部模型呼叫、輸出及證據引用驗證 |
| 處置政策 | policy/engine.py | 證據、判斷、政策 → PolicyDecision | 分離技術判定、優先度及處置，控制可否抑制 |
| 工作流程與保存 | workflow/service.py、lifecycle.py、storage/sqlite.py | 匯入批次 → 已保存判定與複核工作 | 交易、重試、冪等、狀態歷程、重新評估 |
| 人工審核 | review/service.py | 判定與審核事件 → 新審核版本 | 改判、理由、證據、接受風險、抽查 |
| 評估 | evaluation/split.py、metrics.py、runner.py | 固定資料集與後端 → 評估報告 | 防資料洩漏、門檻選擇、漏判及工作量評估 |
| 訓練與發布 | training/dataset.py、train_unsloth.py、release.py | 審核資料 → 候選模型與發布清單 | 資料轉換、訓練、校準、重載驗證、回復版本 |
| 操作與報告 | cli.py、reporting/export.py | CLI 參數 → 報告與退出碼 | 匯入、分流、審核、評估及報表匯出 |

共用 domain/models.py 定義資料契約，domain/identity.py 定義案件識別，config.py 載入設定。共用模型只依賴標準函式庫與資料驗證套件，不依賴模型 SDK 或資料庫。

## 4 建議目錄

以下是預定實作目錄；本次僅交付設計文件。

```text
JevVTNFS/
├── pyproject.toml
├── README.md
├── .env.example
├── .gitignore
├── configs/
│   ├── app.example.yaml
│   ├── policy.example.yaml
│   └── egress.example.yaml
├── docs/
│   └── SYSTEM_DESIGN.md
├── examples/
│   ├── products.json
│   ├── findings.csv
│   ├── findings.json
│   └── advisories.json
├── src/vuln_triage/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── domain/{models,identity}.py
│   ├── ingest/{readers,normalize}.py
│   ├── evidence/{assembler,rules}.py
│   ├── privacy/egress.py
│   ├── decision/{backend,state_builder,api_backend}.py
│   ├── policy/engine.py
│   ├── workflow/{service,lifecycle}.py
│   ├── storage/sqlite.py
│   ├── storage/migrations/
│   ├── review/service.py
│   ├── reporting/export.py
│   ├── evaluation/{split,metrics,runner}.py
│   └── training/{dataset,train_unsloth,release}.py
├── tests/
│   ├── fixtures/
│   ├── test_ingest.py
│   ├── test_evidence.py
│   ├── test_egress.py
│   ├── test_policy.py
│   ├── test_workflow.py
│   ├── test_review.py
│   ├── test_dataset_split.py
│   └── test_end_to_end.py
└── var/                         # 執行時建立，排除版本控制
    ├── triage.db
    ├── raw/
    ├── reports/
    ├── datasets/
    └── models/
```

大括號是檔名簡寫，例如 domain/{models,identity}.py 表示兩個檔案。後續需要本地模型時才加入 decision/local_backend.py。測試用 FakeBackend 放在 tests，不允許在正式執行設定中悄悄取代失敗的模型。

## 5 領域資料契約

| 物件 | 必要資訊 | 設計限制 |
| --- | --- | --- |
| FindingObservation | observation_id、source、source_finding_id、observed_at、asset_id、deployment_id、package、vulnerability_id、raw_ref | CVE 可不存在，保留公告來源的原始識別；同名資產不自動視為同一個部署 |
| PackageRef | ecosystem、name、version、purl（若可用）、dependency_path（若可用） | 版本比較採生態系規則，不能用字串大小比較；不支援的版本格式回 unknown |
| DeploymentSnapshot | snapshot_id、asset_id、deployment_id、environment、artifact_digest、components、configuration、observed_at | 缺少 digest 時保存掃描／部署版本與可靠度；不得宣稱已唯一辨識二進位產物 |
| AdvisorySnapshot | advisory_id、revision、source_uri、retrieved_at、content_hash、affected_ranges、trigger_conditions | LLM 摘要不能代替原始公告；擷取出的條件保留原文引用與審核狀態 |
| EvidenceItem | evidence_id、kind、value、source_ref、observed_at、valid_until、verification_status | true／false／unknown 明確區分；自動抑制使用的證據必須經可信規則或人工驗證 |
| EvidenceBundle | bundle_id、finding、deployment、advisory、evidence、missing_fields、conflicts、fingerprint | 不可變快照；一筆判定只對應一份明確證據集合 |
| Prediction | suggested_assessment、probabilities（可空）、reason_code、evidence_ids、backend_id、model_revision、input_hash、status | 自述信心不是校準機率；服務失敗用 status 表達，不造出分類機率 |
| PolicyDecision | decision_id、assessment、priority、proposed_action、reason_codes、evidence_ids、policy_version、expires_at | 所有欄位由政策明確定義；模型結論不直接寫入外部掃描工具 |
| AuditEvent | audit_id、decision_id、reviewer_id、reviewed_at、assessment、reason、evidence_ids、supersedes_id | 追加事件；改判保留前一版；風險接受另記核准資料 |

判定狀態 assessment：AFFECTED、NOT_AFFECTED、FIXED、UNKNOWN。FIXED 必須有原先受影響及現在已修復的證據；單純看到某個未受影響版本不能推論修復歷史。

處置 proposed_action：PRIORITIZE_REMEDIATION、SCHEDULE_REMEDIATION、HUMAN_REVIEW、SUPPRESS_UNTIL。priority 使用組織定義的優先級，由暴露面、資產重要性及威脅情報等政策計算，不直接等同掃描器嚴重度。

人工風險接受包含 scope、approved_by、reason、expires_at，與 assessment 分開。技術上受影響的案例即使暫緩處理，也維持 AFFECTED。

### 通用匯入欄位

CSV 採平面欄位，JSON 採相同欄位的物件陣列。初版必要欄位為 observed_at、ecosystem、package_name、vulnerability_id；source 由 CLI 傳入。asset_id、deployment_id、package_version 的欄位必須存在，但容許空值：缺少時保存為不完整觀測並送複核，不進行自動排除。source_finding_id、dependency_path、purl、scanner_severity 為選填。

時間必須有時區；無時區且未指定匯入時區時列為錯誤。產品名稱與漏洞標題只能作為描述，不作為可靠識別或漏洞觸發條件。

以下是純合成案例，VULN-DEMO-001 不是實際漏洞公告：

```csv
observed_at,asset_id,deployment_id,ecosystem,package_name,package_version,vulnerability_id,source_finding_id
2026-10-11T09:00:00+08:00,asset-demo-1,deploy-demo-1,npm,demo-package,1.2.3,VULN-DEMO-001,scan-demo-1
```

部署與公告透過另外兩種 JSON 匯入契約保存為快照，不要求掃描 CSV 同時包含完整產品規格。匯入後保留原始欄位及正規化值；修正對應關係時建立新版本。內部 FindingObservation 中的 source_finding_id 可空，observation_id 由系統產生。

## 6 識別與去重

- observation_id 指一次掃描觀測。優先使用來源識別搭配掃描批次；來源缺乏識別時，使用正規化欄位、掃描時間及來源建立雜湊。完全相同檔案重匯不增加觀測。
- issue_key 以資產、環境、元件位置與漏洞識別關聯歷次觀測。漏洞別名只有經確認才合併；同一 CVE 位於不同依賴位置可以是不同案件。
- occurrence_key 加上部署／產物版本及套件版本，用於區別不同部署的受影響實例。
- decision_key 包含 occurrence_key、相關證據 fingerprint、模型／提示／資料轉換版本與政策版本，支援重跑冪等。
- 抑制範圍綁定部署、元件、漏洞及所依賴的證據。新觀測必須檢查範圍與證據有效性；不能以舊 asset 名稱直接套用。

證據 fingerprint 使用固定欄位排序的正規化內容；時間與有效期限另外檢查。相同 fingerprint 不代表證據永不過期。

## 7 對外資料處理

所有外部模型呼叫都必須透過 EgressGateway，包括即時推論、離線資料增強與外部模型評估。外部 AI API 可用，不代表所有供應商或所有資料欄位已獲選定；實作時依核准設定啟用。

預設可傳欄位：公開漏洞公告與識別、套件生態系與名稱／版本、經抽象化的環境分類，以及判定所必需且已核准的設定事實。

預設移除欄位：產品真實名稱、客戶名稱、員工資料、內部網域、IP、主機名稱、內部路徑、憑證及完整原始日誌。識別替換表只留在本機。自由文字不能只靠幾條正規表示式就視為已去識別化；第一版優先不傳未經核准的自由文字，必要時改成已驗證的結構欄位。

EgressPayload 保存處理版本、允許欄位、刪除欄位、輸出雜湊與本機 evidence_id 對照；出站事件保存供應商、模型、時間與請求雜湊，不把原始敏感內容或 API key 寫進日誌。錯誤追蹤與第三方遙測也遵循相同限制。

無法移除識別資訊，或移除後失去必要判斷語意時，回傳 EGRESS_BLOCKED／INSUFFICIENT_CONTEXT，交人工複核；不可重試改送原文。模型輸入中的公告或日誌文字均視為資料，不具備變更政策或呼叫工具的權限。

去識別化前後的輸入版本必須納入評估與資料集紀錄；訓練使用的內容要能對應實際部署後端看到的資訊。

## 8 核心 Interface 草案

以下是 Python 型別契約示意，不是已可執行的程式。

```python
def import_findings(path: Path, source: str) -> ImportResult: ...

def assemble_evidence(
    finding: FindingObservation,
    deployment: DeploymentSnapshot | None,
    advisory: AdvisorySnapshot | None,
) -> EvidenceBundle: ...

class DecisionBackend(Protocol):
    def predict(self, request: DecisionInput) -> Prediction: ...

class EgressGateway:
    def prepare(self, request: DecisionInput) -> EgressResult: ...
    def predict(self, payload: EgressPayload) -> Prediction: ...

def evaluate_policy(
    evidence: EvidenceBundle,
    prediction: Prediction | None,
    policy: PolicyConfig,
) -> PolicyDecision: ...

class TriageService:
    def evaluate(self, observation_id: str, mode: RunMode) -> TriageRun: ...
    def reevaluate(self, issue_id: str, cause: ReassessmentCause) -> TriageRun: ...

def record_audit(command: AuditCommand) -> AuditEvent: ...
def export_dataset(selection: DatasetSelection) -> DatasetManifest: ...
def run_evaluation(config: EvaluationConfig) -> EvaluationReport: ...
```

Evidence assembler、政策及狀態轉換盡量採純函式；檔案、資料庫與網路操作由工作流程協調。DecisionBackend 先用測試 fake 與一個選定的真實 API 實作驗證 Interface，之後本地模型沿用同一個 seam，不預先建立多供應商框架。

API backend 只取得去識別化後的輸入；若使用一般文字 LLM，它的 JSON 自述機率不納入自動抑制門檻。沒有可信機率的後端仍可產生人工複核建議。

## 9 處置政策與重新評估

| 條件 | 處置原則 |
| --- | --- |
| 缺少資產對應、實際套件版本、關鍵公告或必要設定證據 | UNKNOWN，送人工複核 |
| 規則及模型矛盾、證據過期、必要內容被截斷 | 人工複核，保存具體原因 |
| 模型超時、格式錯誤、引用不存在的 evidence_id | 不採用模型結果，保留工作並複核 |
| 已確認受影響 | 根據政策安排修復優先度；不得因內網或 WAF 存在而轉成誤報 |
| 已驗證條件足以證明不受影響 | 產生不受影響建議；初期仍以 shadow／人工確認運行 |
| 開放自動抑制後 | 必須有有效排除證據、允許情境、無衝突、版本化政策及有效期限；使用模型時還需通過其獨立校準與評估門檻 |

「版本不在受影響範圍」等精確規則也有前提：套件識別與版本比較必須可靠、公告來源有效。功能不可達必須來自可信分析或人工證據；描述中沒有提到某功能不構成不可達證據。

Runtime 的處置與業務狀態分開：run.status 為 PENDING／RUNNING／SUCCEEDED／FAILED，review.status 為 OPEN／IN_REVIEW／RESOLVED，suppression.status 為 ACTIVE／EXPIRED／REVOKED。Shadow mode 只記 proposed_action，不建立 ACTIVE suppression。

重新評估觸發：部署／依賴／重要設定改變、漏洞公告更新、威脅情報更新、抑制到期、人工撤銷。證據或範圍改變時先讓舊抑制失效；新判定完成前維持可見。模型或政策升版以明確重評批次執行，保留舊結果及比較。

## 10 保存與失敗處理

SQLite 初版資料表：imports、observations、issues、snapshots、triage_runs、decisions、review_tasks、audit_events、risk_acceptances、suppressions、egress_events。快照可先用驗證後 JSON 欄位保存；外鍵、唯一鍵與 migration 管理結構，不為每種證據拆一張表。

同批次的有效資料可繼續處理，壞列另列失敗清單；批次狀態及退出碼必須揭露部分失敗。單筆判定、其複核工作及狀態事件在同一交易提交。禁止「模型失敗但整批顯示成功」。

先保存待處理 run，再執行外部請求，最後以交易保存結果；API 呼叫期間不持有長時間寫入交易。以 request hash／run key 避免重複工作，設定超時及有限次重試。若供應商不支援冪等，網路中斷後重試可能再次計費，保存 attempt 歷程以供追蹤。

第一版單一 worker 逐批處理即可；恢復中斷時重新領取未完成工作。raw 檔與 SQLite 共同備份，資料保留期間由設定管理。報表輸出 CSV 時處理公式注入字元，避免原始掃描文字被試算表當成公式執行。

## 11 人工回饋與資料集

初期用 CLI 查看案件及 JSON 審核檔匯入，不急著建立前端。審核檔需帶 decision_id 與證據版本，匯入時拒絕不存在的案件、無效狀態及過時覆寫。單機 reviewer_id 是可追蹤身分欄位；未加入登入前不宣稱有多人身分驗證。

審核可補證據與改判。風險接受及「先不修」不能輸出成 NOT_AFFECTED 標籤。增加證據的審核建立新快照及新判定，避免改寫當時的模型輸入。

資料來源分為 human_verified、rule_verified、synthetic_candidate。LLM 產生的資料先列候選，不能直接混入人工 ground truth。每筆資料保留原始案例 lineage，先分割再增強；相同案例及其改寫必須留在同一個分割中。

模型輸入限定判定當下可取得的證據。事後才得知的結論或分析理由不回填為事前輸入。審核理由另存，不直接加入 state。

## 12 評估與模型發布

先比較不使用 AI 的精確規則基準，再比較選定 API；資料品質及增益足夠後才投入本地微調。

| 指標 | 定義 |
| --- | --- |
| 真漏洞漏判率 | 被錯誤抑制的受影響案例數 ÷ 所有已確認受影響案例數 |
| 抑制案例錯誤率 | 被抑制但其實受影響的案例數 ÷ 所有已完成審核的抑制案例數 |
| 自動處理覆蓋率 | 可自動完成處置的案例數 ÷ 所有輸入案例數 |
| 工作量下降 | 與原始流程相比的複核件數及人工耗時差異 |
| 校準與效能 | 可用機率的 Brier／校準誤差、全流程 p50／p95 延遲及單筆成本 |

每個比例同時回報分子、分母及不確定性；分母為零顯示無法估計。未審核的抑制案例不能當作正確。抽查需含高分案例並記錄抽樣方式，避免只看人工已改判案例所造成的偏差。

資料切分區分 train、calibration／validation、final test。以案例 lineage 防止重複洩漏，另建立時間外推及新漏洞／新產品評估切片。資料不足時降低自動化範圍，不以人工合成大量相似案例冒充泛化證據。

具體可接受漏判上限、抽查比例及最低樣本需求由組織風險容忍度與實際資料決定，尚未設定；在通過前預設不啟用自動抑制。門檻在校準／驗證資料選定，final test 不用來反覆調參。

模型產物除了 LoRA adapter，還須包含必要的決策 head、tokenizer／基礎模型 revision、校準參數、輸入契約版本、依賴鎖定、資料集 manifest 與評估報告。必須測試儲存後重新載入能產生有效結果。模型失效時回到人工複核，不能回退成自動忽略。

發布使用版本化 release manifest 指向模型、提示、去識別化及政策版本；審核通過後才變更 active release，保留前版可回復。回復不刪除已產生的判定歷程。

## 13 CLI 操作草案

以下是預定命令，尚未實作：

```text
triage init
triage import examples/products.json --kind deployments --source manual
triage import examples/advisories.json --kind advisories --source manual
triage import examples/findings.csv --kind findings --source generic
triage run --batch <batch-id> --mode shadow
triage review export --status open --output review.json
triage review import review.completed.json
triage report --batch <batch-id> --format csv
triage reevaluate --issue <issue-id> --reason deployment_changed
triage dataset export --selection human-verified
triage evaluate --config configs/evaluation.yaml
triage train --config configs/training.yaml
triage release activate --manifest <release-manifest>
```

init 僅建立本地執行目錄與 schema。run 的外部模型支出受每批筆數／預算與重試設定限制。API key 從環境變數讀取；不得寫入設定範本、資料集或報告。

一般執行依賴與訓練依賴分組，例如 core、api、train、dev；未安裝 GPU 套件也能完成匯入、規則、人工審核和報表。初版不要求常駐 Web server、Redis、向量資料庫或 Kubernetes。

## 14 開發順序與驗收

| 階段 | 實作內容 | 可驗收結果 |
| --- | --- | --- |
| M1 資料與基準流程 | domain、ingest、evidence、storage、基本 CLI、範例資料 | 一批掃描可匯入並產生有證據／缺失原因的報告；重匯不重複建案 |
| M2 政策與人工閉環 | policy、workflow、review、報表及到期重評 | UNKNOWN、衝突、過期均不自動抑制；每次改判能追溯 |
| M3 外部模型試運行 | privacy、API backend、shadow 比較、評估資料集 | 對外 payload 通過去識別化測試；取得與規則基準的真實比較結果 |
| M4 本地模型驗證 | 資料切分、Unsloth 小規模訓練、校準、local backend | 完成訓練／存檔／重載／推論並記錄實際顯存、品質與成本；是否採用由結果決定 |
| M5 有限自動化 | 抑制期限、抽查、發布／回復與重新評估 | 僅已驗證情境可自動抑制；證據變動使舊抑制失效；所有操作可還原歷程 |

M3 可以作為第一個實用版本。M4 是成本、隱私或品質需求驅動的投資，並非 MVP 必經條件。M5 的上線依評估結果決定，不以完成訓練當作通過標準。

## 15 必要測試案例

- CSV 與 JSON 相同內容得到相同正規化結果；壞列不造成其他資料漏件。
- 重匯相同掃描不重複建案；部署改版能產生新實例並重新評估。
- 未知設定不當成 false；版本格式不支援時不推論為不受影響。
- 內網部署、有 WAF、沒有上傳功能，均不能單獨構成任意漏洞的排除證據。
- 外部 payload 不含測試置入的識別資訊與秘密；未知自由文字禁止出站；去識別化失敗不能改送原文。
- 模型高分但證據缺失／衝突，仍送人工；引用不存在的 evidence_id 被拒絕。
- shadow mode 永不建立有效抑制；抑制到期與設定改變能撤銷。
- 工作中斷後恢復不重複保存判定；網路失敗與部分失敗能被報告。
- 風險接受不變成誤報訓練標籤；審核保留歷程並拒絕過時覆寫。
- 資料集 lineage 不跨 train／test；必要證據截斷可被偵測。
- 不含 API key 或 GPU 的測試環境可完成端到端流程；模型品質另以固定審核資料驗證。

## 16 實作前仍需選定的設定

模組設計可先推進；接真實資料及開放自動化前需確認外部 AI 供應商與模型、可傳欄位白名單、公告來源、第一批產品與套件生態系、資料保留期限、人工審核負責人，以及漏判容忍度。這些以設定或資料契約承接，不需要先改成另一套架構。

## 17 技術參考

本設計的模組劃分與驗收條件是專案建議。下列官方資料支持模型接法及原始範例的修正；實作時需固定當時驗證通過的版本。

- [Unsloth 決策模型訓練](https://unsloth.ai/docs/basics/train-your-own-decision-model-with-unsloth)：提供 FastDecisionModel、資料轉換、校準與儲存流程；4GB 案例不可直接推定為 4B 模型需求。
- [Unsloth 本地決策模型](https://unsloth.ai/docs/models/decision-laya)：API 相容與 confidence 差異。
- [TypeSafe confidence](https://docs.typesafe.ai/confidence)：confidence 與選項機率的差別，門檻需要依任務驗證。
- [Spring CVE-2024-22233](https://spring.io/security/cve-2024-22233/)：原稿的 HTTP Request Smuggling 範例應更正為官方描述的 DoS 與觸發條件。
