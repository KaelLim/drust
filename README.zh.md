---
type: index
name: drust
status: production
updated: 2026-06-15
---

# drust

> 自架、多租戶的 **SQLite Backend-as-a-Service**，單一 Rust 執行檔 —— 每個租戶各有 REST **與** 一個 LLM 可直接呼叫的 MCP 端點，內建 row-level security、realtime、向量搜尋、edge functions、S3 檔案儲存。一租戶一檔案，不用另外跑資料庫伺服器。

[English README](README.md) · [架構索引](docs/architecture.md) · [Changelog](CHANGELOG.md) · [給 AI agent 的內部指南](CLAUDE.md)

---

## drust 是什麼？

**drust** 把一台 Linux 主機（或一個容器）變成 PocketHost 風格的資料庫平台。每個租戶擁有獨立的 `data.sqlite`、一組雜湊後的 bearer token、完整型別化的結構化 API、一個 AI agent 不需膠水程式就能驅動的 per-tenant **MCP** 伺服器，以及 Supabase 風格的後台 UI 來編輯 schema。建構於 [axum](https://github.com/tokio-rs/axum) 與 [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk)。

**為何存在。** 為每個小應用各起一套 Postgres / Supabase 太重了 —— 一個團隊會累積數百個小 CRUD app、內部工具、AI agent 暫存區。drust 給每個專案自帶一顆 `tenant.sqlite`、一套寫入路徑絕不吃 raw SQL 的型別化 API、以及 row-level security —— 不需 migration 工具、不需另一台 DB 伺服器、不需逐 app 做注入稽核。它主打**最快 + 最密**：idle 約 15 MB 記憶體、筆電上約 13k req/s、256 MB 的機器塞得下數十個租戶。

## 你可以拿它做什麼

- **CRUD app / SaaS MVP 的後端** —— 不必跑資料庫伺服器：在後台定義 collection，立刻拿到 REST + 型別化的 TypeScript/Zod client，直接上。
- **AI-agent 原生的資料層** —— 任何 MCP client 指向 `/t/<id>/mcp`，agent 就能透過型別化工具檢視 schema、CRUD、向量搜尋、管理檔案。每個錯誤都帶 `suggested_fix`、破壞性操作支援 `dry_run`、且因為 MCP `instructions` 開場白是一張結構化的 intent→tool 地圖，agent 連上第一次就能上手。
- **多租戶平台** —— 單一 drust 程序託管多個完全隔離的租戶；跨租戶存取由 SQL authorizer 在資料庫層就擋掉，不只是應用層。
- **per-user 受保護的資料** —— 宣告一個 `owner_field`，或寫 **PocketBase 風格的 row-level policy**（per-operation 的 `using` / `check` 述詞），每一次讀、寫、realtime 事件都會自動套用過濾。
- **Realtime 應用** —— 用 SSE 訂閱某個 collection，或在單一 WebSocket 上多工多個 room 並廣播 JSON。
- **語意 / 向量搜尋** —— 加一個 `vector` 欄位，對結構化 filter 做 cosine / L2 / L1 top-k 查詢。
- **事件驅動自動化** —— 上傳一支小小的 WebAssembly **edge function**，在 `record.created/updated/deleted` 或 `file.uploaded` 時 in-process 執行。
- **檔案密集的應用** —— per-tenant 的 public/private 物件儲存，大檔走可續傳（tus 1.0）上傳。

## 主要功能

### 資料與隔離
- **Per-tenant SQLite 隔離。** 每租戶一檔，位於 `tenants/<id>/data.sqlite`。跨租戶 `ATTACH` 在 SQL authorizer 層就被拒絕。
- **結構化 REST + MCP 寫入 API。** 寫入永不吃 raw SQL；工具強制 schema、型別、FK 約束、SQL 預設值、以及 per-collection 的 opt-in DML 能力允許清單（`anon_caps`）。
- **唯讀 SQL 走 authorizer 白名單。** 讀取連線以 `SQLITE_OPEN_READONLY` 開啟並在 [`sqlite3_set_authorizer`](https://www.sqlite.org/c3ref/set_authorizer.html) 下執行 —— 不可讀 `sqlite_master`、不可 `ATTACH`、不可寫。
- **Row-level security。** `owner_field` + `read_scope` 提供 per-user 列級過濾；**explicit RLS policy**（`PUT /t/<id>/collections/<c>/policies`，或 MCP `set_policy`）再加上 PocketBase 風格的 per-operation `using`/`check` 述詞，以結構化 Filter AST 表達、編譯成 `?`-bound SQL，並與 owner 條件 AND 疊加。Service key 直接 bypass；user 與 anon 在每一個讀、寫、realtime 面都被過濾。

### AI 原生介面
- **Per-tenant 的 Streamable HTTP MCP。** `/t/<tenant>/mcp` 在 [Streamable HTTP transport](https://spec.modelcontextprotocol.io/specification/2024-11-05/basic/transports/#streamable-http) 上暴露完整的 CRUD / schema / index / RPC / file / 向量搜尋 / webhook / policy / function 工具面。僅 service key；每租戶一個 server 實例。MCP `instructions` 開場白是一張結構化能力地圖，讓 agent 不必窮舉 `tools/list` 就能把 intent 對到 tool。
- **一次呼叫完成 schema bootstrap。** `get_schema_overview` 一次回傳每個 collection 的 schema + 存取狀態（owner_field、anon_caps、realtime、向量維度、RLS policy）與每個 RPC 的 callable 契約。
- **AI 自省輔助。** 每個 REST 錯誤 JSON 都帶情境化的 `suggested_fix`；同樣的提示也透過 `ErrorData.data` 給 MCP client。破壞性工具（`delete_record`、`drop_collection`、`drop_index`）支援 `dry_run: true`，回傳 blast-radius 計數而不變更。service-only 的 `recent_writes` 讓重試中的模型找回上一次嘗試已經寫了什麼。
- **Per-tenant schema codegen。** `GET /t/<id>/openapi.json`、`types.ts`、`zod.ts` 依租戶當前 schema 產生 OpenAPI 3.1、TypeScript `Row`/`Insert`/`Update` 介面、Zod 驗證器。anon 與 service 視圖不同；`X-Drust-Schema-Source` header 記錄渲染的是哪一種。

### 運算與 realtime
- **Edge functions（WebAssembly）。** Per-tenant 上傳的 `.wasm`（wasm32-wasip2 component）函式透過 [wasmtime](https://wasmtime.dev/) in-process 執行，由 `record.created/updated/deleted`（per collection）或 `file.uploaded` 觸發。Host API 就是 REST/MCP 面共用的那層 transport-agnostic 工具，所以函式的寫入會自動 fan out 到 SSE + webhooks。沙箱靠 capability 缺席 + per-tenant 隔離 + epoch deadline + 記憶體上限。guest SDK 範本在 `sdk/edge-function-template/`。
- **Stored RPC。** 具名 SELECT 函式（Supabase 風格），透過 `POST /t/<id>/rpc/<name>` 或 MCP `call_rpc` 呼叫；SQL 在建立時於唯讀 authorizer 下驗證；後台附帶 `EXPLAIN QUERY PLAN` 的測試 playground。`:user_id` 會從呼叫者的 user token 自動綁定。
- **向量儲存 + 相似度搜尋。** Per-collection 的 `vector` 欄位（packed f32 BLOB），以 `POST /t/<id>/collections/<c>/search` 對 Filter AST 做 cosine / L2 / L1 top-k。`sqlite-vec` 註冊為 auto-extension，故 `vec_distance_*` 亦可從 `/query` 與 stored RPC 呼叫。
- **Realtime 廣播。** 每 `(tenant, collection)` 的 SSE 在 `/t/<id>/records/<c>/subscribe`（由 `realtime_enabled` + `anon_caps[select]` 把關，anon 會被 owner/policy 過濾），以及每租戶的 WS 多工在 `/t/<id>/realtime`，含 room、rate-limit / lagged-recovery frame、後台 Broadcast Inspector。訂閱開放；發布預設僅 service key，可 opt-in `allow_user_publish` / `allow_anon_publish`。

### 認證、檔案與維運
- **End-user 認證 + per-tenant OAuth。** Per-tenant 的 `_system_users`，Google / GitHub provider 各租戶自行設定；opt-in 自助註冊；argon2id 雜湊 + 時間等化登入；滑動 30 天 session。
- **物件儲存（選用，S3 相容）。** 兩個 host-wide bucket —— `public`（網站直出）與 `private`（drust 代理）—— 以 `<tenant-id>/` key prefix 命名空間區隔。Public 讀取完全繞過 drust。per-file 的 visibility 切換會把位元組在兩個 bucket 之間搬移。實作對 [Garage](https://garagehq.deuxfleurs.fr/)，但資料路徑是純 S3（`object_store::aws::AmazonS3`），所以 MinIO / R2 / S3 / B2 都能用。
- **可續傳大檔上傳（tus 1.0）。** 第二條 ingest 路徑 `/t/<id>/uploads/*` 收 200 MB–1 GB+ 檔案而不需放寬任何基礎設施 body-limit：受限的 `PATCH` chunk（預設 64 MiB）append 到 per-tenant 的持久 spool，故上傳能撐過 client 斷線與 server 重啟。完成時 SQLite-first + 冪等。
- **Outbound webhooks。** Per-tenant 的 CRUD 事件訂閱，HMAC-SHA256 簽章 POST，4 次重試；SSRF guard 在每次派送都拒絕 private / loopback / CGNAT / IPv6-mapped 目標。
- **後台 UI。** 兩頁式網頁 UI，含 Supabase 風格的 collection editor（FilterAst-backed Table 模式、Definition 視圖、RLS policy 編輯器、anon 能力矩陣、MCP 設定片段）、檔案管理、RPC 與 edge-function 編輯器、audit log 瀏覽、附單租戶還原的 backup 瀏覽。多語（`en` / `zh-Hant`）、三主題。Admin 各自有 personal access token（PAT）供 CLI / MCP 使用。
- **可觀測性與維運。** Prometheus `/admin/_metrics`（audit 丟棄、bearer 拒絕、webhook 嘗試、WS 連線、per-tenant bytes）；audit 列存 `meta_logs.sqlite`，90 天保留 + 每月 VACUUM；每日 `VACUUM INTO` 備份（30 天保留）；soft-delete 含 7 天寬限；per-tenant rate limit；含子網域萬用字元的 CORS 允許清單。

## 用 Docker 啟動

最快上手的方式。drust 只服務 plain HTTP —— 正式環境請在前面擺一個負責 TLS 終止的反向代理（Caddy、nginx、Traefik）。

```bash
# 1. Compose —— drust 跑在 http://localhost:47826（僅 SQLite，無物件儲存）
docker compose up -d
#    ...或連同 S3 檔案儲存一起（drust + MinIO）：
docker compose --profile storage up -d

# 2. 開後台 UI，用 docker-compose.yml 裡的 DRUST_INIT_ADMIN_* 登入
open http://localhost:47826/admin/login

# 3. 健康檢查
curl -s http://localhost:47826/health        # → ok
```

不用 compose、直接 `docker`：

```bash
docker build -t drust:latest .
docker run -d --name drust -p 47826:47826 \
  -v drust-data:/data -v drust-logs:/logs \
  -e DRUST_INIT_ADMIN_USERNAME=admin \
  -e DRUST_INIT_ADMIN_PASSWORD=change-me \
  drust:latest
```

`/data` 裝著 `meta.sqlite`、`meta_logs.sqlite`、每個 `tenants/<id>/`、以及備份 —— 備份那一個 volume 就好。完整 env 清單見 [設定](#設定)。

> [!CAUTION]
> 不要在會擋 `mmap(PROT_EXEC)` 的 seccomp/AppArmor profile 下跑這個容器。Edge functions 透過 wasmtime 的 Cranelift JIT 執行 guest WebAssembly，必須映射可執行記憶體；Docker 預設 profile 允許，但「禁止可執行記憶體」的強化 profile 會讓每次 edge-function 上傳/呼叫都失敗。guest 沙箱是在 wasmtime *內部* 落實，不是靠 process 級的 W^X。

## 從原始碼建置

```bash
git clone https://github.com/KaelLim/drust.git
cd drust
cp .env.example .env             # 編輯 DRUST_INIT_ADMIN_* 等
cargo build --release
./target/release/drust            # 預設綁 127.0.0.1:47826
curl -s http://127.0.0.1:47826/health   # → ok
```

systemd 搭反向代理的部署見 [`CLAUDE.md`](CLAUDE.md) §「Build & restart」與 `deploy/` 的 unit 範本。

> [!NOTE]
> rmcp 的 DNS-rebinding guard 會拒絕任何非 loopback 的 `Host` header。若 MCP 請求在反向代理後面回 `403/421`，代理必須對上游改寫 `Host: 127.0.0.1:47826`。（直連、無代理時不受影響。）

## 架構速覽

```
                            ┌─────────────────── drust :47826 ──────────────────┐
       ┌──────────┐         │                                                   │
client │ TLS edge │ ── HTTP ▶│  axum router                                     │
       └──────────┘         │   ├─ /admin/*           (cookie session)         │
                            │   ├─ /t/<id>/...        (bearer auth)            │
                            │   └─ /t/<id>/mcp        (rmcp Streamable HTTP)   │
                            │                                                   │
                            │  ┌─ meta.sqlite ────┐  ┌─ tenants/<id>/data.sqlite│
                            │  │ admins (+ PAT)   │  │ user collections         │
                            │  │ tenants          │  │ _system_collection_meta  │
                            │  │ tokens (hash)    │  │ _system_users / _sessions│
                            │  │ sessions         │  │ _system_rpc              │
                            │  └──────────────────┘  │ _system_files            │
                            │  ┌─ meta_logs.sqlite ┐ │ _system_webhooks         │
                            │  │ audit (rolling)  │  │ _system_oauth_providers  │
                            │  └──────────────────┘  │ _system_functions        │
                            │                        └──────────────────────────│
                            └─────────────────┬─────────────────────────────────┘
                                              │ 選用 S3 (Garage / MinIO / R2)
                                              ▼
                              ┌──────────────────────────────────┐
                              │ host-wide buckets, key-prefixed   │
                              │  public/<id>/…   private/<id>/…   │
                              └──────────────────────────────────┘
```

Public bucket 的讀取完全繞過 drust —— 直接從 S3 web 端點經反向代理服務。drust 只在*寫入*路徑上。

## API 介面

| 介面 | 路徑 | 認證 | 用途 |
|---|---|---|---|
| 後台 UI | `/admin/*` | Cookie session | 租戶 + schema 管理、policy、檔案、function |
| 租戶 REST | `/t/<id>/...` | Bearer（`anon` / `user` / `service`） | CRUD、`/list`、`/search`、RPC、檔案、上傳、realtime |
| 租戶 MCP | `/t/<id>/mcp` | Bearer（僅 `service`） | LLM 工具呼叫 —— CRUD、schema、index、RPC、檔案、向量搜尋、webhook、policy、function |
| Codegen | `/t/<id>/{openapi.json,types.ts,zod.ts}` | Bearer | 依租戶當前 schema 的型別化 client |
| Health | `/health` | 無 | Liveness probe |

逐檔的公開項目、import、call graph 索引在 [`docs/architecture.md`](docs/architecture.md)（由 `src/**/*.rs` 自動產生）。

## 設定

透過環境變數設定（來自 `.env`、systemd `EnvironmentFile`、或容器 env）：

| 變數 | 必填 | 用途 |
|---|---|---|
| `DRUST_DATA_DIR` | 是 | `meta.sqlite`、`meta_logs.sqlite`、`tenants/`、備份的根目錄 |
| `DRUST_LOG_DIR` | 是 | 保留的 log 目錄 |
| `DRUST_INIT_ADMIN_USERNAME` | 首次開機 | bootstrap admin 帳號 |
| `DRUST_INIT_ADMIN_PASSWORD` | 首次開機 | bootstrap admin 密碼 |
| `DRUST_BIND` | 選用（`127.0.0.1:47826`） | 監聽位址 —— 容器內設 `0.0.0.0:47826` |
| `DRUST_PUBLIC_URL` | 選用 | 對外 base URL —— OAuth redirect/callback 連結需要 |
| `DRUST_CORS_ORIGINS` | 選用 | 逗號分隔允許清單；支援 `https://*.example.com`、`http://localhost:*` |
| `DRUST_DISK_MIN_FREE_PCT` | 選用（20） | 租戶檔案儲存的上傳守門 |
| `GARAGE_S3_ENDPOINT` + `GARAGE_S3_ACCESS_KEY` + `GARAGE_S3_SECRET_KEY` | 選用 | 啟用 S3 儲存功能 |
| `GARAGE_ADMIN_ENDPOINT` + `GARAGE_ADMIN_TOKEN` | 選用 | 僅 Garage：自動建立 bucket |

資料路徑的 S3 走 `object_store::aws::AmazonS3`，所以任何 S3 相容服務都能用（Garage、MinIO、R2、AWS S3、B2）。自動建 bucket 是 Garage 專屬；其他後端請預先建好 bucket。

## 專案結構

```
src/
  main.rs            進入點、router 組裝
  config.rs          env 驅動的設定
  auth/  oauth/       cookie session、bearer token、argon2id、OAuth adapter
  db/                 meta.sqlite migration
  mgmt/               後台 UI handler + askama 範本
  tenant/             租戶生命週期、REST router、bearer middleware、rooms、uploads
  storage/            sqlite pool、schema、檔案/物件 metadata、Garage client、visibility
  query/              SQL authorizer 白名單、filter AST、RLS policy 引擎
  rpc/                stored RPC：prepare、registry、REST + MCP handler
  mcp/                rmcp 工具定義、Streamable HTTP service registry
  codegen/            per-tenant OpenAPI / TypeScript / Zod 產生器
  functions/          edge-function runtime（wasmtime）、dispatcher、executor
  safety/             audit log + audit-DB writer、rate limiter、blast-radius 探測
  bin/                set_admin_password、set_admin_role、drust_session_janitor
sdk/edge-function-template/   edge function 的 guest SDK 腳手架（WIT 為 SoT）
deploy/              systemd unit、Caddyfile 片段、備份 + janitor timer
Dockerfile · docker-compose.yml      容器建置 + 單指令自架
CHANGELOG.md · CLAUDE.md             semver 歷史 · 給 AI agent 的內部指南
```

## 狀態

Production，目前 `v1.38.3`。完整歷史見 [CHANGELOG.md](CHANGELOG.md)。

## 授權

drust 採用 [GNU Affero General Public License v3.0](LICENSE)（AGPL-3.0-only）。

個人、內部、或非商業用途的自架完全在 AGPL-3.0 涵蓋範圍內。若你打算 (a) 將 drust —— 或其修改版 —— 作為託管服務提供給第三方，或 (b) 把 drust 整合進無法以 AGPL 釋出原始碼的專有產品，則很可能需要另外的**商業授權**。

商業授權洽詢請在 GitHub 開一個帶 `commercial-license` 標籤的 issue，或透過 GitHub profile 上的 email 聯絡維護者。
