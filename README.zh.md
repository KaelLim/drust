---
type: index
name: drust
status: production
updated: 2026-05-31
---

# drust

> 自託管的多租戶 SQLite Backend-as-a-Service（Rust 實作）— 每個租戶獨立 REST + MCP 端點、附 admin UI、可選 S3 檔案儲存。

[English README](README.md) · [架構索引](docs/architecture.md) · [更新紀錄](CHANGELOG.md) · [AI agent 內部指引](CLAUDE.md)

---

## drust 是什麼？

**drust** 是一個單一執行檔的 HTTP 服務，把一台 Linux host 變成類 PocketHost 的多租戶資料平台：每個租戶有自己獨立的 SQLite 資料庫、結構化寫入 API、可被 LLM 直接呼叫的 MCP endpoint，以及一個用來編 schema 的 admin UI。基於 [axum](https://github.com/tokio-rs/axum) 與 [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk)。

**為何造輪子。** 內部上百個小型 CRUD 應用與 AI agent 草稿空間，個別開 Postgres / Supabase 太重。drust 給每個專案一份獨立的 `tenant.sqlite`、一組 hashed bearer token、一套全程型別檢查的 API — 不需要 schema migration 工具、不需要單獨資料庫 server、也不會擔心 SQL injection。

## 主要特性

- **每租戶 SQLite 隔離。** 每位租戶一檔，路徑為 `tenants/<id>/data.sqlite`。SQL authorizer 阻擋跨租戶 `ATTACH`。
- **結構化的 REST + MCP 寫入 API。** 寫入路徑不接受裸 SQL；所有 tool 都會檢查 schema、型別、外鍵，並支援每個 collection 自訂的 `anon_caps` 能力清單。WebSocket broadcast 每次 publish 只序列化一次，與訂閱者數量無關。
- **唯讀 SQL 經過 authorizer 白名單。** 讀連線使用 `SQLITE_OPEN_READONLY` + [`sqlite3_set_authorizer`](https://www.sqlite.org/c3ref/set_authorizer.html) — 不能讀 `sqlite_master`、不能 `ATTACH`、不能寫入。
- **每租戶 Streamable HTTP MCP。** `/t/<tenant>/mcp` 提供 CRUD / schema / index / RPC / 檔案 / 向量搜尋 / webhook 完整 tool 介面。每位租戶一個獨立 server instance，走 [Streamable HTTP transport](https://spec.modelcontextprotocol.io/specification/2024-11-05/basic/transports/#streamable-http)。僅 service key 可用。
- **AI introspection 工具。** 每一筆 REST error JSON 都帶 context-aware 的 `suggested_fix` 提示；同樣的提示透過 `ErrorData.data` 也會送給 MCP client。破壞性操作（`delete_record`、`drop_collection`、`drop_index`）支援 `dry_run: true`，回傳預估影響範圍（blast radius）但不真的執行。另有 service-only 的 `recent_writes` MCP tool，讓重試中的 model 可以查回上次嘗試已經完成了哪些操作。
- **每租戶 schema 自動產生器。** `GET /t/<id>/openapi.json`、`GET /t/<id>/types.ts`、`GET /t/<id>/zod.ts` 三個端點依照租戶當下的 schema 即時產出 OpenAPI 3.1、TypeScript `Row` / `Insert` / `Update` 介面、以及 Zod runtime validator（向量欄位 → `z.array(z.number()).length(N)`）。Anon 與 service view 形狀不同；`X-Drust-Schema-Source` header 標明此次回應走的是哪個 view。
- **Stored RPC（類 Supabase 命名 SQL function）。** 租戶可以定義具名 SELECT 函式，透過 `POST /t/<id>/rpc/<name>` 或 MCP 的 `call_rpc` 呼叫。SQL 在建立當下就用唯讀 authorizer 跑 `prepare()` 驗證；admin UI 附 test playground，可直接帶參數試跑 + 看 `EXPLAIN QUERY PLAN`。
- **向量儲存 + 相似度搜尋。** Collection 可宣告 `vector` 型別欄位（封裝為 f32 BLOB），透過 `POST /t/<id>/collections/<c>/search` 走 Filter AST 進行 cosine / L2 / L1 top-k 查詢。`sqlite-vec` 註冊為 SQLite auto-extension，所以 `vec_distance_*` 在 `/query` 與 stored RPC 中也能用。
- **Realtime broadcast。** 兩種介面：每 `(tenant, collection)` 一條 SSE channel（`/t/<id>/records/<c>/subscribe`，受 collection 層的 `realtime_enabled` + `anon_caps[select]` 雙重 gate），以及 v1.31 的每租戶 WS multiplex（`/t/<id>/realtime`），支援 rooms、rate-limit / lagged-recovery 控制訊框，admin 端附 Broadcast Inspector 可瀏覽器端到端煙測。
- **End-user 認證 + 每租戶 OAuth。** 每租戶獨立 `_system_users`；每租戶可自設 Google / GitHub OAuth provider；自助註冊可選擇開關；row-level 過濾透過 `owner_field` + `read_scope`；密碼用 argon2id + timing-equalized 登入。
- **Outbound webhook。** 每租戶可訂閱 CRUD 事件，POST 載荷帶 HMAC-SHA256 簽章，4 次重試（+0s / +1s / +5s / +30s）；admin UI / REST / MCP 三種寫入面；SSRF 防護在每次 dispatch 都會擋私網 / loopback / CGNAT / IPv6-mapped 對應位址；HTTP client 跨重試共用，但每次 Request 都重新解析 DNS，確保 resolver 永遠跑在每條連線上。
- **Schema description（給 LLM 啟動用）。** Collection / field / index / RPC 都可帶純文字 `description`，透過 `describe_collection` 與 `get_schema_overview` 一次取出，讓 LLM 一次 MCP call 就理解整個 schema 的設計意圖。
- **Admin UI。** 雙頁式 web UI（`/admin/tenants` + 各租戶 `/admin/tenants/<id>/<datatable>`），含 Supabase 風格的 collection 編輯器（sticky header、FilterAst 驅動的 Table mode 走 `POST /_list`、Definition view）、檔案管理、RPC 編輯器 + test playground、anon 能力矩陣、MCP 設定範本、audit log 瀏覽器、backup 瀏覽器 + 單租戶還原、Broadcast Inspector。內建中英雙語（`en` / `zh-Hant`）與三套主題（`system` / `cozy-dark` / `soft-light`）。
- **Admin Personal Access Token。** 每位 admin 拿自己的 PAT 跑 CLI / MCP，不再共用某個租戶的 service key。PAT 是 admin scope（不綁特定租戶），可在 admin UI 集中撤銷。
- **S3 檔案儲存（可選）。** 啟用後每位租戶會自動配給兩顆 S3 bucket — `<id>-pub`（啟用 website）與 `<id>-prv`（私有）。預設配 [Garage](https://garagehq.deuxfleurs.fr/)，但資料面是純 S3（`object_store::aws::AmazonS3`）。
- **Admin OAuth。** `/admin/login` 除了帳密之外，也支援 Google / GitHub 登入；email 允許清單由 env 設定；id_token 的 `iss` / `aud` / `exp` claim 依 OIDC §3.1.3.7 驗證。
- **Observability。** 受 admin session 保護的 `/admin/_metrics` Prometheus 端點，揭露 audit drop、bearer denial、webhook attempt、active WS connection、每租戶 DB bytes 等指標。Audit 寫入 `meta_logs.sqlite`，內建 90 天 retention 清理 + 每月 VACUUM，admin UI 可查。
- **Operational 基本配備。** 每租戶 rate limit、每日 `VACUUM INTO` 快照（同時備份 `meta.sqlite` + `meta_logs.sqlite`，保留 30 天）、軟刪除（7 天緩衝期）、CORS allow-list 支援子網域萬用字元。

## 整體架構

```
                            ┌─────────────────── drust :47826 ──────────────────┐
       ┌──────────┐         │                                                   │
client │ TLS edge │ ── HTTP ▶│  axum router                                     │
       └──────────┘         │   ├─ /admin/*           （cookie session）        │
                            │   ├─ /t/<id>/...        （bearer auth）           │
                            │   └─ /t/<id>/mcp        （rmcp Streamable HTTP）  │
                            │                                                   │
                            │  ┌─ meta.sqlite ────┐  ┌─ tenants/<id>/data.sqlite│
                            │  │ admins (+ PAT)   │  │ 使用者 collection         │
                            │  │ tenants          │  │ _system_collection_meta  │
                            │  │ tokens (hash)    │  │ _system_users / _sessions│
                            │  │ sessions         │  │ _system_rpc              │
                            │  └──────────────────┘  │ _system_files            │
                            │  ┌─ meta_logs.sqlite ┐ │ _system_webhooks         │
                            │  │ audit (rolling)  │  │ _system_oauth_providers  │
                            │  └──────────────────┘  └──────────────────────────│
                            └─────────────────┬─────────────────────────────────┘
                                              │ 可選 S3（Garage / MinIO / R2）
                                              ▼
                                    ┌────────────────────┐
                                    │ public bucket +    │
                                    │ tenant-<id>-pub /  │
                                    │ tenant-<id>-prv    │
                                    └────────────────────┘
```

公開 bucket 的讀取請求**完全繞過 drust** — 由反向代理直接打 S3 web endpoint。drust 只在「寫入」路徑上。

## API 介面

| 介面 | 路徑 | 認證 | 用途 |
|---|---|---|---|
| Admin UI | `/admin/*` | Cookie session | 租戶與 schema 管理、檔案操作 |
| Tenant REST | `/t/<id>/...` | Bearer（`anon` 或 `service`） | CRUD、RPC 呼叫、檔案操作 |
| Tenant MCP | `/t/<id>/mcp` | Bearer（限 `service`） | LLM tool calls — CRUD / schema / index / RPC / 檔案 / 向量搜尋 / webhook |
| Health | `/health` | 無 | Liveness probe |

每個檔案的 public items / 模組 import / call graph 完整索引在 [`docs/architecture.md`](docs/architecture.md)（由 `src/**/*.rs` 自動生成）。

## 快速開始

```bash
git clone https://github.com/KaelLim/drust.git
cd drust
cp .env.example .env             # 編輯 DRUST_INIT_ADMIN_* 等變數
cargo build --release
./target/release/drust            # 預設綁 127.0.0.1:47826
curl -s http://127.0.0.1:47826/health   # → ok
```

要走 systemd + 反向代理部署，請參考 [`CLAUDE.md`](CLAUDE.md) 的「Build & restart」章節，以及上層 `tool/services.md` runbook。

> **MCP 注意事項。** rmcp 的 DNS rebinding 防護會拒絕任何非 loopback 的 `Host` header。如果 MCP 請求在反向代理後面回 `403/421`，請務必在 proxy 層把 `Host` 改寫為 `127.0.0.1:47826` 再轉給 drust。完整診斷紀錄連結見 [`CLAUDE.md`](CLAUDE.md)。

## 環境變數

透過環境變數設定（systemd 或 shell 從 `.env` 載入）：

| 變數 | 必要 | 說明 |
|---|---|---|
| `DRUST_DATA_DIR` | 必要 | `meta.sqlite` 與 `tenants/` 的根目錄 |
| `DRUST_INIT_ADMIN_USERNAME` | 首次啟動必要 | 初始 admin 帳號 |
| `DRUST_INIT_ADMIN_PASSWORD` | 首次啟動必要 | 初始 admin 密碼 |
| `DRUST_LOG_DIR` | 必要 | 保留的 log 目錄；自 v1.24 起 audit 直接寫 `meta_logs.sqlite`，不再產生每日 JSONL |
| `DRUST_CORS_ORIGINS` | 選用 | 逗號分隔 allow-list；支援 `https://*.example.com` 子網域 |
| `DRUST_DISK_MIN_FREE_PCT` | 選用（預設 20） | 租戶檔案上傳磁碟低水位防護 |
| `GARAGE_S3_ENDPOINT` + `GARAGE_S3_ACCESS_KEY` + `GARAGE_S3_SECRET_KEY` | 選用 | 啟用 S3 檔案儲存功能 |
| `GARAGE_ADMIN_ENDPOINT` + `GARAGE_ADMIN_TOKEN` | 選用 | 自動配給每租戶 bucket 所需 |

S3 資料面用 `object_store::aws::AmazonS3`，因此任何 S3 相容服務都能用（Garage / MinIO / Cloudflare R2 / AWS S3 / B2）。但「自動配 bucket」這部分是 Garage 專屬 — 換成其他 backend 時，bucket 與每租戶 access key 須事先準備好，drust 不會自動建立。

## 專案結構

```
src/
  main.rs            進入點、router 組裝
  config.rs          env 驅動的設定
  auth/              cookie session、bearer token、argon2id hashing
  oauth/             OAuth provider library（Google + GitHub adapter）
  db/                meta.sqlite migration
  mgmt/              admin UI handler + askama 模板
  tenant/            租戶生命週期、REST router、bearer 中介層
  storage/           sqlite pool、schema、檔案/物件 metadata、Garage client
  query/             唯讀連線的 SQL authorizer 白名單 + 結構化 filter AST
  rpc/               stored RPC：prepare / registry / REST + MCP handler
  mcp/               rmcp tool 定義、Streamable HTTP service registry
  codegen/           每租戶 OpenAPI / TypeScript / Zod 自動產生器
  safety/            audit log + audit-DB writer、rate limiter、blast-radius 探測
  bin/set_admin_password.rs   外部密碼重設 CLI
  bin/set_admin_role.rs       admin role 切換（owner / member）
  bin/drust_session_janitor.rs  到期 session 清理（systemd 每日 timer）
docs/
  architecture.md    自動生成的程式碼索引（透過 gen-architecture.sh 重建）
CHANGELOG.md         遵循 keepachangelog 格式 + semver
CLAUDE.md            給 AI coding agent 看的內部指引
```

## 狀態

Production。目前版本 `v1.32.4`。完整變更歷史見 [CHANGELOG.md](CHANGELOG.md)。

## License

drust 採用 [GNU Affero General Public License v3.0](LICENSE)（AGPL-3.0-only）授權。

個人、內部或非商業用途的 self-hosting 完全在 AGPL-3.0 涵蓋範圍內。若您打算 (a) 將 drust（或其修改版）以託管服務形式提供給第三方使用，或 (b) 將 drust 整合進「無法依 AGPL 公開原始碼」的專屬產品，通常需要另外取得**商業授權**。

商業授權洽詢請於 GitHub 開 issue 並掛 `commercial-license` 標籤，或透過 GitHub profile 上列示的 email 聯繫維護者。
