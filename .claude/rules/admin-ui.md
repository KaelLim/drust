---
paths:
  - "src/mgmt/templates/**"
  - "src/mgmt/*.rs"
  - "build.rs"
  - "build_support/**"
  - "locales/**"
  - "themes/**"
---

# drust admin UI authoring contract

Fires when you touch an admin template, an `src/mgmt` handler, the build-time UI gates, a locale bundle, or a theme palette.

## Shell & layout

Two pages: `/admin/tenants` (search-able list) and `/admin/tenants/{id}/<datatable>` (2-pane shell). Every page renders inside a viewport-fixed `.macwin` with container-scoped scroll. 2-pane grid `var(--sidebar-w) minmax(0, 1fr)` lets right track shrink below content min-content (long URLs, wide tables).

Twelve virtual sidebar entries always shown in order — `_overview`, `_settings`, `_api_keys`, `_rpc`, `_broadcast`, `_system_files`, `_system_users`, `_oauth_providers`, `_webhooks`, `_functions`, `_cron`, `_logs` — then real collections from `sqlite_master`. Canonical order in `_collection_sidebar.html`. Each renders as an inline `<svg>` inside `<span class="nav-icon">` plus an i18n label — **not** emoji; only `ƒ` (`_functions`) is a literal glyph. `_system_files`' href is `/admin/tenants/{id}/_files`; only its `active_coll` sentinel is `_system_files`.

Header convention: eyebrow is `TENANT · <tenant name>`, `h1` is the plain title with no emoji, `_system_users` is labelled "End Users".

**Collection editor**: sticky header (title + `[⚙]` settings popover + inline description), a non-sticky Table-mode toolbar, and a sticky footer with `[Table] [Definition]` view tabs + pager. `Table` fetches rows via `POST /admin/tenants/<id>/collections/<coll>/_list` (FilterAst-backed); `Definition` shows fields + indexes inline. Legacy `?tab=…` URLs 302-redirect to `?view=…`.

Admin `_list` bypasses the read-only authorizer for `_system_*` tables (admin path; connection still `SQLITE_OPEN_READONLY`) and masks sensitive columns (`_system_users.password_hash`).

**Audit UI** (`/admin/audit` host + `/admin/tenants/<id>/_logs` per-tenant): browse-tab rows click-to-open via `drustUI.detail()` reading from an embedded `<script id="audit-entries">` JSON blob — the embed routes through the canonical `src/mgmt/script_json.rs` escaper (`</`→`<\/`, `<!--`, U+2028/9 — losslessly `JSON.parse`-identical; HTML5 §8.2.6.4 closes `<script>` on any literal `</script>` regardless of `type=`). Every admin JSON-into-`<script>` island MUST route through that one escaper — never re-inline the `.replace` dance.

**i18n**: `drust_locale` cookie → `Accept-Language` → `en`. `i18n.rs` (`Locale` + `Translator`) + `locale_layer.rs` (outermost middleware on admin router). Admin Templates carry a **private** `t: Translator` field (63 sites — NOT `pub`, which defeats the obvious verification grep). Bundles compiled in via `include_str!`; `build.rs` panics on missing keys at compile time. `en` and `zh-TW` each carry 944 keys with identical key sets.

**Theming**: three themes. `theme_layer.rs` is registered TWICE — outer cookie-only layer covers unauthenticated routes (`/login`, OAuth callback); inner DB-aware layer inside `protected` reads `admins.theme` when cookie is absent. Both share one resolver via `ThemeLayerState.allow_db_fallback: bool`. Palettes in `themes/<code>.toml`; `build.rs` enforces drift vs `EXPECTED_THEMES`. Cookie attrs `Path=/drust + Secure`; login + `/admin/settings` both route through `build_theme_cookie` / `build_locale_cookie` so attributes match (otherwise duplicate-Path cookies shadow saves).

**CORS** on tenant routes only, applied OUTSIDE `bearer_auth_layer` so OPTIONS preflight short-circuits before auth. Mgmt UI routes have no CORS layer.

## Admin 頁面解剖學

新增或修改 admin 頁面前先讀這節。七道 build.rs 閘會強制其中每一條 —— 違反的後果是 `cargo build` 失敗,不是 review 時才被發現。

**頁面骨架**(每個非 `_` 開頭的模板):

```jinja
{% extends "_base.html" %}
{% import "_ui.html" as ui %}
...
{% call ui::view_head(eyebrow, title, sub) %}
  <button class="btn primary">動作</button>
{% endcall %}
```

**元件庫 `_ui.html`** — 六個 macro,全部接受 caller body:

| Macro | 簽章 | caller body 內容 |
|---|---|---|
| `view_head` | `(eyebrow, title, sub)` | 標題右側的動作按鈕 |
| `data_table` | `(caption)` | `<thead>` + `<tbody>` |
| `empty_state` | `(chonk, title, sub)` | 補充說明 / CTA |
| `toolbar` | `()` | 篩選、排序、每頁筆數控制項 |
| `card` | `(title, sub)` | 卡片內容(自行決定是否包 `.card-body`) |
| `form_row` | `(label, hint)` | `<input>` / `<select>` / `<textarea>` |

不需要的文字參數傳 `""` 即省略該行。**含 markup 的說明文字放 caller body,不要傳進參數** —— 參數走自動跳脫,markup 會變成字面文字。

**按鈕正典**:`class="btn"` 加修飾詞 —— `sm`(小)、`icon`(方形圖示鈕)、`primary` / `ghost` / `danger`(變體)。例:`class="btn sm ghost"`。BEM 形式(`btn-sm`、`btn-ghost`、`btn-primary`、`btn-danger`)**已淘汰**,模板與 JS 字串皆不得使用。

**七道閘**(`build_support/ui_gates.rs`,由 `build.rs` 執行):

| 閘 | 規則 | 觸發時的修法 |
|---|---|---|
| `raw-hex` | 頁面模板禁生 hex 色 | 改用 `var(--token)`;品牌 logo SVG 移進 `_icons.html` |
| `missing-view-head` | 頁面必須呼叫 `ui::view_head` | 接上 macro,或宣告 `{# page-kind: standalone #}`(askama 註解,非 `{% block %}`) |
| `ghost-class` | 用到的 class 必須有 CSS 定義 | 在 `_styles.html` 補定義,或改用既有 class |
| `button-convention` | 禁用 BEM 按鈕 class | 改修飾詞形式 |
| `unsafe-safe-filter` | `\|safe` 只允許白名單來源 | 見下 |
| `ghost-css-var` | 用到的 `var(--x)` 必須有 `--x:` 定義(帶 fallback 也不豁免) | 在 `_styles.html` 補 `--x:` 定義,或改用既有變數 |
| `inline-handler-interp` | inline 事件處理器(`onclick=`/`onsubmit=`/`on*=`)禁內插動態 `{{ }}`,僅 `t.s("字面")` 豁免 | 值移到 `data-*` 屬性 + delegated handler,經 `textContent`(如 `drustUI.confirm`)呈現。瀏覽器先 entity-decode 屬性再當 JS 編譯,自動跳脫在此無效 |

> [!CAUTION]
> **`t.fmt<N>(…)` 與 `t.fmt<N>_html(…)` 只差一個尾綴,但只有後者跳脫插值參數。** 把前者接上 `|safe` 會重現 v1.49.3 修掉的 HIGH stored-XSS,而且**執行期測試抓不到**。閘 5 因此只允許以下 `|safe` 來源 —— 三種形狀規則:帶 `json` 底線區段的變數(`script_json.rs` 正典跳脫器)、`t.s("…")`(編譯期 bundle,key 必須是字面值)、`t.fmt<N>_html(…)`;外加兩條具名例外:`i18n_js`(同一個 `script_json` 跳脫器,名字早於 `_json` 慣例)與 `body_html`(CHANGELOG viewer 專屬,operator 控制的 markdown,綁定 `src/mgmt/docs.rs` 一個 handler)。新增任何一條都必須是經審查的刻意行為,且在 `is_allowlisted_safe_producer` 就地附註來源。

**豁免一律走宣告制。** 不得在 `build.rs` 或 `ui_gates.rs` 建立檔名豁免清單 —— 清單會腐化(「先加進清單」很快變成習慣),而模板內的宣告不會:新頁忘記宣告的後果是被閘擋下,fail-closed。

## Provenance

Extracted from CLAUDE.md "Admin UI" + "Admin 頁面解剖學" during the 2026-08-02 restructure.
