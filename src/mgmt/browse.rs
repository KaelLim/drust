use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::tenants::TenantsState;
use crate::storage::schema::{
    Collection, CollectionSchema, Field, IndexInfo, describe_collection, list_collections,
};
use crate::storage::tenant_db::open_read;
use askama::Template;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "collections.html")]
struct CollectionsPage {
    tenant_name: String,
    version: &'static str,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

#[derive(Template)]
#[template(path = "collection_rows.html")]
struct RowsPage {
    tenant_id: String,
    tenant_name: String,
    coll_name: String,
    active_coll: String,
    collections: Vec<Collection>,
    fields: Vec<Field>,
    /// Per-field rows enriched with `is_indexed`; consumed only by the
    /// schema tab to render PK / FK / IDX badge-mini chips. Built from
    /// `fields` × `indices` in the handler so the template can stay
    /// presentation-only.
    fields_with_badges: Vec<FieldRow>,
    /// Pairs of `(verb, currently_enabled)` for the four DML verbs in
    /// canonical order. Drives the checkbox row in the Anon tab editor.
    anon_cap_choices: Vec<(&'static str, bool)>,
    /// v1.16 — whether SSE broadcast is enabled for this collection. Drives
    /// the Realtime tab's single toggle.
    realtime_enabled: bool,
    /// Index list for the Indexes tab.
    indices: Vec<IndexInfo>,
    /// v1.19 — collection-level description for the description tile.
    collection_description: Option<String>,
    /// RLS v1.38 — pre-serialized `CollectionPolicies` JSON consumed by the
    /// settings popover's Policies panel to hydrate the per-op builders.
    policies_json: String,
    /// RLS v1.38 — the collection's `owner_field` (None when not owner-scoped).
    /// Drives the "this collection is owner-scoped; explicit policies AND with
    /// the owner rule" note in the Policies panel (§6.2).
    owner_field: Option<String>,
    /// RLS v1.38 — `owner_field` pre-serialized as a JSON string|null for the
    /// JS module (avoids the non-existent `|json` askama filter).
    owner_field_json: String,
    /// v1.19.1 — error code surfaced when the description form bounced off
    /// the server-side validator. `None` on the plain GET render.
    desc_error: Option<String>,
    /// v1.28 — pre-serialized JSON strings injected into the JS module so
    /// the template avoids the non-existent `|json|safe` askama filter.
    fields_json: String,
    tenant_id_json: String,
    coll_name_json: String,
    version: &'static str,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// Field row enriched with badge flags, consumed by the schema tab.
/// `is_indexed` is set when the field name appears in any explicit
/// index on this collection (PK columns surface via `pk` instead, so
/// `is_indexed` is only useful when the field is *also* covered by a
/// non-PK explicit index — the template hides IDX when `pk` is true).
struct FieldRow {
    name: String,
    sql_type: String,
    nullable: bool,
    pk: bool,
    foreign_key: Option<String>,
    default_value: Option<String>,
    is_indexed: bool,
    /// v1.19 — per-field description, threaded from `Field::description`.
    description: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct BrowseQs {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
    /// `data` (default) or `schema`. Anything else falls back to `data`.
    #[serde(default)]
    pub tab: Option<String>,
    /// v1.19.1 — surfaced after a server-side description validator failure
    /// (e.g. NUL byte slipped past the JS hint). Rendered as an inline
    /// error banner on the schema/indexes tab.
    #[serde(default)]
    pub desc_error: Option<String>,
}

fn tenant_active(conn: &rusqlite::Connection, tenant_id: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tenant_id],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

fn tenant_name_lookup(conn: &rusqlite::Connection, tenant_id: &str) -> Option<String> {
    conn.query_row(
        "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tenant_id],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

pub async fn collections_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    let tenant_name = tenant_name_lookup(&meta, &tenant_id).unwrap_or_else(|| tenant_id.clone());
    drop(meta);

    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let collections = match list_collections(&conn) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if let Some(first) = collections.first() {
        let to = crate::base_path::base(&format!(
            "/admin/tenants/{}/collections/{}",
            tenant_id, first.name
        ));
        return Redirect::to(&to).into_response();
    }

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        CollectionsPage {
            tenant_name,
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Replace cell values in columns that should never appear in HTML
/// (e.g. password hashes). Returns the column names unchanged and the
/// masked rows. When there are no sensitive columns for the given
/// collection name this is a zero-cost passthrough.
pub(crate) fn mask_sensitive_columns(
    coll: &str,
    column_names: Vec<String>,
    rows: Vec<Vec<String>>,
) -> (Vec<String>, Vec<Vec<String>>) {
    let mask_cols: &[&str] = match coll {
        "_system_users" => &["password_hash"],
        "_system_oauth_providers" => &["client_secret"],
        "_system_webhooks" => &["secret"],
        _ => &[],
    };
    if mask_cols.is_empty() {
        return (column_names, rows);
    }
    let masked_idxs: Vec<usize> = column_names
        .iter()
        .enumerate()
        .filter(|(_, n)| mask_cols.contains(&n.as_str()))
        .map(|(i, _)| i)
        .collect();
    if masked_idxs.is_empty() {
        return (column_names, rows);
    }
    let masked_rows = rows
        .into_iter()
        .map(|row| {
            row.into_iter()
                .enumerate()
                .map(|(i, v)| {
                    if masked_idxs.contains(&i) {
                        "\u{25cf}\u{25cf}\u{25cf}\u{25cf}".to_string()
                    } else {
                        v
                    }
                })
                .collect()
        })
        .collect();
    (column_names, masked_rows)
}

/// Build the three pre-serialized JSON strings the collection-editor template
/// inlines into its JS module, every one routed through the canonical
/// `<script>`-safe escaper. `fields` carries tenant-controlled free text
/// (per-field `description`), so escaping here is load-bearing, not cosmetic.
fn editor_json_payloads<F: serde::Serialize>(
    fields: &[F],
    tenant_id: &str,
    coll_name: &str,
) -> (String, String, String) {
    use crate::mgmt::script_json::json_for_script;
    (
        json_for_script(fields),
        json_for_script(tenant_id),
        json_for_script(coll_name),
    )
}

/// RLS v1.38 — `<script>`-safe escaper for the settings popover's Policies
/// panel payloads. A `Policy` FilterAst literal operand is arbitrary
/// tenant-supplied free text, so a stored `</script>` literal must not be
/// able to break out of the JS island — these MUST route through the
/// canonical escaper exactly like `editor_json_payloads`, never a raw
/// `serde_json::to_string` (drust/CLAUDE.md script-island invariant).
/// `owner_field` is a validated SQL column name, escaped here too for
/// defense-in-depth / consistency. Returns `(policies_json, owner_field_json)`.
fn policy_json_payloads(
    policies: &crate::query::policy::CollectionPolicies,
    owner_field: &Option<String>,
) -> (String, String) {
    use crate::mgmt::script_json::json_for_script;
    (json_for_script(policies), json_for_script(owner_field))
}

pub async fn collection_rows_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    Query(qs): Query<BrowseQs>,
) -> Response {
    // v1.28 back-compat: legacy ?tab=... values now map to ?view=... on the
    // redesigned editor. ?tab=schema|indexes → ?view=definition; the other
    // three tabs (anon, realtime, explain) live in the settings popover
    // now, so we land users on the Table view.
    if let Some(tab) = qs.tab.as_deref() {
        let view = match tab {
            "schema" | "indexes" => Some("definition"),
            "anon" | "realtime" | "explain" => Some("table"),
            _ => None,
        };
        if let Some(v) = view {
            let to = crate::base_path::base(&format!(
                "/admin/tenants/{tenant_id}/collections/{coll_name}?view={v}"
            ));
            return Redirect::to(&to).into_response();
        }
    }

    // v1.28 back-compat: ?filter=<raw SQL> is dropped — no safe translation
    // exists. Log it so we can audit how many users hit it post-deploy.
    if qs.filter.as_deref().filter(|s| !s.is_empty()).is_some() {
        tracing::info!(
            target: "drust::admin",
            tenant_id = %tenant_id, coll_name = %coll_name, filter = ?qs.filter,
            "v1.28 back-compat: legacy ?filter= seen; param dropped"
        );
    }

    let meta = state.session.meta.lock().await;
    let tenant_name = match tenant_name_lookup(&meta, &tenant_id) {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    drop(meta);

    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let schema: CollectionSchema = match describe_collection(&conn, &coll_name) {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, "collection not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let collections = match list_collections(&conn) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // v1.16 — pull the current SSE broadcast flag off the same schema row
    // we already loaded above. `describe_collection` falls back to true
    // when no `_system_collection_meta` row exists yet.
    let realtime_enabled = schema.realtime_enabled;

    // Cross-reference indices to mark fields that participate in any
    // explicit index. Used by the Definition view to render an IDX badge.
    let indexed_fields: std::collections::HashSet<String> = schema
        .indices
        .iter()
        .flat_map(|idx| idx.fields.iter().cloned())
        .collect();
    let fields_with_badges: Vec<FieldRow> = schema
        .fields
        .iter()
        .map(|f| FieldRow {
            name: f.name.clone(),
            sql_type: f.sql_type.clone(),
            nullable: f.nullable,
            pk: f.pk,
            foreign_key: f.foreign_key.clone(),
            default_value: f.default_value.clone(),
            is_indexed: indexed_fields.contains(&f.name),
            description: f.description.clone(),
        })
        .collect();

    // Materialise the four DML verbs with their current on/off state so
    // the template can iterate without knowing about `BTreeSet<DmlVerb>`.
    let current_caps = schema.anon_caps.clone();
    let anon_cap_choices: Vec<(&'static str, bool)> = ["select", "insert", "update", "delete"]
        .iter()
        .map(|v| {
            let verb = match *v {
                "select" => crate::storage::schema::DmlVerb::Select,
                "insert" => crate::storage::schema::DmlVerb::Insert,
                "update" => crate::storage::schema::DmlVerb::Update,
                "delete" => crate::storage::schema::DmlVerb::Delete,
                _ => unreachable!(),
            };
            (*v, current_caps.contains(&verb))
        })
        .collect();

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    let (fields_json, tenant_id_json, coll_name_json) =
        editor_json_payloads(&schema.fields, &tenant_id, &coll_name);
    // RLS v1.38 — serialize the stored policy set + owner_field for the
    // settings popover's Policies panel. Both carry tenant-controlled free
    // text (a `Policy` FilterAst literal operand is an arbitrary tenant-
    // supplied string), so they MUST route through the canonical
    // `<script>`-island escaper exactly like `fields_json` above — a raw
    // `serde_json::to_string` would let a stored `</script>` literal break
    // out of the JS island (drust/CLAUDE.md script-island invariant).
    let owner_field = schema.owner_field.clone();
    let (policies_json, owner_field_json) = policy_json_payloads(&schema.policies, &owner_field);
    Html(
        RowsPage {
            tenant_id,
            tenant_name,
            active_coll: coll_name.clone(),
            coll_name,
            collections,
            fields: schema.fields,
            fields_with_badges,
            indices: schema.indices,
            anon_cap_choices,
            realtime_enabled,
            collection_description: schema.description,
            policies_json,
            owner_field,
            owner_field_json,
            desc_error: qs.desc_error.clone(),
            fields_json,
            tenant_id_json,
            coll_name_json,
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Form payload for the anon_caps editor on the Schema tab. Empty
/// `caps` means "lock the collection" (anon role gets nothing).
#[derive(serde::Deserialize)]
pub struct AnonCapsForm {
    #[serde(default)]
    pub caps: Vec<String>,
}

/// POST `/admin/tenants/{tenant}/collections/{coll}/anon-caps`.
///
/// Writes the new capability set to `_system_collection_meta` and
/// invalidates the in-process schema cache for the collection so the
/// next REST/MCP request re-reads from SQLite. Unknown verb strings in
/// the form are silently dropped — the UI only ever submits the four
/// canonical names.
pub async fn update_anon_caps(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    // Use axum_extra::Form (serde_html_form) — the stdlib serde_urlencoded
    // backing axum::Form cannot deserialize repeated keys (`caps=select&caps=insert`)
    // into Vec<String>, so the HTML checkbox form would 422 on every submit.
    axum_extra::extract::Form(form): axum_extra::extract::Form<AnonCapsForm>,
) -> Response {
    use crate::storage::schema::{DmlVerb, write_anon_caps};
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let mut caps = std::collections::BTreeSet::new();
    for v in form.caps {
        match v.as_str() {
            "select" => {
                caps.insert(DmlVerb::Select);
            }
            "insert" => {
                caps.insert(DmlVerb::Insert);
            }
            "update" => {
                caps.insert(DmlVerb::Update);
            }
            "delete" => {
                caps.insert(DmlVerb::Delete);
            }
            _ => {}
        }
    }
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let coll_for_writer = coll_name.clone();
    let caps_for_writer = caps.clone();
    if let Err(e) = pool
        .with_writer(move |c| write_anon_caps(c, &coll_for_writer, &caps_for_writer))
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Invalidate the per-tenant schema cache for this collection so the
    // next REST/MCP request through the tenant router sees the new gate
    // immediately, not after the next DDL or process restart.
    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema"
    )))
    .into_response()
}

/// Form payload for the Realtime tab toggle.
///
/// Browser checkbox semantics: a checked box submits `enabled=1`; an
/// unchecked box omits the field entirely. We map "field present" → on,
/// "field absent" → off.
#[derive(serde::Deserialize)]
pub struct RealtimeForm {
    #[serde(default)]
    pub enabled: Option<String>,
}

/// POST `/admin/tenants/{tenant}/collections/{coll}/realtime`.
///
/// Form submit from the Realtime tab. Flips the flag, invalidates the
/// schema cache, and evicts the broadcast channel on disable so any
/// in-flight SSE connection terminates immediately.
pub async fn update_realtime(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    axum_extra::extract::Form(form): axum_extra::extract::Form<RealtimeForm>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let enabled = form.enabled.is_some();
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let coll_for_writer = coll_name.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            crate::storage::schema::write_realtime_enabled(c, &coll_for_writer, enabled)
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Cache invalidate BEFORE bus evict — mirrors the REST handler's
    // ordering so any subscriber racing in between reads fresh schema.
    pool.schema_cache.invalidate(&coll_name);
    if !enabled {
        state.bus.evict_collection(&tenant_id, &coll_name);
    }
    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=realtime"
    )))
    .into_response()
}

/// JSON body for the admin policy editor. Each op is optional; `Some` replaces
/// that op's stored policy, `None` (key absent) clears it. Mirrors the
/// data-plane `tenant::policy_routes::PutPoliciesBody` shape so the same JSON
/// the [⚙] popover's "view JSON" disclosure shows round-trips through either
/// surface.
#[derive(serde::Deserialize)]
pub struct AdminPoliciesBody {
    #[serde(default)]
    pub select: Option<crate::query::policy::Policy>,
    #[serde(default)]
    pub insert: Option<crate::query::policy::Policy>,
    #[serde(default)]
    pub update: Option<crate::query::policy::Policy>,
    #[serde(default)]
    pub delete: Option<crate::query::policy::Policy>,
}

/// POST `/admin/tenants/{id}/collections/{coll}/policies`
///
/// Admin-plane wrapper over `write_policy` — the [⚙] settings popover's
/// Policies panel posts here via `fetch()` (the admin UI holds the admin
/// session, not a bearer token, so it cannot reuse the service-only data-plane
/// `PUT …/policies` route). Validates each supplied policy and replaces the
/// stored set in one writer transaction (existence + `validate_policy` run
/// INSIDE the writer closure, TOCTOU-safe — mirrors `put_policies` and
/// `set_owner_field`), then invalidates the schema cache. Returns JSON,
/// matching the other admin JSON endpoints (`create_index_admin`,
/// `explain_admin`).
pub async fn admin_update_policies(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    Json(body): Json<AdminPoliciesBody>,
) -> Response {
    use crate::storage::schema::{DmlVerb, is_protected_collection};
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    if is_protected_collection(&coll_name) {
        return json_err(
            StatusCode::FORBIDDEN,
            "PROTECTED_COLLECTION",
            "cannot set policies on a _system_* collection",
        );
    }

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let cache = pool.schema_cache.clone();
    let coll_c = coll_name.clone();
    let res = pool
        .with_writer(move |c| {
            // Existence + validation INSIDE the writer closure (TOCTOU-safe,
            // mirrors put_policies / set_owner_field).
            let schema = match crate::storage::schema::describe_collection(c, &coll_c)? {
                Some(s) => s,
                None => {
                    return Ok(Err((
                        "COLLECTION_NOT_FOUND",
                        "no such collection".to_string(),
                    )));
                }
            };
            for (op, p) in [
                (DmlVerb::Select, &body.select),
                (DmlVerb::Insert, &body.insert),
                (DmlVerb::Update, &body.update),
                (DmlVerb::Delete, &body.delete),
            ] {
                if let Some(policy) = p
                    && let Err(e) = crate::query::policy::validate_policy(&schema, op, policy)
                {
                    return Ok(Err(("POLICY_INVALID", e.to_string())));
                }
                crate::storage::schema::write_policy(c, &coll_c, op, p.as_ref())?;
            }
            Ok(Ok(()))
        })
        .await;
    cache.invalidate(&coll_name);
    match res {
        Ok(Ok(())) => axum::Json(serde_json::json!({"ok": true})).into_response(),
        Ok(Err((code @ "COLLECTION_NOT_FOUND", msg))) => {
            json_err(StatusCode::NOT_FOUND, code, &msg)
        }
        Ok(Err((code, msg))) => json_err(StatusCode::BAD_REQUEST, code, &msg),
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

/// Build a JSON error body with `error_code` + `message`, matching the shape
/// the other admin JSON endpoints (`create_index_admin`, `explain_admin`) emit.
fn json_err(status: StatusCode, code: &str, msg: &str) -> Response {
    let body = serde_json::json!({ "error_code": code, "message": msg });
    let mut r = axum::Json(body).into_response();
    *r.status_mut() = status;
    r
}

// ── Admin index DDL endpoints ─────────────────────────────────────────────────
// These are JSON-returning endpoints called via fetch() from the admin UI
// (Tasks 19/20). They use the same admin-session middleware as all other
// tenants_router routes — no explicit session extractor needed.

#[derive(serde::Deserialize)]
pub struct AdminCreateIndexBody {
    pub fields: Vec<String>,
    #[serde(default)]
    pub unique: Option<bool>,
    #[serde(default)]
    pub force: Option<bool>,
}

/// POST `/admin/tenants/{id}/collections/{coll}/_indexes`
///
/// Create an index on a collection. Returns JSON. Admin-session-protected
/// (via the wrapping `admin_session_layer` on `tenants_router`).
pub async fn create_index_admin(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    Json(body): Json<AdminCreateIndexBody>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    match crate::mcp::tools::index::create_index_with_threshold(
        &pool,
        &coll_name,
        &body.fields,
        body.unique.unwrap_or(false),
        body.force.unwrap_or(false),
        state.index_large_table_rows,
    )
    .await
    {
        Ok(v) => (StatusCode::CREATED, axum::Json(v)).into_response(),
        Err(e) => {
            use axum::Json;
            let msg = e.to_string();
            let (status, code) = map_index_admin_error(&msg);
            let body = serde_json::json!({ "error_code": code, "message": msg });
            let mut r = Json(body).into_response();
            *r.status_mut() = status;
            r
        }
    }
}

/// DELETE `/admin/tenants/{id}/collections/{coll}/_indexes/{name}`
///
/// Drop an index by name. Returns JSON.
pub async fn drop_index_admin(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name, index_name)): Path<(String, String, String)>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    match crate::mcp::tools::index::drop_index(&pool, &coll_name, Some(&index_name), None).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => {
            use axum::Json;
            let msg = e.to_string();
            let (status, code) = map_index_admin_error(&msg);
            let body = serde_json::json!({ "error_code": code, "message": msg });
            let mut r = Json(body).into_response();
            *r.status_mut() = status;
            r
        }
    }
}

/// POST `/admin/tenants/{id}/collections/{coll}/_explain`
///
/// Run `EXPLAIN QUERY PLAN` on a SQL string. Returns JSON `{"plan":[...]}`.
pub async fn explain_admin(
    State(state): State<TenantsState>,
    Path((tenant_id, _coll_name)): Path<(String, String)>,
    Json(body): Json<crate::tenant::query_endpoint::ExplainBody>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    match crate::mcp::tools::index::explain_select(&pool, &body.sql).await {
        Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
        Err(e) => {
            use axum::Json;
            let msg = e.to_string();
            let (status, code) = if msg.contains("not authorized")
                || msg.contains("authorizer")
                || msg.contains("prohibited")
            {
                (StatusCode::BAD_REQUEST, "SQL_NOT_ALLOWED")
            } else if msg.contains("syntax") || msg.contains("near") {
                (StatusCode::BAD_REQUEST, "SQL_PARSE_ERROR")
            } else {
                (StatusCode::BAD_REQUEST, "SQL_ERROR")
            };
            let body = serde_json::json!({ "error_code": code, "message": msg });
            let mut r = Json(body).into_response();
            *r.status_mut() = status;
            r
        }
    }
}

// ── Description admin POST endpoints (v1.19) ─────────────────────────────────
// Three form-POST routes that proxy to the write_*_description helpers.
// Auth shape is identical to update_anon_caps (same session middleware wraps
// all /admin/tenants/* routes — no explicit extractor needed).

/// Shared form body for the three description endpoints.
#[derive(serde::Deserialize)]
pub struct DescriptionForm {
    #[serde(default)]
    pub description: String,
}

/// POST `/admin/tenants/{id}/collections/{coll}/description`
pub async fn admin_update_collection_description(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    axum::extract::Form(form): axum::extract::Form<DescriptionForm>,
) -> Response {
    use crate::storage::schema::{
        check_description, collection_exists, is_protected_collection, write_collection_description,
    };
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    if is_protected_collection(&coll_name) {
        return (
            StatusCode::FORBIDDEN,
            "cannot set description on a _system_* collection",
        )
            .into_response();
    }

    let validated = match check_description(&form.description) {
        Ok(v) => v,
        Err((code, _)) => {
            return Redirect::to(&crate::base_path::base(&format!(
                "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema&desc_error={code}"
            )))
            .into_response();
        }
    };
    let value: Option<String> = if validated.is_empty() {
        None
    } else {
        Some(validated)
    };

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Existence check before any write.
    let coll_for_check = coll_name.clone();
    let exists = match pool
        .with_reader(move |c| collection_exists(c, &coll_for_check))
        .await
    {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !exists {
        return (StatusCode::NOT_FOUND, "no such collection").into_response();
    }

    let coll_for_writer = coll_name.clone();
    let value_for_writer = value.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            write_collection_description(c, &coll_for_writer, value_for_writer.as_deref())
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema"
    )))
    .into_response()
}

/// POST `/admin/tenants/{id}/collections/{coll}/fields/{field}/description`
pub async fn admin_update_field_description(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name, field_name)): Path<(String, String, String)>,
    axum::extract::Form(form): axum::extract::Form<DescriptionForm>,
) -> Response {
    use crate::storage::schema::{
        check_description, describe_collection, is_protected_collection, write_field_description,
    };
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    if is_protected_collection(&coll_name) {
        return (
            StatusCode::FORBIDDEN,
            "cannot set description on a _system_* collection",
        )
            .into_response();
    }

    let validated = match check_description(&form.description) {
        Ok(v) => v,
        Err((code, _)) => {
            return Redirect::to(&crate::base_path::base(&format!(
                "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema&desc_error={code}"
            )))
            .into_response();
        }
    };
    let value: Option<String> = if validated.is_empty() {
        None
    } else {
        Some(validated)
    };

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Existence: collection + field both must exist.
    let coll_for_check = coll_name.clone();
    let cs = match pool
        .with_reader(move |c| describe_collection(c, &coll_for_check))
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such collection").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !cs.fields.iter().any(|f| f.name == field_name) {
        return (StatusCode::NOT_FOUND, "no such field").into_response();
    }

    let coll_for_writer = coll_name.clone();
    let field_for_writer = field_name.clone();
    let value_for_writer = value.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            write_field_description(
                c,
                &coll_for_writer,
                &field_for_writer,
                value_for_writer.as_deref(),
            )
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema"
    )))
    .into_response()
}

/// POST `/admin/tenants/{id}/collections/{coll}/indexes/{index_name}/description`
pub async fn admin_update_index_description(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name, index_name)): Path<(String, String, String)>,
    axum::extract::Form(form): axum::extract::Form<DescriptionForm>,
) -> Response {
    use crate::storage::schema::{
        check_description, describe_collection, is_protected_collection, write_index_description,
    };
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    if is_protected_collection(&coll_name) {
        return (
            StatusCode::FORBIDDEN,
            "cannot set description on a _system_* collection",
        )
            .into_response();
    }

    let validated = match check_description(&form.description) {
        Ok(v) => v,
        Err((code, _)) => {
            return Redirect::to(&crate::base_path::base(&format!(
                "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=indexes&desc_error={code}"
            )))
            .into_response();
        }
    };
    let value: Option<String> = if validated.is_empty() {
        None
    } else {
        Some(validated)
    };

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Existence: collection + index both must exist.
    let coll_for_check = coll_name.clone();
    let cs = match pool
        .with_reader(move |c| describe_collection(c, &coll_for_check))
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such collection").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !cs.indices.iter().any(|i| i.name == index_name) {
        return (StatusCode::NOT_FOUND, "no such index").into_response();
    }

    let coll_for_writer = coll_name.clone();
    let idx_for_writer = index_name.clone();
    let value_for_writer = value.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            write_index_description(
                c,
                &coll_for_writer,
                &idx_for_writer,
                value_for_writer.as_deref(),
            )
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/collections/{coll_name}?tab=indexes"
    )))
    .into_response()
}

fn map_index_admin_error(msg: &str) -> (StatusCode, &'static str) {
    if msg.contains("no such collection") || msg.contains("no such index") {
        (StatusCode::NOT_FOUND, "NOT_FOUND")
    } else if msg.contains("not found on collection") {
        (StatusCode::NOT_FOUND, "FIELD_NOT_FOUND")
    } else if msg.contains("LARGE_TABLE") {
        (StatusCode::CONFLICT, "LARGE_TABLE")
    } else if msg.contains("already exists") {
        (StatusCode::CONFLICT, "INDEX_EXISTS")
    } else if msg.contains("UNIQUE") || msg.contains("unique") {
        (StatusCode::CONFLICT, "UNIQUE_VIOLATION")
    } else if msg.contains("INVALID_PARAMS")
        || msg.contains("must be non-empty")
        || msg.contains("non-empty")
        || msg.contains("duplicate")
    {
        (StatusCode::BAD_REQUEST, "INVALID_PARAMS")
    } else if msg.contains("invalid identifier") {
        (StatusCode::BAD_REQUEST, "INVALID_IDENTIFIER")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
    }
}

#[cfg(test)]
mod editor_payload_tests {
    use super::editor_json_payloads;
    // Pin the regression to the EXACT type the handler serializes
    // (`schema.fields: Vec<storage::schema::Field>`). `Field.description` is
    // tenant-controlled free text (sourced from `_system_collection_meta`), so
    // it is the live stored-XSS vector — testing the parallel `FieldSpec` type
    // would not catch a future `#[serde(skip)]` on the real field.
    use crate::storage::schema::Field;

    #[test]
    fn fields_payload_escapes_hostile_description() {
        let fields = vec![Field {
            name: "n".into(),
            sql_type: "text".into(),
            nullable: true,
            pk: false,
            default_value: None,
            foreign_key: None,
            description: Some("</script><img src=x onerror=alert(1)>".into()),
        }];
        let (fields_json, tid_json, coll_json) = editor_json_payloads(&fields, "t-1", "posts");
        // The hostile description really is serialized into the payload …
        assert!(
            fields_json.contains("onerror=alert(1)"),
            "description must reach the payload: {fields_json}"
        );
        // … but its `</script>` closer is neutralized.
        assert!(
            !fields_json.contains("</script>"),
            "live closer leaked: {fields_json}"
        );
        assert!(
            fields_json.contains("<\\/script>"),
            "closer not escaped: {fields_json}"
        );
        // Identifiers round-trip untouched.
        assert_eq!(tid_json, "\"t-1\"");
        assert_eq!(coll_json, "\"posts\"");
    }

    // RLS v1.38 — the Policies panel injects `policies_json` into the page
    // `<script>` island via `policy_json_payloads` (the same path the handler
    // calls). A `Policy` FilterAst literal operand is arbitrary tenant-supplied
    // free text, so a stored `</script>` literal must NOT be able to break out
    // of the JS island. This pins that the real handler helper neutralizes the
    // closer (and that the naive `serde_json::to_string` the review caught
    // would have leaked it).
    #[test]
    fn policies_payload_escapes_hostile_literal() {
        use super::policy_json_payloads;
        use crate::query::policy::{CollectionPolicies, Policy};
        use crate::query::vector_filter::FilterAst;

        let mut leaf = serde_json::Map::new();
        leaf.insert(
            "title".into(),
            serde_json::json!({ "$eq": "</script><img src=x onerror=alert(1)>" }),
        );
        let policies = CollectionPolicies {
            select: Some(Policy {
                using: Some(FilterAst::Leaf(leaf)),
                check: None,
            }),
            ..Default::default()
        };

        // What the handler actually emits.
        let (policies_json, _) = policy_json_payloads(&policies, &None);
        // The hostile literal really is serialized into the payload …
        assert!(
            policies_json.contains("onerror=alert(1)"),
            "literal must reach the payload: {policies_json}"
        );
        // … but its `</script>` closer is neutralized.
        assert!(
            !policies_json.contains("</script>"),
            "live closer leaked: {policies_json}"
        );
        assert!(
            policies_json.contains("<\\/script>"),
            "closer not escaped: {policies_json}"
        );

        // Guard against regressing to the naive path the review rejected: the
        // raw serializer would leave the live `</script>` closer intact, so
        // this assertion proves the test is not vacuous.
        let raw = serde_json::to_string(&policies).unwrap();
        assert!(
            raw.contains("</script>"),
            "test is vacuous unless the naive path leaks the closer: {raw}"
        );
    }

    // RLS v1.38 — `owner_field_json` shares the island; a validated SQL column
    // name is not exploitable in practice, but it MUST use the same escaper for
    // defense-in-depth / consistency (per the review). Pin that None → `null`
    // and a value round-trips through the handler helper unchanged.
    #[test]
    fn owner_field_payload_uses_escaper() {
        use super::policy_json_payloads;
        use crate::query::policy::CollectionPolicies;
        let empty = CollectionPolicies::default();
        let (_, none_json) = policy_json_payloads(&empty, &None);
        assert_eq!(none_json, "null");
        let (_, some_json) = policy_json_payloads(&empty, &Some("user_id".to_string()));
        assert_eq!(some_json, "\"user_id\"");
    }

    const MASK: &str = "\u{25cf}\u{25cf}\u{25cf}\u{25cf}";

    #[test]
    fn mask_oauth_client_secret() {
        let (_cols, rows) = super::mask_sensitive_columns(
            "_system_oauth_providers",
            vec!["provider".into(), "client_secret".into()],
            vec![vec!["google".into(), "supersecret".into()]],
        );
        assert_eq!(rows[0][1], MASK);
        assert_eq!(rows[0][0], "google");
    }

    #[test]
    fn mask_webhook_secret() {
        let (_cols, rows) = super::mask_sensitive_columns(
            "_system_webhooks",
            vec!["url".into(), "secret".into()],
            vec![vec!["https://x".into(), "deadbeef".into()]],
        );
        assert_eq!(rows[0][1], MASK);
    }

    #[test]
    fn mask_still_masks_password_hash() {
        let (_cols, rows) = super::mask_sensitive_columns(
            "_system_users",
            vec!["email".into(), "password_hash".into()],
            vec![vec!["a@b".into(), "$argon2$".into()]],
        );
        assert_eq!(rows[0][1], MASK);
    }
}
