//! Tenant-files admin page (group D). Relocated from `tenants.rs` by Finding #4.
//!
//! v1.63 (#950-B) also makes this page the only Files-RLS face an operator
//! holding an admin SESSION can reach: the REST (`/t/<id>/file-policies`) and
//! MCP registry faces both demand a service bearer, which the admin plane does
//! not carry. The two write endpoints at the bottom of this file are that face
//! — thin admin-plane wrappers over the SAME `storage::file_policy` core, in
//! the spirit of `browse::admin_update_policies`. They add no rule of their
//! own: validation, the four error codes, and the storage half are T3's.

use super::TenantsState;
use crate::mgmt::format::humanize_bytes;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::storage::file_policy::{
    FilePolicyError, FilePolicyRow, delete_file_policy, load_file_policies, longest_match,
    upsert_file_policy, validate_file_policy,
};
use crate::storage::tenant_db::open_read;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

// ─── Admin tenant-files subpage (Task 21) ────────────────────────────────────

/// A single file row for the admin tenant-files view.
struct AdminTenantFileRow {
    key: String,
    original_name: String,
    content_type: String,
    size_human: String,
    visibility: String,
    uploaded_at: String,
    public_url: String,
    /// v1.63 — the caller-declared logical path, `None` for an unfiled row.
    /// Metadata only: the bytes still live under the flat `key`.
    path: Option<String>,
}

/// One rendered group of the fake folder tree.
///
/// "Fake" is the whole point: drust has no folder object, no folder table and
/// no folder API. A group is `path` up to and including its last `/`, computed
/// at RENDER time over the rows this page already fetched — so two files
/// sharing a path are two rows, a folder with no files does not exist, and
/// nothing here can ever disagree with storage.
struct AdminFileFolder {
    /// `""` = the tenant root (a path with no `/` in it), `avatars/alice/`
    /// otherwise. Empty for the unfiled group too — read `unfiled` first.
    prefix: String,
    /// Rows with `path IS NULL`. Distinct from the root group: unfiled rows
    /// only ever match the `''` REGISTRY prefix, never a named one.
    unfiled: bool,
    /// The registered prefix governing every row in this group, if any.
    ///
    /// One lookup for the whole group is EXACT, not an approximation: a
    /// registered prefix is `''` or ends with `/`, so any prefix matching a
    /// file path either is a prefix of the folder as well, or would have to
    /// extend past the last `/` into the file name — impossible for a value
    /// ending in `/`.
    governed_by: Option<String>,
    files: Vec<AdminTenantFileRow>,
}

/// One row of the folder-rule card.
struct AdminFilePolicyView {
    prefix: String,
    owner_scoped: bool,
    public_read: bool,
    /// Compact JSON of the clause, rendered read-only. The card's own form
    /// cannot author clauses — REST and MCP can, and a rule they created must
    /// still be legible here rather than silently summarized as "no rule".
    select_json: Option<String>,
    delete_json: Option<String>,
    /// v1.64 (#974) — the publish grant, pre-joined for display (`"anon, user"`).
    /// `None` = the prefix grants nobody, which is the deny-by-default state and
    /// renders as no pill at all.
    public_upload_roles: Option<String>,
}

#[derive(Template)]
#[template(path = "tenant_files_admin.html")]
struct TenantFilesAdminPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    /// This page's rows, grouped for the folder tree. Empty ⇒ empty state.
    folders: Vec<AdminFileFolder>,
    /// The tenant's `_system_file_policy` rows, for the folder-rule card.
    policies: Vec<AdminFilePolicyView>,
    /// Set when the registry could not be read. Surfaced rather than swallowed:
    /// the same failure makes every non-service file read DENY (T4), so an
    /// operator seeing "no files are readable" needs to see this line.
    policy_error: Option<String>,
    total_files: usize,
    used_mb_display: String,
    storage_available: bool,
    max_upload_mb: u64,
    disk: crate::mgmt::public_files::DiskView,
    /// Driver list for `_collection_sidebar.html`.
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_system_files"` here — kept for sidebar `.on` matching.
    active_coll: String,
    page: u32,
    total_pages: u32,
    prev_url: Option<String>,
    next_url: Option<String>,
    per_page_options: Vec<TenantFilesPerPageOption>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

#[derive(Clone)]
pub struct TenantFilesPerPageOption {
    pub value: u32,
    pub selected: bool,
}

const TENANT_FILES_DEFAULT_PER_PAGE: u32 = 25;
const TENANT_FILES_PER_PAGE_OPTIONS: &[u32] = &[10, 25, 50, 100];

/// The folder a declared path belongs to: everything up to and including its
/// last `/`, or `""` when it carries none. Byte-indexed on `/` (ASCII, so a
/// multi-byte character can never contain it) — the same reason the RLS prefix
/// match is a byte range and not `substr`.
fn folder_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "",
    }
}

/// Group one page of rows into the fake folder tree, preserving the SQL order
/// (`uploaded_at DESC`) both for the groups — by first appearance — and within
/// each group. Grouping is per PAGE on purpose: it is a rendering of the rows
/// the pager already chose, never a second query with a different order.
fn group_into_folders(
    rows: Vec<AdminTenantFileRow>,
    policies: &[FilePolicyRow],
) -> Vec<AdminFileFolder> {
    let mut out: Vec<AdminFileFolder> = Vec::new();
    for row in rows {
        let (prefix, unfiled) = match row.path.as_deref() {
            Some(p) => (folder_of(p).to_string(), false),
            None => (String::new(), true),
        };
        match out
            .iter_mut()
            .find(|g| g.unfiled == unfiled && g.prefix == prefix)
        {
            Some(g) => g.files.push(row),
            None => {
                let probe = if unfiled { None } else { Some(prefix.as_str()) };
                let governed_by = longest_match(policies, probe).map(|p| p.prefix.clone());
                out.push(AdminFileFolder {
                    prefix,
                    unfiled,
                    governed_by,
                    files: vec![row],
                });
            }
        }
    }
    out
}

/// Registry rows in card shape. Clause JSON is re-serialized (not the stored
/// text) so a hand-edited row renders canonically.
fn policy_views(policies: &[FilePolicyRow]) -> Vec<AdminFilePolicyView> {
    policies
        .iter()
        .map(|p| AdminFilePolicyView {
            prefix: p.prefix.clone(),
            owner_scoped: p.owner_scoped,
            public_read: p.public_read,
            select_json: p
                .select_policy
                .as_ref()
                .and_then(|a| serde_json::to_string(a).ok()),
            delete_json: p
                .delete_policy
                .as_ref()
                .and_then(|a| serde_json::to_string(a).ok()),
            public_upload_roles: p.public_upload_roles.as_ref().map(|r| r.join(", ")),
        })
        .collect()
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct TenantFilesListQs {
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

/// GET /admin/tenants/{id}/files
/// Renders the tenant's _system_files with upload form + per-row actions.
/// Admin uploads go to the tenant's own buckets (tenant-{id}-{pub,prv}).
pub async fn tenant_files_admin_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<TenantFilesListQs>,
) -> Response {
    // Resolve tenant name (and validate existence) from meta.sqlite.
    let tenant_name: Option<String> = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .ok()
    };
    let tenant_name = match tenant_name {
        Some(n) => n,
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("no such tenant: {tenant_id}"),
            )
                .into_response();
        }
    };

    let disk = crate::mgmt::public_files::build_disk_view();
    let max_upload_mb = (state.max_upload_bytes / (1024 * 1024)) as u64;
    let storage_available = state.garage.is_some();

    let per_page = qs
        .per_page
        .filter(|n| TENANT_FILES_PER_PAGE_OPTIONS.contains(n))
        .unwrap_or(TENANT_FILES_DEFAULT_PER_PAGE);
    let req_page = qs.page.unwrap_or(1).max(1);
    let per_page_options: Vec<TenantFilesPerPageOption> = TENANT_FILES_PER_PAGE_OPTIONS
        .iter()
        .map(|&v| TenantFilesPerPageOption {
            value: v,
            selected: v == per_page,
        })
        .collect();

    let pager_url = |p: u32| -> String {
        if per_page == TENANT_FILES_DEFAULT_PER_PAGE {
            crate::base_path::base(&format!("/admin/tenants/{tenant_id}/files?page={p}"))
        } else {
            crate::base_path::base(&format!(
                "/admin/tenants/{tenant_id}/files?page={p}&per_page={per_page}"
            ))
        }
    };

    let empty_page = |tenant_id: String, tenant_name: String| -> Response {
        // Sidebar still renders the virtual rows even when the tenant DB
        // hasn't been opened; `collections: vec![]` is fine here.
        let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
        Html(
            TenantFilesAdminPage {
                version: env!("CARGO_PKG_VERSION"),
                tenant_id,
                tenant_name,
                folders: vec![],
                policies: vec![],
                policy_error: None,
                total_files: 0,
                used_mb_display: "0.0 MB".into(),
                storage_available,
                max_upload_mb,
                disk: disk.clone(),
                collections: vec![],
                active_coll: "_system_files".to_string(),
                page: 1,
                total_pages: 1,
                prev_url: None,
                next_url: None,
                per_page_options: per_page_options.clone(),
                t: Translator::new(locale),
                admin: admin.clone(),
                palette_resolved: trc.palette_resolved,
                mascot_json_static: trc.mascot_json_static,
                mascot_json_light: trc.mascot_json_light,
                mascot_json_dark: trc.mascot_json_dark,
            }
            .render()
            .unwrap(),
        )
        .into_response()
    };

    // Open the tenant's data.sqlite read-only.
    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(_) => return empty_page(tenant_id, tenant_name),
    };

    // Total count + total bytes for the header. Falls back to (0, 0) when
    // _system_files doesn't exist yet (Garage disabled at creation).
    let (total_files_i64, total_bytes_i64): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM _system_files",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .unwrap_or((0, 0));
    let total_files = total_files_i64.max(0) as usize;
    let used_mb_display = format!("{:.1} MB", total_bytes_i64 as f64 / 1_048_576.0);

    let total_pages: u32 = if total_files == 0 {
        1
    } else {
        ((total_files as u64).div_ceil(per_page as u64)) as u32
    };
    let page = req_page.min(total_pages);
    let offset = ((page - 1) as i64) * (per_page as i64);

    // The folder-rule card, and the per-group "governed by" pill, read the
    // registry off the connection this page already opened — the same
    // one-connection discipline the data-plane gates follow. A failure is
    // REPORTED, never rendered as "no rules": the read path denies on the same
    // failure, so an empty card would read as "wide open" at the exact moment
    // access is closed.
    let (file_policies, policy_error) = match load_file_policies(&conn) {
        Ok(p) => (p, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let policies = policy_views(&file_policies);

    // Paginated SELECT.
    let mut stmt = match conn.prepare(
        "SELECT id, key, original_name, content_type, size_bytes, visibility, uploaded_at, path \
         FROM _system_files ORDER BY uploaded_at DESC LIMIT ?1 OFFSET ?2",
    ) {
        Ok(s) => s,
        Err(_) => return empty_page(tenant_id, tenant_name),
    };

    let base_url = &state.public_base_url;
    let files: Vec<AdminTenantFileRow> =
        match stmt.query_map(rusqlite::params![per_page as i64, offset], |r| {
            let _id: i64 = r.get(0)?;
            let key: String = r.get(1)?;
            let original_name: String = r.get(2)?;
            let content_type: Option<String> = r.get(3)?;
            let size_bytes: i64 = r.get(4)?;
            let visibility: String = r.get(5)?;
            let uploaded_at: String = r.get(6)?;
            let path: Option<String> = r.get(7)?;
            let vis_enum = if visibility == "public" {
                crate::storage::files::Visibility::Public
            } else {
                crate::storage::files::Visibility::Private
            };
            let public_url = crate::storage::files::build_public_url(
                base_url,
                &crate::storage::files::Owner::Tenant(tenant_id.clone()),
                vis_enum,
                &key,
            );
            Ok(AdminTenantFileRow {
                key,
                original_name,
                content_type: content_type.unwrap_or_else(|| "application/octet-stream".into()),
                size_human: humanize_bytes(size_bytes as u64),
                visibility,
                uploaded_at,
                public_url,
                path,
            })
        }) {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => vec![],
        };
    let folders = group_into_folders(files, &file_policies);

    let prev_url = (page > 1).then(|| pager_url(page - 1));
    let next_url = (page < total_pages).then(|| pager_url(page + 1));

    let collections = crate::storage::schema::list_collections(&conn).unwrap_or_default();

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantFilesAdminPage {
            version: env!("CARGO_PKG_VERSION"),
            tenant_id,
            tenant_name,
            folders,
            policies,
            policy_error,
            total_files,
            used_mb_display,
            storage_available,
            max_upload_mb,
            disk,
            collections,
            active_coll: "_system_files".to_string(),
            page,
            total_pages,
            prev_url,
            next_url,
            per_page_options,
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

// ─── Folder-rule card: the admin-plane registry face (v1.63, #950-B) ─────────

/// Map a registry refusal onto its HTTP shape — the SAME mapping the REST face
/// uses (`tenant::file_policy_routes::policy_error_response`). The card shows
/// `error_code` verbatim, so a divergence here would give an operator a
/// different vocabulary than the API they will script against later.
fn policy_error_response(e: &FilePolicyError) -> Response {
    let status = match e {
        FilePolicyError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_REQUEST,
    };
    crate::error::json_error(status, e.code(), &e.message())
}

/// `POST /admin/tenants/{id}/_files/policies` — register or replace one prefix
/// rule from the folder-rule card.
///
/// Mounted on `tenants_router`, so `tenant_ownership_layer` has already refused
/// a member's foreign tenant and a soft-deleted one; `ensure_tenant_visible` is
/// the second, in-handler half of that same invariant (CLAUDE.md #7 — a
/// tenant-scoped admin route joins a guarded sub-router **or** calls the choke
/// point; the webhook and OAuth admin writes do both, and so does this).
///
/// The body is `FilePolicyRow` itself — the identical JSON the REST face
/// accepts — so a clause authored over REST round-trips through this endpoint
/// unchanged. The card's own form sends `prefix`, the two flags and the
/// `public_upload_roles` grant; the `select` / `delete` clauses remain
/// REST/MCP-only — a UI limitation, not a second wire shape.
pub async fn file_policy_save(
    State(state): State<TenantsState>,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    Path(tenant_id): Path<String>,
    axum::Json(row): axum::Json<FilePolicyRow>,
) -> Response {
    if let Some(r) = super::common::ensure_tenant_visible(
        &state,
        &tenant_id,
        crate::mgmt::tenant_authz::sees_all_tenants(&admin.role),
        caller_id,
    )
    .await
    {
        return r;
    }
    // Validate BEFORE the writer lock: pure, and a refusal must leave no row.
    if let Err(e) = validate_file_policy(&row) {
        return policy_error_response(&e);
    }
    let pool = match state.tenants.get_or_create(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return crate::error::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };
    match pool.with_writer(move |c| upsert_file_policy(c, &row)).await {
        Ok(()) => axum::Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => crate::error::json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

/// The clear body. `prefix` is REQUIRED and `""` is a legitimate value naming
/// the tenant root — same reasoning as the REST face's mandatory `?prefix=`:
/// a truncated request must never clear the root by default.
#[derive(serde::Deserialize)]
pub struct AdminClearFilePolicyBody {
    pub prefix: String,
}

/// `POST /admin/tenants/{id}/_files/policies/clear` — remove one prefix rule.
///
/// POST with a JSON body rather than `DELETE …?prefix=`: the root prefix is the
/// empty string, which is the one value a query parameter cannot distinguish
/// from "absent" without care, and the card must be able to clear the root (it
/// is exactly how a tenant opts into Supabase-style deny-by-default).
pub async fn file_policy_clear(
    State(state): State<TenantsState>,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    Path(tenant_id): Path<String>,
    axum::Json(body): axum::Json<AdminClearFilePolicyBody>,
) -> Response {
    if let Some(r) = super::common::ensure_tenant_visible(
        &state,
        &tenant_id,
        crate::mgmt::tenant_authz::sees_all_tenants(&admin.role),
        caller_id,
    )
    .await
    {
        return r;
    }
    let pool = match state.tenants.get_or_create(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return crate::error::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };
    let for_error = body.prefix.clone();
    match pool
        .with_writer(move |c| delete_file_policy(c, &body.prefix))
        .await
    {
        Ok(true) => axum::Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => policy_error_response(&FilePolicyError::NotFound(for_error)),
        Err(e) => crate::error::json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(key: &str, path: Option<&str>) -> AdminTenantFileRow {
        AdminTenantFileRow {
            key: key.to_string(),
            original_name: key.to_string(),
            content_type: "text/plain".into(),
            size_human: "1 B".into(),
            visibility: "private".into(),
            uploaded_at: "2026-08-12 00:00:00".into(),
            public_url: String::new(),
            path: path.map(|p| p.to_string()),
        }
    }

    #[test]
    fn folder_of_takes_everything_through_the_last_slash() {
        assert_eq!(folder_of("avatars/alice/me.png"), "avatars/alice/");
        assert_eq!(folder_of("top.png"), "");
        assert_eq!(folder_of("照片/alice/x.png"), "照片/alice/");
        // A trailing slash is not a legal path (T1 rejects it), but the
        // renderer must not panic on a hand-INSERTed one.
        assert_eq!(folder_of("a/"), "a/");
    }

    #[test]
    fn grouping_keeps_unfiled_rows_out_of_the_root_group() {
        let groups = group_into_folders(
            vec![
                row("a", Some("avatars/alice/x")),
                row("b", None),
                row("c", Some("top.png")),
                row("d", Some("avatars/alice/y")),
            ],
            &[],
        );
        assert_eq!(
            groups.len(),
            3,
            "root, unfiled and avatars/alice/ are three"
        );
        assert_eq!(groups[0].prefix, "avatars/alice/");
        assert_eq!(groups[0].files.len(), 2, "same folder, one group");
        assert!(groups[1].unfiled);
        assert!(!groups[2].unfiled);
        assert_eq!(groups[2].prefix, "", "a slash-less path is the root group");
    }

    #[test]
    fn governing_prefix_is_the_longest_registered_match() {
        let policies = vec![
            FilePolicyRow {
                prefix: String::new(),
                owner_scoped: false,
                public_read: true,
                select_policy: None,
                delete_policy: None,
                public_upload_roles: None,
            },
            FilePolicyRow {
                prefix: "avatars/".into(),
                owner_scoped: true,
                public_read: false,
                select_policy: None,
                delete_policy: None,
                public_upload_roles: None,
            },
        ];
        let groups = group_into_folders(
            vec![row("a", Some("avatars/alice/x")), row("b", None)],
            &policies,
        );
        assert_eq!(groups[0].governed_by.as_deref(), Some("avatars/"));
        // An unfiled row can only ever match the root rule.
        assert_eq!(groups[1].governed_by.as_deref(), Some(""));
    }
}
