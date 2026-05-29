//! REST handler for `POST /t/{tenant}/rpc/{name}`.
//!
//! v1.30 — branches on `stored.mode`:
//!   * `Read`  → unchanged v1.6 path (`pool.with_reader` + read-only
//!     authorizer). Preserved byte-for-byte in the `RpcMode::Read` arm.
//!   * `Write` → v1.30 path (`pool.with_writer` + writable authorizer
//!     wrapped in a SAVEPOINT for atomic rollback / dry_run).
//!
//! On success, increments the per-role call counter and `last_called_at`
//! on `_system_rpc` — fire-and-forget so the response isn't blocked on
//! the writer mutex.

use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::query::executor::{
    ExecError, QueryResult, execute_read_query_with_named,
};
use crate::rpc::params::{ParamError, validate_and_bind};
use crate::rpc::registry::{self, RegistryError};
use crate::tenant::router::TenantRef;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::json;

const MAX_ROWS: usize = 1_000;
const MAX_BYTES: usize = 1_048_576;

/// All possible outcomes of a single RPC dispatch. The closure passed
/// to `with_reader` / `with_writer` returns one of these wrapped in
/// `Ok`, so true `rusqlite::Error`s only surface for connection-level
/// problems.
enum RpcOutcome {
    Ok(QueryResult),
    OkWrite(crate::rpc::exec_write::WriteRpcOutcome),
    NotFound,
    /// Role denial on a Read-mode RPC. Wire code: `ANON_DENIED`.
    AnonDenied,
    /// Role denial on a Write-mode RPC. Wire code: `RPC_DENIED`.
    WriteRoleDenied,
    /// Write-mode RPC declares `:user_id` but caller is Anon (cannot
    /// be auto-bound). Pre-flight reject before any SQL runs.
    UserIdBindingRequired,
    Param(ParamError),
    Exec(ExecError),
    StatementFailed(crate::rpc::exec_write::RpcStatementError),
    /// SAVEPOINT RELEASE failed after a write-mode dispatch.
    TxCommitFailed(String),
    Registry(RegistryError),
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct DryRunQs {
    #[serde(default)]
    pub dry_run: Option<bool>,
}

pub async fn call_rpc(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, name)): Path<(String, String)>,
    Query(qs): Query<DryRunQs>,
    // Accept missing or empty bodies gracefully. Axum's `Json<T>` extractor
    // rejects an empty body outright; using `Option<Json<...>>` would force
    // the Content-Type header check on every caller. We deserialise into a
    // raw `serde_json::Value` and require it to be a JSON object (or null /
    // missing → empty).
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let raw_body = match body {
        Some(Json(v)) => v,
        None => serde_json::Value::Null,
    };
    let body_map = match raw_body {
        serde_json::Value::Null => serde_json::Map::new(),
        serde_json::Value::Object(m) => m,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "BAD_BODY",
                "request body must be a JSON object",
            );
        }
    };

    let pool = t.pool.clone();
    let name_for_lookup = name.clone();
    let ctx_for_lookup = ctx.clone();

    // ── Step A: look up the stored RPC + branch on mode ─────────────
    // We do the lookup on a reader first so we know which arm to enter
    // (it's a single fast meta-table read; pre-flighting the role check
    // here keeps the write arm from grabbing the writer mutex when it'd
    // bail out anyway).
    let stored_res = pool
        .with_reader(move |conn| {
            match registry::lookup(conn, &name_for_lookup) {
                Ok(Some(s)) => Ok(Ok(s)),
                Ok(None) => Ok(Err(RpcOutcome::NotFound)),
                Err(e) => Ok(Err(RpcOutcome::Registry(e))),
            }
        })
        .await;

    let stored = match stored_res {
        Ok(Ok(s)) => s,
        Ok(Err(o)) => return outcome_to_response(o, &t, &name),
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    let dry_run = matches!(stored.mode, crate::rpc::registry::RpcMode::Write)
        && qs.dry_run.unwrap_or(false);

    let outcome_res: rusqlite::Result<RpcOutcome> = match stored.mode {
        crate::rpc::registry::RpcMode::Read => {
            // ═══════════════════════════════════════════════════════
            // READ ARM — preserved byte-for-byte from v1.6. Do not
            // refactor this block; lane B regression-tests it as the
            // baseline. The closure re-runs the registry lookup so
            // (stored, ctx) move into a single `with_reader` call,
            // matching the pre-v1.30 shape.
            // ═══════════════════════════════════════════════════════
            let name_for_closure = name.clone();
            let ctx_for_closure = ctx_for_lookup.clone();
            pool
                .with_reader(move |conn| {
                    // 1. Look up the RPC by name.
                    let stored = match registry::lookup(conn, &name_for_closure) {
                        Ok(Some(s)) => s,
                        Ok(None) => return Ok(RpcOutcome::NotFound),
                        Err(e) => return Ok(RpcOutcome::Registry(e)),
                    };

                    // 2. Role allow-list check.
                    //    Service: always allowed.
                    //    Anon / User: allowed only when anon_callable = true.
                    let allowed = match &ctx_for_closure {
                        AuthCtx::Service { .. } => true,
                        AuthCtx::Anon | AuthCtx::User { .. } => stored.anon_callable,
                    };
                    if !allowed {
                        return Ok(RpcOutcome::AnonDenied);
                    }

                    // 2b. Auto-bind :user_id from AuthCtx when:
                    //     (a) the RPC declares a param named "user_id",
                    //     (b) the caller is a User token, and
                    //     (c) the body did not supply user_id.
                    let mut body_map = body_map;
                    if let AuthCtx::User { user_id, .. } = &ctx_for_closure {
                        let declares_user_id = stored.params.iter().any(|p| p.name == "user_id");
                        if declares_user_id && !body_map.contains_key("user_id") {
                            body_map.insert(
                                "user_id".into(),
                                serde_json::Value::String(user_id.clone()),
                            );
                        }
                    }

                    // 3. Validate + bind params.
                    let bound = match validate_and_bind(&stored.params, &body_map) {
                        Ok(b) => b,
                        Err(e) => return Ok(RpcOutcome::Param(e)),
                    };

                    // 4. Execute through the read-only authorizer.
                    match execute_read_query_with_named(
                        conn,
                        &stored.sql,
                        &bound,
                        MAX_ROWS,
                        MAX_BYTES,
                    ) {
                        Ok(qr) => Ok(RpcOutcome::Ok(qr)),
                        Err(e) => Ok(RpcOutcome::Exec(e)),
                    }
                })
                .await
            // ═══════════════════════════════════════════════════════
            // END READ ARM
            // ═══════════════════════════════════════════════════════
        }
        crate::rpc::registry::RpcMode::Write => {
            // ═══════════════════════════════════════════════════════
            // WRITE ARM — v1.30. Critical-path ordering (do not reorder):
            //   1. detach_authorizer        (defensive; spec §14 Q4)
            //   2. SAVEPOINT (raw)          (authorizer would deny Savepoint)
            //   3. attach_writable_authorizer
            //   4. split + execute_one loop
            //   5. detach_authorizer        (MANDATORY before step 6 —
            //                                RELEASE would be denied otherwise)
            //   6. ROLLBACK TO (if err|dry_run) + RELEASE
            //   7. return outcome
            // ═══════════════════════════════════════════════════════

            // 0. Role allow-list. Write-mode emits RPC_DENIED instead
            //    of ANON_DENIED so the wire shape distinguishes "this
            //    mutation is service-only" from the read-mode case.
            let allowed = match &ctx_for_lookup {
                AuthCtx::Service { .. } => true,
                AuthCtx::Anon | AuthCtx::User { .. } => stored.anon_callable,
            };
            if !allowed {
                Ok(RpcOutcome::WriteRoleDenied)
            } else {
                // 0b. Pre-flight :user_id auto-bind. If the RPC declares
                //     a `user_id` param but the caller is Anon, reject
                //     BEFORE entering the writer closure (no mutation
                //     should happen).
                let declares_user_id =
                    stored.params.iter().any(|p| p.name == "user_id");
                let mut body_map = body_map;
                match &ctx_for_lookup {
                    AuthCtx::User { user_id, .. } => {
                        if declares_user_id && !body_map.contains_key("user_id") {
                            body_map.insert(
                                "user_id".into(),
                                serde_json::Value::String(user_id.clone()),
                            );
                        }
                    }
                    AuthCtx::Anon => {
                        if declares_user_id && !body_map.contains_key("user_id") {
                            return outcome_to_response(
                                RpcOutcome::UserIdBindingRequired,
                                &t,
                                &name,
                            );
                        }
                    }
                    AuthCtx::Service { .. } => {
                        // Service may or may not supply user_id; no auto-bind.
                    }
                }

                // 0c. Validate + bind params (same helper as read arm).
                let bound = match validate_and_bind(&stored.params, &body_map) {
                    Ok(b) => b,
                    Err(e) => return outcome_to_response(RpcOutcome::Param(e), &t, &name),
                };

                // 0d. Pre-validate SQL size (parity with executor.rs).
                if stored.sql.len() > MAX_BYTES {
                    return outcome_to_response(
                        RpcOutcome::Exec(ExecError::TooLarge {
                            bytes: stored.sql.len(),
                            limit: MAX_BYTES,
                        }),
                        &t,
                        &name,
                    );
                }

                let sql_for_closure = stored.sql.clone();
                pool
                    .with_writer(move |conn| {
                        // ── STEP 1: defensive detach. spec §14 Q4 confirms
                        //    with_writer does NOT auto-detach. If any prior
                        //    closure left an authorizer attached it would
                        //    prevent step 2 (Savepoint is Denied).
                        crate::query::authorizer::detach_authorizer(conn);

                        // ── STEP 2: SAVEPOINT (raw, no authorizer).
                        conn.execute("SAVEPOINT drust_rpc_v2", [])?;

                        // ── STEP 3: attach writable authorizer. From here,
                        //    every conn.prepare is gated.
                        crate::query::authorizer::attach_writable_authorizer(conn);

                        // ── STEP 4: split + execute loop.
                        let stmts = match crate::rpc::exec_write::split_statements(
                            &sql_for_closure,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                // Split itself failed (incomplete body / NUL).
                                // Undo savepoint cleanly: detach FIRST (RELEASE
                                // would be Denied otherwise) then ROLLBACK + RELEASE.
                                crate::query::authorizer::detach_authorizer(conn);
                                let _ = conn.execute("ROLLBACK TO drust_rpc_v2", []);
                                // C4 follow-up F1: mirror the normal-path
                                // RELEASE handling — if RELEASE fails, the
                                // savepoint stack is the operator-visible
                                // problem; report TxCommitFailed rather than
                                // hiding it behind the split error.
                                if let Err(rel) = conn.execute("RELEASE drust_rpc_v2", []) {
                                    return Ok(RpcOutcome::TxCommitFailed(rel.to_string()));
                                }
                                return Ok(RpcOutcome::StatementFailed(e));
                            }
                        };

                        let mut last_rows: Option<QueryResult> = None;
                        let mut combined_affected: i64 = 0;
                        let mut last_insert_rowid: Option<i64> = None;
                        let mut exec_error:
                            Option<crate::rpc::exec_write::RpcStatementError> = None;
                        let mut statement_count: usize = 0;

                        // C4 follow-up F2 — INVARIANT: execute_one MUST NOT
                        // panic. A panic here would leave the writer
                        // connection with an open SAVEPOINT drust_rpc_v2;
                        // tokio::sync::Mutex does not poison and
                        // rusqlite::Connection's Drop only runs at process
                        // exit, so the next request's STEP 2 would nest a
                        // savepoint with the same name. The subsequent
                        // RELEASE only releases the innermost — the leaked
                        // savepoint would persist until process restart,
                        // holding any pre-panic mutations in limbo.
                        // execute_one returns Err on all known SQL-error
                        // paths; this invariant is asserted by the
                        // execute_one_never_panics_on_bad_sql test in
                        // exec_write::tests.
                        for (i, stmt) in stmts.iter().enumerate() {
                            statement_count += 1;
                            match crate::rpc::exec_write::execute_one(
                                conn,
                                stmt,
                                &bound,
                                i + 1,
                            ) {
                                Ok(o) => {
                                    if o.rows.is_some() {
                                        last_rows = o.rows;
                                    }
                                    combined_affected += o.affected_rows;
                                    if let Some(rid) = o.last_insert_rowid {
                                        last_insert_rowid = Some(rid);
                                    }
                                }
                                Err(e) => {
                                    exec_error = Some(e);
                                    break;
                                }
                            }
                        }

                        // ── STEP 5: MANDATORY detach BEFORE savepoint resolution.
                        crate::query::authorizer::detach_authorizer(conn);

                        // ── STEP 6: resolve savepoint.
                        let should_rollback = exec_error.is_some() || dry_run;
                        if should_rollback {
                            let _ = conn.execute("ROLLBACK TO drust_rpc_v2", []);
                        }
                        if let Err(e) = conn.execute("RELEASE drust_rpc_v2", []) {
                            return Ok(RpcOutcome::TxCommitFailed(e.to_string()));
                        }

                        // ── STEP 7: return outcome.
                        match exec_error {
                            Some(e) => Ok(RpcOutcome::StatementFailed(e)),
                            None => Ok(RpcOutcome::OkWrite(
                                crate::rpc::exec_write::WriteRpcOutcome {
                                    last_rows,
                                    affected_rows: combined_affected,
                                    last_insert_rowid,
                                    statement_count,
                                    dry_run,
                                },
                            )),
                        }
                    })
                    .await
            }
        }
    };

    let outcome = match outcome_res {
        Ok(o) => o,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    outcome_to_response(outcome, &t, &name)
}

/// Translate a `RpcOutcome` into the final HTTP response. Factored out so
/// pre-flight rejection paths (param-error before entering with_writer,
/// :user_id binding refusal, etc.) can use the same shape as the
/// post-closure dispatch.
fn outcome_to_response(outcome: RpcOutcome, t: &TenantRef, name: &str) -> Response {
    match outcome {
        RpcOutcome::Ok(qr) => {
            // Fire-and-forget counter bump on the writer mutex. Failed
            // calls (any non-Ok arm above) do not increment.
            let pool_for_counter = t.pool.clone();
            let role_for_counter = t.role;
            let name_for_counter = name.to_string();
            tokio::spawn(async move {
                let res = pool_for_counter
                    .with_writer(move |c| {
                        registry::increment(c, &name_for_counter, role_for_counter)
                    })
                    .await;
                if let Err(e) = res {
                    tracing::warn!(error = %e, "rpc counter bump failed");
                }
            });
            let row_count = qr.rows.len();
            let mut resp = Json(json!({
                "column_names": qr.column_names,
                "rows": qr.rows,
                "row_count": row_count,
                "truncated": qr.truncated,
            }))
            .into_response();
            // v1.30: emit AuditExtra{rpc_mode:"read"} on success so the
            // audit row is uniform with the write-mode arm.
            resp.extensions_mut().insert(
                crate::safety::audit::AuditExtra(json!({"rpc_mode": "read"})),
            );
            resp
        }
        RpcOutcome::OkWrite(w) => {
            // Mirror the read-arm counter-bump pattern.
            let pool_for_counter = t.pool.clone();
            let role_for_counter = t.role;
            let name_for_counter = name.to_string();
            tokio::spawn(async move {
                let res = pool_for_counter
                    .with_writer(move |c| {
                        registry::increment(c, &name_for_counter, role_for_counter)
                    })
                    .await;
                if let Err(e) = res {
                    tracing::warn!(error = %e, "rpc counter bump failed");
                }
            });

            let mut body = serde_json::Map::new();
            if let Some(qr) = &w.last_rows {
                body.insert("column_names".into(), json!(qr.column_names));
                body.insert("rows".into(), json!(qr.rows));
                body.insert("row_count".into(), json!(qr.rows.len()));
                body.insert("truncated".into(), json!(qr.truncated));
            } else {
                body.insert("column_names".into(), json!(Vec::<String>::new()));
                body.insert("rows".into(), json!(Vec::<serde_json::Value>::new()));
                body.insert("row_count".into(), json!(0));
                body.insert("truncated".into(), json!(false));
            }
            body.insert("affected_rows".into(), json!(w.affected_rows));
            body.insert("last_insert_rowid".into(), json!(w.last_insert_rowid));
            body.insert("statement_count".into(), json!(w.statement_count));
            if w.dry_run {
                body.insert("dry_run".into(), json!(true));
                body.insert("would_commit".into(), json!(true));
            }

            let mut resp = Json(serde_json::Value::Object(body)).into_response();
            let audit_extra = json!({
                "rpc_mode": "write",
                "rpc_affected_rows": w.affected_rows,
                "rpc_dry_run": w.dry_run,
                "rpc_statement_count": w.statement_count,
            });
            resp.extensions_mut()
                .insert(crate::safety::audit::AuditExtra(audit_extra));
            resp
        }
        RpcOutcome::NotFound => json_error(
            StatusCode::NOT_FOUND,
            "RPC_NOT_FOUND",
            &format!("no such rpc: {name}"),
        ),
        RpcOutcome::AnonDenied => json_error(
            StatusCode::FORBIDDEN,
            "ANON_DENIED",
            &format!("anon role cannot call rpc '{name}'"),
        ),
        RpcOutcome::WriteRoleDenied => json_error(
            StatusCode::FORBIDDEN,
            "RPC_DENIED",
            &format!("role cannot call rpc '{name}'"),
        ),
        RpcOutcome::UserIdBindingRequired => json_error(
            StatusCode::FORBIDDEN,
            "USER_ID_BINDING_REQUIRED",
            ":user_id binding requires a user token (anon cannot call this RPC)",
        ),
        RpcOutcome::Param(e) => match e {
            ParamError::Missing(_) => {
                json_error(StatusCode::BAD_REQUEST, "PARAM_MISSING", &e.to_string())
            }
            ParamError::TypeMismatch { .. } => json_error(
                StatusCode::BAD_REQUEST,
                "PARAM_TYPE_MISMATCH",
                &e.to_string(),
            ),
            ParamError::Unknown(_) => {
                json_error(StatusCode::BAD_REQUEST, "PARAM_UNKNOWN", &e.to_string())
            }
            ParamError::BadParamsJson(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PARAM_BAD_STORED",
                &e.to_string(),
            ),
        },
        RpcOutcome::Exec(e) => match &e {
            ExecError::TooLarge { .. } => json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "QUERY_TOO_LARGE",
                &e.to_string(),
            ),
            ExecError::Forbidden(_) => json_error(
                StatusCode::FORBIDDEN,
                "QUERY_FORBIDDEN",
                &e.to_string(),
            ),
            ExecError::Timeout(_) => json_error(
                StatusCode::REQUEST_TIMEOUT,
                "QUERY_TIMEOUT",
                &e.to_string(),
            ),
            ExecError::Sql(_) => {
                json_error(StatusCode::BAD_REQUEST, "SQL_ERROR", &e.to_string())
            }
        },
        RpcOutcome::StatementFailed(e) => {
            let code = if e.authorizer_denied {
                "INVALID_SQL_FOR_MODE"
            } else {
                "RPC_STATEMENT_FAILED"
            };
            let mut body = serde_json::Map::new();
            body.insert("error_code".into(), json!(code));
            body.insert(
                "message".into(),
                json!(format!(
                    "statement {} failed: {}",
                    e.statement_index, e.message
                )),
            );
            body.insert("statement_index".into(), json!(e.statement_index));
            if let Some(fix) = crate::safety::error_fixes::lookup(code) {
                body.insert("suggested_fix".into(), json!(fix));
            }
            let mut resp = Json(serde_json::Value::Object(body)).into_response();
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            resp.extensions_mut().insert(
                crate::safety::audit::AuditExtra(json!({
                    "rpc_mode": "write",
                    "rpc_statement_index": e.statement_index,
                })),
            );
            resp
        }
        RpcOutcome::TxCommitFailed(msg) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "TX_COMMIT_FAILED",
            &msg,
        ),
        RpcOutcome::Registry(e) => match e {
            RegistryError::NotFound(_) => json_error(
                StatusCode::NOT_FOUND,
                "RPC_NOT_FOUND",
                &e.to_string(),
            ),
            RegistryError::BadParams(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PARAM_BAD_STORED",
                &e.to_string(),
            ),
            RegistryError::AlreadyExists(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            ),
            RegistryError::Sqlite(_) => {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string())
            }
        },
    }
}
