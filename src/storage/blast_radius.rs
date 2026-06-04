//! v1.26 — Pure read helpers that compute the side effects of a
//! destructive op without executing it. Powers `dry_run` mode on
//! `delete_record` / `drop_collection` / `drop_index` (MCP + REST).
//!
//! All functions run inside `pool.with_reader` and never touch row
//! data. They never write audit rows and never fire webhooks.

use crate::storage::pool::SharedTenantPool;
use serde::Serialize;

#[derive(Serialize)]
pub struct FkBlocker {
    pub collection: String,
    pub via_field: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct DeleteBlastRadius {
    pub would_delete: bool,
    pub id: i64,
    pub fk_blocks: Vec<FkBlocker>,
}

#[derive(Serialize)]
pub struct ReverseFk {
    pub collection: String,
    pub field: String,
    pub row_count: u64,
}

#[derive(Serialize)]
pub struct DropCollectionBlastRadius {
    pub would_drop: bool,
    pub row_count: u64,
    pub indexes: Vec<String>,
    pub rpcs: Vec<String>,
    pub reverse_fks: Vec<ReverseFk>,
}

#[derive(Debug, Serialize)]
pub struct DropIndexBlastRadius {
    pub would_drop: bool,
    pub name: String,
}

/// Inspect all collections that FK-reference `coll` and count how many
/// rows in each have `<fk_field> = id`. A non-empty result means a real
/// DELETE would fail with FK_RESTRICT (drust always emits ON DELETE
/// RESTRICT).
pub async fn delete_blast_radius(
    pool: &SharedTenantPool,
    coll: &str,
    id: i64,
) -> anyhow::Result<DeleteBlastRadius> {
    let coll_owned = coll.to_string();
    let blocks = pool
        .with_reader(move |c| {
            // Walk every user table and look at its foreign_key_list.
            // Cheaper than parsing _system_collection_meta.fields_json
            // and works on tables created before the meta column existed.
            let mut user_tables = c.prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name NOT LIKE 'sqlite_%' \
                 AND name NOT LIKE '\\_system\\_%' ESCAPE '\\'",
            )?;
            let tables: Vec<String> = user_tables
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?;
            let mut blocks: Vec<FkBlocker> = Vec::new();
            for t in &tables {
                let pragma = format!("PRAGMA foreign_key_list(\"{}\")", t.replace('"', "\"\""));
                let mut stmt = c.prepare(&pragma)?;
                // Cols: id, seq, table, from, to, on_update, on_delete, match
                let rows =
                    stmt.query_map([], |r| Ok((r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?;
                for row in rows {
                    let (target_table, from_col) = row?;
                    if target_table == coll_owned {
                        let count_sql = format!(
                            "SELECT COUNT(*) FROM \"{}\" WHERE \"{}\" = ?1",
                            t.replace('"', "\"\""),
                            from_col.replace('"', "\"\""),
                        );
                        let count: i64 =
                            c.query_row(&count_sql, rusqlite::params![id], |r| r.get(0))?;
                        if count > 0 {
                            blocks.push(FkBlocker {
                                collection: t.clone(),
                                via_field: from_col,
                                count: count as u64,
                            });
                        }
                    }
                }
            }
            Ok::<_, rusqlite::Error>(blocks)
        })
        .await?;
    Ok(DeleteBlastRadius {
        would_delete: true,
        id,
        fk_blocks: blocks,
    })
}

/// Returns row_count + indexes + rpcs + reverse_fks for a target table.
pub async fn drop_collection_blast_radius(
    pool: &SharedTenantPool,
    coll: &str,
) -> anyhow::Result<DropCollectionBlastRadius> {
    let coll_owned = coll.to_string();
    let (row_count, indexes, rpcs, reverse_fks) = pool
        .with_reader(move |c| {
            // row_count
            let row_count_sql = format!(
                "SELECT COUNT(*) FROM \"{}\"",
                coll_owned.replace('"', "\"\"")
            );
            let row_count: i64 = c.query_row(&row_count_sql, [], |r| r.get(0))?;

            // indexes on this table (excluding sqlite-internal autoindex)
            let mut idx_stmt = c.prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='index' AND tbl_name = ?1 AND name NOT LIKE 'sqlite_%'",
            )?;
            let indexes: Vec<String> = idx_stmt
                .query_map(rusqlite::params![coll_owned], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?;

            // RPCs whose SQL mentions this collection (conservative substring match)
            // _system_rpc may not exist on older tenants — tolerate.
            let mut rpcs: Vec<String> = Vec::new();
            let rpc_table_exists: i64 = c
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_system_rpc'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if rpc_table_exists > 0 {
                let mut stmt = c.prepare("SELECT name, sql FROM _system_rpc")?;
                let rows =
                    stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
                for row in rows {
                    let (name, sql) = row?;
                    if sql.contains(&coll_owned) {
                        rpcs.push(name);
                    }
                }
            }

            // Reverse FKs: collections whose foreign_key_list points at coll_owned.
            let mut user_tables = c.prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name NOT LIKE 'sqlite_%' \
                 AND name NOT LIKE '\\_system\\_%' ESCAPE '\\'",
            )?;
            let tables: Vec<String> = user_tables
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?;
            let mut reverse_fks: Vec<ReverseFk> = Vec::new();
            for t in &tables {
                if t == &coll_owned {
                    continue;
                }
                let pragma = format!("PRAGMA foreign_key_list(\"{}\")", t.replace('"', "\"\""));
                let mut stmt = c.prepare(&pragma)?;
                let rows =
                    stmt.query_map([], |r| Ok((r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?;
                for row in rows {
                    let (target, from_col) = row?;
                    if target == coll_owned {
                        let cnt_sql =
                            format!("SELECT COUNT(*) FROM \"{}\"", t.replace('"', "\"\""));
                        let row_count: i64 = c.query_row(&cnt_sql, [], |r| r.get(0))?;
                        reverse_fks.push(ReverseFk {
                            collection: t.clone(),
                            field: from_col,
                            row_count: row_count as u64,
                        });
                    }
                }
            }

            Ok::<_, rusqlite::Error>((row_count as u64, indexes, rpcs, reverse_fks))
        })
        .await?;

    Ok(DropCollectionBlastRadius {
        would_drop: true,
        row_count,
        indexes,
        rpcs,
        reverse_fks,
    })
}

/// Confirm index exists (matches existing `drop_index` validation) and
/// return its name. No further blast info — dropping an index never
/// affects row data.
pub async fn drop_index_blast_radius(
    pool: &SharedTenantPool,
    index_name: &str,
) -> anyhow::Result<DropIndexBlastRadius> {
    let name_owned = index_name.to_string();
    let exists: i64 = pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name = ?1",
                rusqlite::params![name_owned],
                |r| r.get(0),
            )
        })
        .await?;
    if exists == 0 {
        anyhow::bail!("INDEX_NOT_FOUND: no such index: {index_name}");
    }
    Ok(DropIndexBlastRadius {
        would_drop: true,
        name: index_name.to_string(),
    })
}
