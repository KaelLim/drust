#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir {
    Asc,
    Desc,
}

#[derive(Debug, Clone)]
pub struct ListParams {
    pub filter: Option<String>,
    pub sort_field: String,
    pub sort_dir: SortDir,
    pub page: u32,
    pub per_page: u32,
    /// Row-level owner filter: when `Some((field, user_id))`, an
    /// `AND "field" = 'user_id'` clause is appended to the WHERE.
    /// User IDs are `u-<uuid4>` shaped — safe to inline after escaping.
    pub owner_filter: Option<(String, String)>,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            filter: None,
            sort_field: "created_at".to_string(),
            sort_dir: SortDir::Desc,
            page: 1,
            per_page: 20,
            owner_filter: None,
        }
    }
}

pub fn parse_sort(raw: &str) -> (String, SortDir) {
    if let Some(stripped) = raw.strip_prefix('-') {
        (stripped.to_string(), SortDir::Desc)
    } else {
        (raw.to_string(), SortDir::Asc)
    }
}

fn q(id: &str) -> String {
    format!("\"{}\"", id.replace('"', "\"\""))
}

/// Single-quote escape for safe SQL literal inlining (e.g. user IDs).
fn sql_escape(s: &str) -> String {
    s.replace('\'', "''")
}

pub fn build_list_sql(collection: &str, p: &ListParams) -> String {
    let table = q(collection);
    let dir = match p.sort_dir {
        SortDir::Asc => "ASC",
        SortDir::Desc => "DESC",
    };
    let per_page = p.per_page.clamp(1, 500) as u64;
    let page = p.page.max(1) as u64;
    let offset = (page - 1) * per_page;
    let mut out = format!("SELECT * FROM {table}");
    // Combine user-supplied filter and owner filter under one WHERE clause.
    let mut wheres: Vec<String> = Vec::new();
    if let Some(f) = &p.filter {
        wheres.push(format!("({f})"));
    }
    if let Some((field, val)) = &p.owner_filter {
        // v1.21 — defense-in-depth: user IDs are minted as `u-<uuid4-hex>`
        // by `auth::user_session` so inlining them after `sql_escape` is
        // safe. This debug_assert catches any future caller that shoves
        // an arbitrary string into `owner_filter` (which would re-open
        // the v1.19.2 raw-SQL injection class on `/records/*`). Stripped
        // from release builds.
        debug_assert!(
            val.starts_with("u-")
                && val.len() >= 4
                && val.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'u'),
            "owner_filter user_id shape: expected `u-<hex/uuid>`, got {val:?}"
        );
        wheres.push(format!("{} = '{}'", q(field), sql_escape(val)));
    }
    if !wheres.is_empty() {
        out.push_str(&format!(" WHERE {}", wheres.join(" AND ")));
    }
    out.push_str(&format!(" ORDER BY {} {}", q(&p.sort_field), dir));
    out.push_str(&format!(" LIMIT {per_page} OFFSET {offset}"));
    out
}

pub fn build_count_sql(
    collection: &str,
    filter: Option<&str>,
    owner_filter: Option<(&str, &str)>,
) -> String {
    let table = q(collection);
    let mut wheres: Vec<String> = Vec::new();
    if let Some(f) = filter {
        wheres.push(format!("({f})"));
    }
    if let Some((field, val)) = owner_filter {
        wheres.push(format!("{} = '{}'", q(field), sql_escape(val)));
    }
    if wheres.is_empty() {
        format!("SELECT COUNT(*) FROM {table}")
    } else {
        format!("SELECT COUNT(*) FROM {table} WHERE {}", wheres.join(" AND "))
    }
}
