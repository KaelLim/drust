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
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            filter: None,
            sort_field: "created_at".to_string(),
            sort_dir: SortDir::Desc,
            page: 1,
            per_page: 20,
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
    if let Some(f) = &p.filter {
        out.push_str(&format!(" WHERE ({f})"));
    }
    out.push_str(&format!(" ORDER BY {} {}", q(&p.sort_field), dir));
    out.push_str(&format!(" LIMIT {per_page} OFFSET {offset}"));
    out
}

pub fn build_count_sql(collection: &str, filter: Option<&str>) -> String {
    let table = q(collection);
    match filter {
        Some(f) => format!("SELECT COUNT(*) FROM {table} WHERE ({f})"),
        None => format!("SELECT COUNT(*) FROM {table}"),
    }
}
