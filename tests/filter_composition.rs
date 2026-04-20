use drust::query::filter::{ListParams, SortDir, build_list_sql};

#[test]
fn default_no_filter() {
    let sql = build_list_sql("posts", &ListParams::default());
    assert_eq!(
        sql,
        "SELECT * FROM \"posts\" ORDER BY \"created_at\" DESC LIMIT 20 OFFSET 0"
    );
}

#[test]
fn with_filter() {
    let p = ListParams {
        filter: Some("status='published' AND views>100".into()),
        ..ListParams::default()
    };
    let sql = build_list_sql("posts", &p);
    assert_eq!(
        sql,
        "SELECT * FROM \"posts\" WHERE (status='published' AND views>100) ORDER BY \"created_at\" DESC LIMIT 20 OFFSET 0"
    );
}

#[test]
fn with_sort_asc() {
    let p = ListParams {
        sort_field: "views".into(),
        sort_dir: SortDir::Asc,
        ..ListParams::default()
    };
    let sql = build_list_sql("posts", &p);
    assert!(sql.contains("ORDER BY \"views\" ASC"));
}

#[test]
fn page_offset() {
    let p = ListParams {
        page: 3,
        per_page: 10,
        ..ListParams::default()
    };
    let sql = build_list_sql("posts", &p);
    assert!(sql.ends_with("LIMIT 10 OFFSET 20"));
}

#[test]
fn per_page_caps_at_500() {
    let p = ListParams {
        page: 1,
        per_page: 10_000,
        ..ListParams::default()
    };
    let sql = build_list_sql("posts", &p);
    assert!(sql.contains("LIMIT 500"));
}

#[test]
fn parse_sort_leading_minus() {
    use drust::query::filter::parse_sort;
    let (f, d) = parse_sort("-created_at");
    assert_eq!(f, "created_at");
    assert!(matches!(d, SortDir::Desc));
    let (f2, d2) = parse_sort("views");
    assert_eq!(f2, "views");
    assert!(matches!(d2, SortDir::Asc));
}
