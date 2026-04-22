use drust::storage::disk;

#[test]
fn disk_stats_reports_plausible_values_for_tmp() {
    let stats = disk::disk_stats(std::path::Path::new("/tmp")).unwrap();
    assert!(stats.total_bytes > 0, "total must be positive");
    assert!(stats.free_bytes <= stats.total_bytes);
    assert!((0.0..=100.0).contains(&stats.free_pct));
    let recomputed = (stats.free_bytes as f64 / stats.total_bytes as f64) * 100.0;
    assert!((stats.free_pct - recomputed).abs() < 0.01);
}

#[test]
fn disk_stats_for_missing_path_errors() {
    let err = disk::disk_stats(std::path::Path::new("/no/such/path/exists/xyz789"));
    assert!(err.is_err());
}
