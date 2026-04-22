use drust::storage::tenant_db::validate_tenant_id;

#[test]
fn accepts_sensible_ids() {
    assert!(validate_tenant_id("event-registration").is_ok());
    assert!(validate_tenant_id("a").is_ok());
    assert!(validate_tenant_id("abc123").is_ok());
}

#[test]
fn rejects_illegal_chars() {
    assert!(validate_tenant_id("Event-Reg").is_err()); // uppercase
    assert!(validate_tenant_id("foo_bar").is_err()); // underscore
    assert!(validate_tenant_id("foo.bar").is_err()); // dot
    assert!(validate_tenant_id("foo/bar").is_err()); // slash
    assert!(validate_tenant_id("").is_err()); // empty
    assert!(validate_tenant_id("  leading-space").is_err());
}

#[test]
fn rejects_over_52_chars() {
    let at_52 = "a".repeat(52);
    let at_53 = "a".repeat(53);
    assert!(validate_tenant_id(&at_52).is_ok(), "52 should be OK");
    assert!(validate_tenant_id(&at_53).is_err(), "53 must fail");
}

#[test]
fn rejects_reserved_names() {
    for name in ["admin", "system", "root", "public"] {
        assert!(validate_tenant_id(name).is_err(), "reserved: {name}");
    }
}
