use drust::storage::files::{Owner, Visibility, bucket_for_upload, build_public_url};

#[test]
fn bucket_for_admin_public() {
    assert_eq!(
        bucket_for_upload(&Owner::Admin, Visibility::Public),
        "public"
    );
}

#[test]
fn bucket_for_admin_private() {
    assert_eq!(
        bucket_for_upload(&Owner::Admin, Visibility::Private),
        "admin-private"
    );
}

#[test]
fn bucket_for_tenant() {
    let o = Owner::Tenant("acme".into());
    assert_eq!(bucket_for_upload(&o, Visibility::Public), "tenant-acme-pub");
    assert_eq!(
        bucket_for_upload(&o, Visibility::Private),
        "tenant-acme-prv"
    );
}

#[test]
fn build_public_url_admin() {
    let b = "https://tool.example";
    assert_eq!(
        build_public_url(b, &Owner::Admin, Visibility::Public, "abc"),
        "https://tool.example/public/abc"
    );
}

#[test]
fn build_public_url_tenant() {
    let b = "https://tool.example";
    assert_eq!(
        build_public_url(b, &Owner::Tenant("acme".into()), Visibility::Public, "abc"),
        "https://tool.example/t-public/acme/abc"
    );
}

#[test]
fn build_url_for_private_admin_points_to_drust_bytes_route() {
    let b = "https://tool.example";
    assert_eq!(
        build_public_url(b, &Owner::Admin, Visibility::Private, "abc"),
        "https://tool.example/drust/admin/files/abc/bytes"
    );
}

#[test]
fn build_url_for_private_tenant_points_to_drust_bytes_route() {
    let b = "https://tool.example";
    assert_eq!(
        build_public_url(b, &Owner::Tenant("acme".into()), Visibility::Private, "abc"),
        "https://tool.example/drust/t/acme/files/abc/bytes"
    );
}
