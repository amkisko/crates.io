use insta::{assert_json_snapshot, assert_snapshot};

#[test]
fn test_openapi_snapshot() {
    let document = crates_io::openapi::document(false);
    let document = serde_json::to_value(document).unwrap();
    assert_snapshot!("200 OK", @"200 OK");
    assert_json_snapshot!(document);
}

#[test]
fn test_openapi_internal_snapshot() {
    let document = crates_io::openapi::document(true);
    let document = serde_json::to_value(document).unwrap();
    assert_snapshot!("200 OK", @"200 OK");
    assert_json_snapshot!(document);
}
