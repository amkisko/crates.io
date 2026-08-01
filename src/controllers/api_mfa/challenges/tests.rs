use super::mutation_preflight::validate_callback_url;

#[test]
fn mutation_callback_requires_one_bounded_state_value() {
    let valid = "http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef";
    assert_eq!(validate_callback_url(valid).unwrap(), valid);

    for invalid in [
        "http://127.0.0.1:34567/cargo/registry-authorization",
        "http://127.0.0.1:34567/cargo/registry-authorization?state=short",
        "http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef&state=other",
        "http://localhost:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef",
    ] {
        assert!(
            validate_callback_url(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}
