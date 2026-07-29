//! `cargo-credential-crates-io` — Cargo credential provider for crates.io link-login.

use cargo_credential_crates_io::CratesIoCredential;

fn main() {
    cargo_credential::main(CratesIoCredential::default());
}
