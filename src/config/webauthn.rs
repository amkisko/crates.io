use anyhow::Context;
use crates_io_env_vars::var;
use url::Url;

/// `WebAuthn` / passkey relying-party configuration for API MFA.
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    /// Public origin of the registry API used for same-origin challenge polling.
    pub api_origin: Url,
    /// Relying party ID (typically the registrable domain, e.g. `crates.io`).
    pub rp_id: String,
    /// Expected browser origin (e.g. `https://crates.io`).
    pub rp_origin: Url,
    /// Human-readable relying party name shown by authenticators.
    pub rp_name: String,
}

impl WebauthnConfig {
    /// Builds config from environment, defaulting RP ID/origin from `domain_name`.
    ///
    /// Environment variables:
    /// - `REGISTRY_API_ORIGIN` (default: `https://{domain_name}`)
    /// - `WEBAUTHN_RP_ID` (default: `domain_name`)
    /// - `WEBAUTHN_RP_ORIGIN` (default: `https://{domain_name}`)
    /// - `WEBAUTHN_RP_NAME` (default: `crates.io`)
    pub fn from_env(domain_name: &str) -> anyhow::Result<Self> {
        let default_origin = format!("https://{domain_name}");
        let api_origin = var("REGISTRY_API_ORIGIN")?
            .unwrap_or_else(|| default_origin.clone())
            .parse::<Url>()
            .context("invalid REGISTRY_API_ORIGIN")?;
        let rp_id = var("WEBAUTHN_RP_ID")?.unwrap_or_else(|| domain_name.to_string());
        let rp_origin = var("WEBAUTHN_RP_ORIGIN")?
            .unwrap_or(default_origin)
            .parse::<Url>()
            .context("invalid WEBAUTHN_RP_ORIGIN")?;
        let rp_name = var("WEBAUTHN_RP_NAME")?.unwrap_or_else(|| "crates.io".into());

        Ok(Self {
            api_origin,
            rp_id,
            rp_origin,
            rp_name,
        })
    }

    /// Test configuration using `http://localhost` as the origin.
    pub fn for_testing() -> Self {
        Self {
            api_origin: Url::parse("http://localhost:8888").unwrap(),
            rp_id: "localhost".into(),
            rp_origin: Url::parse("http://localhost:8888").unwrap(),
            rp_name: "crates.io".into(),
        }
    }
}
