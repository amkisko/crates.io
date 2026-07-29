//! Cargo credential provider that mints crates.io tokens via browser link-login.
//!
//! On `login` without a pasted token, starts `POST /api/v1/cli_login`, prints the
//! `login_url` and confirmation code on stderr, polls until the token is delivered
//! once, stores it in `$CARGO_HOME/credentials.toml`, and never prints the secret.

use cargo_credential::{
    Action, CacheControl, Credential, CredentialResponse, RegistryInfo, Secret,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use toml::Value as TomlValue;

/// Index URLs accepted for the crates.io registry.
pub const CRATES_IO_INDEX_URLS: &[&str] = &[
    "https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// Default crates.io site/API origin.
pub const DEFAULT_API_BASE: &str = "https://crates.io";

/// Environment variable overriding the API/site base URL (staging/local).
pub const API_BASE_ENV: &str = "CARGO_REGISTRY_CRATES_IO_URL";

/// Credential provider implementation.
pub struct CratesIoCredential {
    /// Optional override for tests (API base URL).
    pub api_base: Option<String>,
    /// Optional override for tests (`CARGO_HOME`).
    pub cargo_home: Option<PathBuf>,
    /// HTTP client factory for tests.
    pub http: reqwest::blocking::Client,
    /// Sleep between polls (overridable in tests).
    pub poll_sleep: Duration,
}

impl Default for CratesIoCredential {
    fn default() -> Self {
        Self {
            api_base: None,
            cargo_home: None,
            http: reqwest::blocking::Client::new(),
            poll_sleep: Duration::from_secs(2),
        }
    }
}

impl Credential for CratesIoCredential {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        args: &[&str],
    ) -> Result<CredentialResponse, cargo_credential::Error> {
        if !is_crates_io_index(registry.index_url) {
            return Err(cargo_credential::Error::UrlNotSupported);
        }

        let api_base = resolve_api_base(self.api_base.as_deref(), args);
        let cargo_home = self.cargo_home.clone().unwrap_or_else(default_cargo_home);

        match action {
            Action::Get(_) => {
                let token =
                    read_stored_token(&cargo_home)?.ok_or(cargo_credential::Error::NotFound)?;
                Ok(CredentialResponse::Get {
                    token,
                    cache: CacheControl::Session,
                    operation_independent: true,
                })
            }
            Action::Login(options) => {
                let token = match &options.token {
                    Some(token) => token.to_owned(),
                    None => {
                        let plaintext = run_link_login(&self.http, &api_base, self.poll_sleep)?;
                        Secret::from(plaintext)
                    }
                };
                write_stored_token(&cargo_home, token.expose().as_str())?;
                Ok(CredentialResponse::Login)
            }
            Action::Logout => {
                if !clear_stored_token(&cargo_home)? {
                    return Err(cargo_credential::Error::NotFound);
                }
                Ok(CredentialResponse::Logout)
            }
            _ => Err(cargo_credential::Error::OperationNotSupported),
        }
    }
}

/// Returns true when the index URL is crates.io (git or sparse).
pub fn is_crates_io_index(index_url: &str) -> bool {
    CRATES_IO_INDEX_URLS.contains(&index_url)
}

fn resolve_api_base(override_base: Option<&str>, args: &[&str]) -> String {
    if let Some(base) = override_base {
        return base.trim_end_matches('/').to_string();
    }
    for arg in args {
        if let Some(base) = arg.strip_prefix("--api-base=") {
            return base.trim_end_matches('/').to_string();
        }
    }
    std::env::var(API_BASE_ENV)
        .unwrap_or_else(|_| DEFAULT_API_BASE.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn default_cargo_home() -> PathBuf {
    if let Ok(home) = std::env::var("CARGO_HOME") {
        return PathBuf::from(home);
    }
    dirs_next_home().join(".cargo")
}

fn dirs_next_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Header binding poll redeem to the CLI that called `POST /cli_login`.
pub const POLL_SECRET_HEADER: &str = "Crates-Cli-Login-Secret";

#[derive(Debug, Deserialize)]
struct StartResponse {
    login_url: String,
    poll_url: String,
    confirmation_code: String,
    poll_secret: String,
    recommended_poll_interval_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    status: String,
    token: Option<String>,
}

/// Starts the ceremony, prints the login URL, and returns the one-time token.
pub fn run_link_login(
    http: &reqwest::blocking::Client,
    api_base: &str,
    poll_sleep: Duration,
) -> anyhow::Result<String> {
    let start_url = format!("{api_base}/api/v1/cli_login");
    let start: StartResponse = http
        .post(&start_url)
        .json(&serde_json::json!({}))
        .send()?
        .error_for_status()?
        .json()?;

    // Never print the token or poll_secret; URL + confirmation code belong on stderr.
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "Please visit this URL to authorize cargo login on crates.io:\n  {}\n\n\
         Confirmation code (enter this on the website):\n  {}\n",
        start.login_url, start.confirmation_code
    )?;
    stderr.flush()?;

    let interval = start
        .recommended_poll_interval_secs
        .map(Duration::from_secs)
        .unwrap_or(poll_sleep)
        .max(poll_sleep);

    loop {
        thread::sleep(interval);
        let poll: PollResponse = http
            .get(&start.poll_url)
            .header(POLL_SECRET_HEADER, &start.poll_secret)
            .send()?
            .error_for_status()?
            .json()?;

        match poll.status.as_str() {
            "pending" => continue,
            "ready" => {
                let token = poll
                    .token
                    .ok_or_else(|| anyhow::anyhow!("CLI login ready but token missing"))?;
                return Ok(token);
            }
            "consumed" => {
                anyhow::bail!("CLI login token was already consumed by another poller");
            }
            "expired" => anyhow::bail!("CLI login session expired; run cargo login again"),
            other => anyhow::bail!("unexpected CLI login status: {other}"),
        }
    }
}

/// Reads the crates.io token from `credentials.toml` (`[registry] token = …`).
pub fn read_stored_token(
    cargo_home: &Path,
) -> Result<Option<Secret<String>>, cargo_credential::Error> {
    let path = credentials_path(cargo_home);
    let Ok(contents) = fs::read_to_string(&path) else {
        return Ok(None);
    };
    let table: toml::Table = contents
        .parse()
        .map_err(|err| cargo_credential::Error::Other(Box::new(err)))?;
    let token = table
        .get("registry")
        .and_then(|r| r.get("token"))
        .and_then(|t| t.as_str())
        .map(|t| Secret::from(t.to_owned()));
    Ok(token)
}

/// Writes the crates.io token into `credentials.toml` in the `cargo:token` shape.
pub fn write_stored_token(cargo_home: &Path, token: &str) -> anyhow::Result<()> {
    fs::create_dir_all(cargo_home)?;
    let path = credentials_path(cargo_home);
    let mut table: toml::Table = if path.exists() {
        fs::read_to_string(&path)?.parse()?
    } else {
        toml::Table::new()
    };

    let registry = table
        .entry("registry")
        .or_insert_with(|| TomlValue::Table(toml::Table::new()));
    let registry = registry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("credentials.toml [registry] is not a table"))?;
    registry.insert("token".into(), TomlValue::String(token.to_owned()));

    fs::write(&path, toml::to_string_pretty(&table)?)?;
    // Restrict permissions on Unix when possible.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Removes the crates.io token from `credentials.toml`. Returns whether a token was present.
pub fn clear_stored_token(cargo_home: &Path) -> anyhow::Result<bool> {
    let path = credentials_path(cargo_home);
    if !path.exists() {
        return Ok(false);
    }
    let mut table: toml::Table = fs::read_to_string(&path)?.parse()?;
    let Some(registry) = table.get_mut("registry").and_then(|v| v.as_table_mut()) else {
        return Ok(false);
    };
    let removed = registry.remove("token").is_some();
    if registry.is_empty() {
        table.remove("registry");
    }
    fs::write(&path, toml::to_string_pretty(&table)?)?;
    Ok(removed)
}

fn credentials_path(cargo_home: &Path) -> PathBuf {
    cargo_home.join("credentials.toml")
}

/// Helper used by unit tests to exercise login option plumbing without HTTP.
#[derive(Debug, Serialize)]
pub struct StartRequest {
    pub localhost_port: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_non_crates_io_index() {
        assert!(!is_crates_io_index("sparse+https://example.com/index/"));
        assert!(is_crates_io_index(
            "https://github.com/rust-lang/crates.io-index"
        ));
        assert!(is_crates_io_index("sparse+https://index.crates.io/"));
    }

    #[test]
    fn credentials_roundtrip() {
        let dir = tempdir().unwrap();
        write_stored_token(dir.path(), "cio_test_token").unwrap();
        let token = read_stored_token(dir.path()).unwrap().unwrap();
        assert_eq!(token.expose(), "cio_test_token");
        assert!(clear_stored_token(dir.path()).unwrap());
        assert!(read_stored_token(dir.path()).unwrap().is_none());
    }

    #[test]
    fn link_login_polls_until_ready() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let server = MockServer::start();
        let start_mock = server.mock(|when, then| {
            when.method(POST).path("/api/v1/cli_login");
            then.status(200).json_body(serde_json::json!({
                "login_id": "login_test",
                "login_url": format!("{}/settings/tokens/cli/login_test", server.base_url()),
                "poll_url": format!("{}/api/v1/cli_login/login_test", server.base_url()),
                "confirmation_code": "ABCD-EFGH",
                "poll_secret": "pollsecret_test_abcdefghijklmnopqrstuv",
                "expires_at": "2099-01-01T00:00:00Z",
                "recommended_poll_interval_secs": 0,
            }));
        });

        let polls = Arc::new(AtomicUsize::new(0));
        let polls_for_mock = polls.clone();
        let poll_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/cli_login/login_test")
                .header(POLL_SECRET_HEADER, "pollsecret_test_abcdefghijklmnopqrstuv");
            then.respond_with(move |_req| {
                let n = polls_for_mock.fetch_add(1, Ordering::SeqCst);
                let body = if n == 0 {
                    serde_json::json!({ "status": "pending" })
                } else {
                    serde_json::json!({
                        "status": "ready",
                        "token": "cio_from_poll",
                    })
                };
                httpmock::HttpMockResponse::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(body.to_string())
                    .build()
            });
        });

        let client = reqwest::blocking::Client::new();
        let token = run_link_login(&client, &server.base_url(), Duration::from_millis(1)).unwrap();
        assert_eq!(token, "cio_from_poll");
        start_mock.assert();
        poll_mock.assert_calls(2);
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn login_stores_token_without_printing() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/api/v1/cli_login");
            then.status(200).json_body(serde_json::json!({
                "login_id": "login_x",
                "login_url": format!("{}/settings/tokens/cli/login_x", server.base_url()),
                "poll_url": format!("{}/api/v1/cli_login/login_x", server.base_url()),
                "confirmation_code": "WXYZ-2345",
                "poll_secret": "pollsecret_login_x_abcdefghijklmnopqrst",
                "expires_at": "2099-01-01T00:00:00Z",
                "recommended_poll_interval_secs": 0,
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/cli_login/login_x").header(
                POLL_SECRET_HEADER,
                "pollsecret_login_x_abcdefghijklmnopqrst",
            );
            then.status(200).json_body(serde_json::json!({
                "status": "ready",
                "token": "cio_secret_never_echo",
            }));
        });

        let dir = tempdir().unwrap();
        let provider = CratesIoCredential {
            api_base: Some(server.base_url()),
            cargo_home: Some(dir.path().to_path_buf()),
            http: reqwest::blocking::Client::new(),
            poll_sleep: Duration::from_millis(1),
        };

        let registry = RegistryInfo {
            index_url: "sparse+https://index.crates.io/",
            name: Some("crates-io"),
            headers: Vec::new(),
        };
        let response = provider
            .perform(
                &registry,
                &Action::Login(cargo_credential::LoginOptions {
                    token: None,
                    login_url: None,
                }),
                &[],
            )
            .unwrap();
        assert!(matches!(response, CredentialResponse::Login));

        let stored = read_stored_token(dir.path()).unwrap().unwrap();
        assert_eq!(stored.expose(), "cio_secret_never_echo");
    }
}
