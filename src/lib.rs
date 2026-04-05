//! # xlock
//!
//! Bot protection middleware for Rust applications, powered by [x-lock](https://x-lock.dev).
//!
//! ## Features
//!
//! - `actix` (default) — actix-web middleware via `XLock` transform

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[cfg(feature = "actix")]
mod actix;
#[cfg(feature = "actix")]
pub use crate::actix::XLock;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for x-lock verification.
#[derive(Clone, Debug)]
pub struct Config {
    /// Site key. Falls back to the `XLOCK_SITE_KEY` env var when empty.
    pub site_key: String,
    /// Base URL of the x-lock API.
    pub api_url: String,
    /// When `true` (the default), verification errors allow the request through.
    pub fail_open: bool,
    /// Only requests whose path starts with one of these prefixes are checked.
    /// An empty list means *all* POST requests are checked.
    pub protected_paths: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            site_key: std::env::var("XLOCK_SITE_KEY").unwrap_or_default(),
            api_url: "https://api.x-lock.dev".into(),
            fail_open: true,
            protected_paths: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Verify result
// ---------------------------------------------------------------------------

/// Outcome of an x-lock verification call.
#[derive(Clone, Debug, Default)]
pub struct VerifyResult {
    /// `true` when the request was blocked by x-lock.
    pub blocked: bool,
    /// Human-readable reason supplied by the API (when blocked).
    pub reason: Option<String>,
    /// Transport or API error that occurred during verification.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Enforce request / response types (internal)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EnforceReq {
    token: String,
    #[serde(rename = "siteKey")]
    site_key: String,
    path: String,
}

#[derive(Serialize)]
struct V3EnforceReq {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "siteKey")]
    site_key: String,
    path: String,
}

#[derive(Deserialize)]
struct EnforceRes {
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// verify()
// ---------------------------------------------------------------------------

/// Create a shared [`Client`] with sensible defaults for x-lock calls.
pub fn default_client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to build reqwest client")
}

/// Verify a token/session against the x-lock API.
///
/// * `client`   — a reusable `reqwest::Client` (create one with [`default_client`]).
/// * `config`   — your [`Config`].
/// * `token`    — the value of the `x-lock` header sent by the browser.
/// * `path`     — the request path being protected.
///
/// Returns a [`VerifyResult`] describing the outcome.
pub async fn verify(client: &Client, config: &Config, token: &str, path: &str) -> VerifyResult {
    let site_key = if config.site_key.is_empty() {
        std::env::var("XLOCK_SITE_KEY").unwrap_or_default()
    } else {
        config.site_key.clone()
    };

    let result = if token.starts_with("v3.") {
        let session_id = token.splitn(3, '.').nth(1).unwrap_or_default().to_string();
        client
            .post(format!("{}/v3/session/enforce", config.api_url))
            .json(&V3EnforceReq {
                session_id,
                site_key,
                path: path.to_string(),
            })
            .send()
            .await
    } else {
        client
            .post(format!("{}/v1/enforce", config.api_url))
            .json(&EnforceReq {
                token: token.to_string(),
                site_key,
                path: path.to_string(),
            })
            .send()
            .await
    };

    match result {
        Ok(res) if res.status() == reqwest::StatusCode::FORBIDDEN => {
            let data: EnforceRes = res.json().await.unwrap_or(EnforceRes { reason: None });
            VerifyResult {
                blocked: true,
                reason: data.reason,
                error: None,
            }
        }
        Ok(res) if res.status().is_client_error() => VerifyResult {
            blocked: !config.fail_open,
            reason: None,
            error: Some(format!("x-lock API returned {}", res.status())),
        },
        Ok(_) => VerifyResult::default(),
        Err(e) => {
            eprintln!("[x-lock] Enforcement error: {e}");
            VerifyResult {
                blocked: !config.fail_open,
                reason: None,
                error: Some(e.to_string()),
            }
        }
    }
}
