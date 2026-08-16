//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::LazyLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::oidc::config::OidcConfig;
use crate::raise_error;
use crate::utc_now;

/// How long a fetched discovery document is reused before being re-fetched.
const CACHE_TTL_MS: i64 = 60 * 60 * 1000;

/// Shared client for all outbound OIDC requests (discovery, JWKS, token,
/// userinfo). Kept separate from the IMAP OAuth2 client because those honour a
/// per-account proxy, whereas the IdP is a first-party dependency of the server.
pub(crate) static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        // The IdP endpoints are all direct JSON; a redirect here would either be
        // an issuer misconfiguration or an attempt to point us elsewhere.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("bichon/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("failed to build the OIDC HTTP client")
});

/// The subset of OpenID Provider Metadata (OIDC Discovery 1.0 §3) Bichon uses.
///
/// Unknown members are ignored, so provider-specific extensions are harmless.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// RP-initiated logout (OIDC Session Management). Absent on providers that
    /// do not support it, in which case Bichon can only clear its own session.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

impl ProviderMetadata {
    /// Which client authentication method to use at the token endpoint.
    ///
    /// The spec's default is `client_secret_basic`, and strict providers reject
    /// requests that present the secret twice, so exactly one method is picked
    /// rather than sending both.
    pub fn token_auth_method(&self) -> TokenAuthMethod {
        if self.token_endpoint_auth_methods_supported.is_empty() {
            return TokenAuthMethod::Basic;
        }
        let supports = |m: &str| {
            self.token_endpoint_auth_methods_supported
                .iter()
                .any(|s| s == m)
        };
        if supports("client_secret_basic") {
            TokenAuthMethod::Basic
        } else if supports("client_secret_post") {
            TokenAuthMethod::Post
        } else {
            // Only `none` (public client) or methods Bichon cannot perform were
            // advertised; send no client credentials and let PKCE carry the flow.
            TokenAuthMethod::None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenAuthMethod {
    /// HTTP Basic with the client id and secret (spec default).
    Basic,
    /// `client_id` / `client_secret` in the form body.
    Post,
    /// Public client: no client credentials at all.
    None,
}

struct Cached {
    issuer_url: String,
    metadata: ProviderMetadata,
    fetched_at: i64,
}

static CACHE: LazyLock<RwLock<Option<Cached>>> = LazyLock::new(|| RwLock::new(None));

/// Fetch the provider metadata, reusing the cached copy when it is still fresh.
pub async fn provider_metadata(config: &OidcConfig) -> BichonResult<ProviderMetadata> {
    {
        let guard = CACHE.read().await;
        if let Some(cached) = guard.as_ref() {
            if cached.issuer_url == config.issuer_url
                && utc_now!() - cached.fetched_at < CACHE_TTL_MS
            {
                return Ok(cached.metadata.clone());
            }
        }
    }

    let metadata = fetch(config).await?;

    let mut guard = CACHE.write().await;
    *guard = Some(Cached {
        issuer_url: config.issuer_url.clone(),
        metadata: metadata.clone(),
        fetched_at: utc_now!(),
    });
    Ok(metadata)
}

async fn fetch(config: &OidcConfig) -> BichonResult<ProviderMetadata> {
    let url = config.discovery_url();
    debug!("fetching OIDC discovery document from {}", url);

    let response = HTTP.get(&url).send().await.map_err(|e| {
        raise_error!(
            format!("Could not reach the OIDC discovery endpoint {}: {}", url, e),
            ErrorCode::NetworkError
        )
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(raise_error!(
            format!(
                "The OIDC discovery endpoint {} returned HTTP {}.",
                url, status
            ),
            ErrorCode::HttpResponseError
        ));
    }

    let metadata: ProviderMetadata = response.json().await.map_err(|e| {
        raise_error!(
            format!(
                "The OIDC discovery document at {} could not be parsed: {}",
                url, e
            ),
            ErrorCode::HttpResponseError
        )
    })?;

    // OIDC Discovery §4.3: the returned issuer MUST match the one used to build
    // the request. Skipping this check would let a compromised well-known
    // document redirect the whole flow to another issuer.
    if metadata.issuer.trim_end_matches('/') != config.issuer_url {
        return Err(raise_error!(
            format!(
                "OIDC discovery mismatch: document at {} declares issuer '{}' but BICHON_OIDC_ISSUER_URL is '{}'.",
                url, metadata.issuer, config.issuer_url
            ),
            ErrorCode::HttpResponseError
        ));
    }

    Ok(metadata)
}

/// Drop the cached document. Exposed for tests and for future admin-triggered
/// reloads after an IdP rotation.
pub async fn invalidate_cache() {
    *CACHE.write().await = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata_with(methods: &[&str]) -> ProviderMetadata {
        ProviderMetadata {
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "https://idp.example.com/auth".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            userinfo_endpoint: None,
            end_session_endpoint: None,
            token_endpoint_auth_methods_supported: methods
                .iter()
                .map(|s| s.to_string())
                .collect(),
            id_token_signing_alg_values_supported: vec![],
            code_challenge_methods_supported: vec![],
            scopes_supported: vec![],
        }
    }

    #[test]
    fn token_auth_method_defaults_to_basic_when_unadvertised() {
        assert_eq!(metadata_with(&[]).token_auth_method(), TokenAuthMethod::Basic);
    }

    #[test]
    fn token_auth_method_prefers_basic() {
        assert_eq!(
            metadata_with(&["client_secret_post", "client_secret_basic"]).token_auth_method(),
            TokenAuthMethod::Basic
        );
    }

    #[test]
    fn token_auth_method_falls_back_to_post() {
        assert_eq!(
            metadata_with(&["client_secret_post"]).token_auth_method(),
            TokenAuthMethod::Post
        );
    }

    #[test]
    fn token_auth_method_handles_public_clients() {
        assert_eq!(
            metadata_with(&["none", "private_key_jwt"]).token_auth_method(),
            TokenAuthMethod::None
        );
    }

    #[test]
    fn discovery_url_does_not_double_the_slash() {
        let config = OidcConfig {
            issuer_url: "https://idp.example.com/realms/x".into(),
            client_id: "bichon".into(),
            client_secret: None,
            redirect_uri: "https://mail.example.com/api/auth/oidc/callback".into(),
            default_role_id: 1,
            auto_redirect: false,
        };
        assert_eq!(
            config.discovery_url(),
            "https://idp.example.com/realms/x/.well-known/openid-configuration"
        );
    }
}
