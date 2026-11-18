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

    fetch_classified(&url, &config.issuer_url)
        .await
        .map_err(|f| {
            let code = if f.failure.kind.is_transport() {
                ErrorCode::NetworkError
            } else {
                ErrorCode::HttpResponseError
            };
            raise_error!(f.message, code)
        })
}

/// A failure together with the operator-facing message the legacy error carried.
struct Failed {
    failure: DiscoveryFailure,
    message: String,
}

impl Failed {
    fn new(failure: DiscoveryFailure, message: String) -> Self {
        Self { failure, message }
    }
}

/// Fetch and validate the document at `url`, classifying every way it can fail.
/// `issuer` must already have its trailing slash removed.
async fn fetch_classified(url: &str, issuer: &str) -> Result<ProviderMetadata, Failed> {
    let fail = |kind: DiscoveryKind, status: Option<u16>, hint: Option<String>| DiscoveryFailure {
        kind,
        url: Some(url.to_owned()),
        status,
        hint,
    };
    let transport = |e: &reqwest::Error, what: &str| {
        let kind = classify_transport_error(e);
        Failed::new(
            fail(kind, None, None),
            format!(
                "Could not {} the OIDC discovery endpoint {}: {}",
                what, url, e
            ),
        )
    };

    let response = HTTP
        .get(url)
        .send()
        .await
        .map_err(|e| transport(&e, "reach"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(Failed::new(
            fail(
                classify_status(status.as_u16()),
                Some(status.as_u16()),
                None,
            ),
            format!(
                "The OIDC discovery endpoint {} returned HTTP {}.",
                url, status
            ),
        ));
    }

    let body = response.bytes().await.map_err(|e| transport(&e, "read"))?;

    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        Failed::new(
            fail(DiscoveryKind::NotJson, Some(status.as_u16()), None),
            format!(
                "The OIDC discovery document at {} could not be parsed: {}",
                url, e
            ),
        )
    })?;
    let metadata: ProviderMetadata = serde_json::from_value(value).map_err(|e| {
        Failed::new(
            fail(
                DiscoveryKind::Incomplete,
                Some(status.as_u16()),
                Some(e.to_string()),
            ),
            format!(
                "The OIDC discovery document at {} could not be parsed: {}",
                url, e
            ),
        )
    })?;

    // OIDC Discovery §4.3: the returned issuer MUST match the one used to build
    // the request. Skipping this check would let a compromised well-known
    // document redirect the whole flow to another issuer.
    if metadata.issuer.trim_end_matches('/') != issuer {
        return Err(Failed::new(
            fail(
                DiscoveryKind::IssuerMismatch,
                Some(status.as_u16()),
                Some(format!("The provider reports its issuer as '{}'.", metadata.issuer)),
            ),
            format!(
                "OIDC discovery mismatch: document at {} declares issuer '{}' but BICHON_OIDC_ISSUER_URL is '{}'.",
                url, metadata.issuer, issuer
            ),
        ));
    }

    Ok(metadata)
}

/// Map a non-success HTTP status to a kind.
fn classify_status(status: u16) -> DiscoveryKind {
    match status {
        300..=399 => DiscoveryKind::Redirect,
        404 => DiscoveryKind::NotFound,
        401 | 403 => DiscoveryKind::AccessDenied,
        500..=599 => DiscoveryKind::ServerError,
        _ => DiscoveryKind::HttpError,
    }
}

fn classify_transport_error(e: &reqwest::Error) -> DiscoveryKind {
    let mut chain = Vec::new();
    let mut refused = false;
    let mut src = std::error::Error::source(e);
    while let Some(err) = src {
        chain.push(err.to_string());
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            refused |= io.kind() == std::io::ErrorKind::ConnectionRefused;
        }
        src = err.source();
    }
    classify_transport(e.is_timeout(), e.is_connect(), refused, &chain)
}

/// Pure core of transport classification. `chain` is the error's source chain
/// (not including the top-level reqwest message, which embeds the URL).
fn classify_transport(
    is_timeout: bool,
    is_connect: bool,
    refused: bool,
    chain: &[String],
) -> DiscoveryKind {
    if is_timeout {
        return DiscoveryKind::Timeout;
    }
    let text = chain.join(" | ").to_ascii_lowercase();
    let dns = [
        "dns error",
        "failed to lookup",
        "name or service not known",
        "nodename nor servname",
        "no address associated",
        "name resolution",
    ]
    .iter()
    .any(|m| text.contains(m));
    if dns {
        return DiscoveryKind::Dns;
    }
    let tls = ["certificate", "tls", "ssl", "handshake", "invalid peer"]
        .iter()
        .any(|m| text.contains(m));
    if tls {
        return DiscoveryKind::Tls;
    }
    if refused || is_connect {
        return DiscoveryKind::ConnectionRefused;
    }
    DiscoveryKind::Network
}

/// The parsed discovery document.
pub type DiscoveryDocument = ProviderMetadata;

/// Why a discovery attempt failed. `kind` is the stable part the UI switches on.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryKind {
    InvalidIssuer,
    Dns,
    ConnectionRefused,
    Timeout,
    Tls,
    Network,
    Redirect,
    NotFound,
    AccessDenied,
    ServerError,
    HttpError,
    NotJson,
    Incomplete,
    IssuerMismatch,
}

impl DiscoveryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidIssuer => "invalid_issuer",
            Self::Dns => "dns",
            Self::ConnectionRefused => "connection_refused",
            Self::Timeout => "timeout",
            Self::Tls => "tls",
            Self::Network => "network",
            Self::Redirect => "redirect",
            Self::NotFound => "not_found",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::HttpError => "http_error",
            Self::NotJson => "not_json",
            Self::Incomplete => "incomplete",
            Self::IssuerMismatch => "issuer_mismatch",
        }
    }

    /// Kinds where no HTTP response was obtained.
    fn is_transport(&self) -> bool {
        matches!(
            self,
            Self::Dns | Self::ConnectionRefused | Self::Timeout | Self::Tls | Self::Network
        )
    }
}

impl std::fmt::Display for DiscoveryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryFailure {
    pub kind: DiscoveryKind,
    pub url: Option<String>,
    pub status: Option<u16>,
    pub hint: Option<String>,
}

impl DiscoveryFailure {
    /// Stable machine code, `discovery_<kind>`.
    pub fn code(&self) -> String {
        format!("discovery_{}", self.kind.as_str())
    }

    fn bare(kind: DiscoveryKind, hint: Option<String>) -> Self {
        Self {
            kind,
            url: None,
            status: None,
            hint,
        }
    }
}

impl std::fmt::Display for DiscoveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OIDC discovery failed ({})", self.kind.as_str())?;
        if let Some(url) = &self.url {
            write!(f, " at {}", url)?;
        }
        if let Some(status) = self.status {
            write!(f, ": HTTP {}", status)?;
        }
        if let Some(hint) = &self.hint {
            write!(f, ". {}", hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for DiscoveryFailure {}

/// Fetch the discovery document afresh, bypassing the cache in both directions.
/// Uses the same no-redirect client and timeouts as normal discovery.
pub async fn probe_uncached(issuer: &str) -> Result<DiscoveryDocument, DiscoveryFailure> {
    let issuer = issuer.trim().trim_end_matches('/');
    let allow_insecure = crate::oidc::config::allow_insecure_issuer()
        .map_err(|e| DiscoveryFailure::bare(DiscoveryKind::InvalidIssuer, Some(e.to_string())))?;
    crate::oidc::config::check_issuer_url(issuer, allow_insecure)
        .map_err(|e| DiscoveryFailure::bare(DiscoveryKind::InvalidIssuer, Some(e.to_string())))?;
    let url = format!("{}/.well-known/openid-configuration", issuer);
    fetch_classified(&url, issuer).await.map_err(|f| f.failure)
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
            token_endpoint_auth_methods_supported: methods.iter().map(|s| s.to_string()).collect(),
            id_token_signing_alg_values_supported: vec![],
            code_challenge_methods_supported: vec![],
            scopes_supported: vec![],
        }
    }

    #[test]
    fn token_auth_method_defaults_to_basic_when_unadvertised() {
        assert_eq!(
            metadata_with(&[]).token_auth_method(),
            TokenAuthMethod::Basic
        );
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
            link_by_email: false,
        };
        assert_eq!(
            config.discovery_url(),
            "https://idp.example.com/realms/x/.well-known/openid-configuration"
        );
    }

    // -- failure classification --------------------------------------------

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve one canned HTTP response, then return the issuer URL.
    async fn serve(response: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn http(status: &str, extra: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    async fn kind_for(response: String) -> DiscoveryFailure {
        let issuer = serve(response).await;
        probe_uncached(&issuer).await.expect_err("should fail")
    }

    #[tokio::test]
    async fn probe_succeeds_on_a_matching_document() {
        // The issuer embeds the port, which is only known after binding.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let body = format!(
            r#"{{"issuer":"{issuer}/","authorization_endpoint":"a","token_endpoint":"t","jwks_uri":"j"}}"#
        );
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(http("200 OK", "", &body).as_bytes()).await;
        });
        let doc = probe_uncached(&issuer).await.expect("probe");
        assert_eq!(doc.token_endpoint, "t");
    }

    #[tokio::test]
    async fn issuer_mismatch() {
        let body = r#"{"issuer":"https://other.example","authorization_endpoint":"a","token_endpoint":"t","jwks_uri":"j"}"#;
        let f = kind_for(http("200 OK", "", body)).await;
        assert_eq!(f.kind, DiscoveryKind::IssuerMismatch);
        assert_eq!(f.code(), "discovery_issuer_mismatch");
    }

    #[tokio::test]
    async fn not_json() {
        let f = kind_for(http("200 OK", "", "<html>hi</html>")).await;
        assert_eq!(f.kind, DiscoveryKind::NotJson);
    }

    #[tokio::test]
    async fn incomplete() {
        let f = kind_for(http("200 OK", "", r#"{"issuer":"x"}"#)).await;
        assert_eq!(f.kind, DiscoveryKind::Incomplete);
    }

    #[tokio::test]
    async fn not_found() {
        let f = kind_for(http("404 Not Found", "", "")).await;
        assert_eq!((f.kind, f.status), (DiscoveryKind::NotFound, Some(404)));
    }

    #[tokio::test]
    async fn access_denied() {
        let f = kind_for(http("403 Forbidden", "", "")).await;
        assert_eq!((f.kind, f.status), (DiscoveryKind::AccessDenied, Some(403)));
    }

    #[tokio::test]
    async fn server_error() {
        let f = kind_for(http("500 Internal Server Error", "", "")).await;
        assert_eq!((f.kind, f.status), (DiscoveryKind::ServerError, Some(500)));
    }

    #[tokio::test]
    async fn http_error() {
        let f = kind_for(http("418 I'm a teapot", "", "")).await;
        assert_eq!(f.kind, DiscoveryKind::HttpError);
    }

    #[tokio::test]
    async fn redirect() {
        let f = kind_for(http("302 Found", "Location: http://127.0.0.1:1/\r\n", "")).await;
        assert_eq!((f.kind, f.status), (DiscoveryKind::Redirect, Some(302)));
    }

    #[tokio::test]
    async fn connection_refused() {
        // Bind then drop to get a port nothing listens on.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let f = probe_uncached(&format!("http://127.0.0.1:{port}"))
            .await
            .expect_err("should fail");
        assert_eq!(f.kind, DiscoveryKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn invalid_issuer() {
        for bad in ["not a url", "http://idp.example.com", "ftp://x.example"] {
            let f = probe_uncached(bad).await.expect_err("should fail");
            assert_eq!(f.kind, DiscoveryKind::InvalidIssuer, "{bad}");
        }
    }

    #[test]
    fn transport_classification() {
        let c = |t, conn, refused, chain: &[&str]| {
            classify_transport(
                t,
                conn,
                refused,
                &chain.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(c(true, true, false, &[]), DiscoveryKind::Timeout);
        assert_eq!(
            c(
                false,
                true,
                false,
                &["dns error: failed to lookup address information"]
            ),
            DiscoveryKind::Dns
        );
        assert_eq!(
            c(
                false,
                true,
                false,
                &["invalid peer certificate: UnknownIssuer"]
            ),
            DiscoveryKind::Tls
        );
        assert_eq!(
            c(false, true, true, &["Connection refused"]),
            DiscoveryKind::ConnectionRefused
        );
        assert_eq!(
            c(false, false, false, &["connection reset"]),
            DiscoveryKind::Network
        );
    }

    #[test]
    fn kinds_serialize_snake_case_and_match_codes() {
        let all = [
            (DiscoveryKind::InvalidIssuer, "invalid_issuer"),
            (DiscoveryKind::Dns, "dns"),
            (DiscoveryKind::ConnectionRefused, "connection_refused"),
            (DiscoveryKind::Timeout, "timeout"),
            (DiscoveryKind::Tls, "tls"),
            (DiscoveryKind::Network, "network"),
            (DiscoveryKind::Redirect, "redirect"),
            (DiscoveryKind::NotFound, "not_found"),
            (DiscoveryKind::AccessDenied, "access_denied"),
            (DiscoveryKind::ServerError, "server_error"),
            (DiscoveryKind::HttpError, "http_error"),
            (DiscoveryKind::NotJson, "not_json"),
            (DiscoveryKind::Incomplete, "incomplete"),
            (DiscoveryKind::IssuerMismatch, "issuer_mismatch"),
        ];
        for (kind, name) in all {
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{name}\""));
            let f = DiscoveryFailure {
                kind,
                url: None,
                status: None,
                hint: None,
            };
            assert_eq!(f.code(), format!("discovery_{name}"));
        }
    }

    #[tokio::test]
    async fn probe_does_not_touch_the_cache() {
        let _ = probe_uncached("http://127.0.0.1:1").await;
        assert!(CACHE.read().await.is_none());
    }
}
