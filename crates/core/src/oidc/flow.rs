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

//! The Authorization Code flow with PKCE, from the sign-in click to a WebUI token.
//!
//! ```text
//!  SPA                     Bichon                        IdP
//!   │  GET /oidc/login       │                            │
//!   ├───────────────────────►│  state+nonce+PKCE stored   │
//!   │◄── 302 authorize ──────┤ ─────────────────────────► │
//!   │                        │                            │  user authenticates
//!   │                        │◄── GET /oidc/callback ──────┤
//!   │                        │ ── POST /token ──────────► │
//!   │                        │◄── id_token ───────────────┤
//!   │                        │  verify, resolve user,     │
//!   │◄── 302 ?oidc_handoff ──┤  mint token, park handoff  │
//!   │  POST /oidc/handoff    │                            │
//!   ├───────────────────────►│                            │
//!   │◄── access_token ───────┤  handoff consumed          │
//! ```
//!
//! The access token is delivered in a response body rather than a redirect URL,
//! so it never lands in browser history, a `Referer` header or an access log.

use oauth2::PkceCodeChallenge;
use serde::Deserialize;
use tracing::{debug, warn};
use url::Url;

use crate::error::code::ErrorCode;
use crate::error::{BichonError, BichonResult};
use crate::oidc::config::OidcConfig;
use crate::oidc::discovery::{self, DiscoveryFailure, ProviderMetadata, TokenAuthMethod, HTTP};
use crate::oidc::jwt::{self, IdTokenClaims};
use crate::oidc::store::{self, Handoff, PendingAuth};
use crate::oidc::user::{self, ResolveError, SsoIdentity};
use crate::token::AccessTokenModel;
use crate::{generate_token, raise_error, utc_now};

/// Scopes Bichon needs. `openid` is mandatory; the other two supply the email
/// address and display name used when provisioning.
const WANTED_SCOPES: [&str; 3] = ["openid", "profile", "email"];

/// Outcome of a successful callback.
#[derive(Clone, Debug)]
pub struct CompletedLogin {
    /// One-shot id the SPA exchanges for the access token.
    pub handoff_id: String,
    /// In-app path the user was heading to before signing in.
    pub redirect_to: Option<String>,
    /// For the audit event.
    pub username: String,
}

/// Every way the sign-in flow can fail, each with one stable [`code`].
///
/// `Display` is for logs only: it may name URLs, settings and IdP responses.
/// The browser is only ever told the code.
///
/// [`code`]: FlowError::code
#[derive(Debug)]
pub enum FlowError {
    /// SSO is not active or its configuration is missing (`OidcConfig::load`).
    Unavailable(BichonError),
    /// The authorization request could not be built or stored.
    StartFailed(BichonError),
    /// Token exchange, ID token verification, or minting the session failed.
    Failed(BichonError),
    /// The IdP redirected back with an `error` parameter.
    Declined { error: String },
    /// The callback is missing `code` or `state`.
    Incomplete,
    /// The `state` is unknown, expired, or already used.
    StateInvalid,
    /// Fetching or validating the discovery document failed.
    Discovery {
        failure: DiscoveryFailure,
        /// The operator-facing error the legacy path carried.
        error: BichonError,
    },
    /// The allowlist is set and the identity's email is missing, unverified or
    /// in a domain that is not on it.
    EmailDomainNotAllowed,
    /// The identity could not be mapped onto a Bichon user.
    Resolve(ResolveError),
}

impl FlowError {
    /// Stable machine code for the sign-in page.
    pub fn code(&self) -> String {
        match self {
            Self::Unavailable(_) => "sso_unavailable".into(),
            Self::StartFailed(_) => "sso_start_failed".into(),
            Self::Failed(_) => "sso_failed".into(),
            Self::Declined { .. } => "sso_declined".into(),
            Self::Incomplete => "sso_incomplete".into(),
            Self::StateInvalid => "sso_state_invalid".into(),
            Self::Discovery { failure, .. } => failure.code(),
            Self::EmailDomainNotAllowed => "email_domain_not_allowed".into(),
            Self::Resolve(e) => e.code().into(),
        }
    }
}

const STATE_INVALID_MESSAGE: &str = "This sign-in link is no longer valid. It may have expired or already been used; please start again.";

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(e) | Self::StartFailed(e) | Self::Failed(e) => write!(f, "{}", e),
            Self::Declined { error } => {
                write!(f, "The identity provider declined the sign-in (error={:?}).", error)
            }
            Self::Incomplete => f.write_str(
                "The sign-in response from the identity provider was missing 'code' or 'state'.",
            ),
            Self::StateInvalid => f.write_str(STATE_INVALID_MESSAGE),
            Self::Discovery { error, .. } => write!(f, "{}", error),
            Self::EmailDomainNotAllowed => f.write_str(
                "The identity's email address is missing, not verified by the provider, or not in an allowed domain.",
            ),
            Self::Resolve(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for FlowError {}

impl From<FlowError> for BichonError {
    fn from(e: FlowError) -> Self {
        match e {
            FlowError::Unavailable(inner)
            | FlowError::StartFailed(inner)
            | FlowError::Failed(inner)
            | FlowError::Discovery { error: inner, .. } => inner,
            FlowError::Resolve(inner) => inner.into(),
            FlowError::Incomplete => raise_error!(e.to_string(), ErrorCode::InvalidParameter),
            FlowError::Declined { .. }
            | FlowError::StateInvalid
            | FlowError::EmailDomainNotAllowed => {
                raise_error!(e.to_string(), ErrorCode::PermissionDenied)
            }
        }
    }
}

fn discovery_error((failure, error): (DiscoveryFailure, BichonError)) -> FlowError {
    FlowError::Discovery { failure, error }
}

/// Whether `email` may sign in under `allowed` (already normalized, lowercase).
///
/// An empty list allows everyone. Otherwise the provider must vouch for the
/// address (`email_verified == Some(true)`) and its domain, the part after the
/// last `@`, must match an entry case-insensitively.
fn email_domain_allowed(allowed: &[String], email: Option<&str>, verified: Option<bool>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    if verified != Some(true) {
        return false;
    }
    let Some(email) = email.map(str::trim).filter(|e| !e.is_empty()) else {
        return false;
    };
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    let domain = domain.to_lowercase();
    !domain.is_empty() && allowed.iter().any(|d| d.eq_ignore_ascii_case(&domain))
}

/// Build the authorization URL and remember what the callback will need.
///
/// `redirect_to` is the in-app path to return to; it is stored server-side
/// rather than round-tripped through the IdP.
pub async fn begin(config: &OidcConfig, redirect_to: Option<String>) -> BichonResult<String> {
    begin_coded(config, redirect_to).await.map_err(BichonError::from)
}

/// [`begin`] with a classified error.
pub async fn begin_coded(
    config: &OidcConfig,
    redirect_to: Option<String>,
) -> Result<String, FlowError> {
    let metadata = discovery::provider_metadata_detailed(config)
        .await
        .map_err(discovery_error)?;

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = generate_token!(160);
    let nonce = generate_token!(160);

    if !metadata.code_challenge_methods_supported.is_empty()
        && !metadata
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
    {
        return Err(FlowError::StartFailed(raise_error!(
            format!(
                "The provider advertises PKCE methods {:?} but Bichon requires S256.",
                metadata.code_challenge_methods_supported
            ),
            ErrorCode::Incompatible
        )));
    }

    let mut url = Url::parse(&metadata.authorization_endpoint).map_err(|e| {
        FlowError::StartFailed(raise_error!(
            format!(
                "The provider's authorization_endpoint '{}' is not a valid URL: {}",
                metadata.authorization_endpoint, e
            ),
            ErrorCode::HttpResponseError
        ))
    })?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_uri)
            .append_pair("scope", &scopes(&metadata))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256");
    }

    store::put_pending(
        state,
        PendingAuth {
            code_verifier: verifier.secret().clone(),
            nonce,
            redirect_to,
            created_at: utc_now!(),
        },
    )
    .map_err(FlowError::StartFailed)?;

    Ok(url.to_string())
}

/// Exchange the authorization code, verify the identity and mint a session.
pub async fn complete(config: &OidcConfig, state: &str, code: &str) -> BichonResult<CompletedLogin> {
    complete_coded(config, state, code)
        .await
        .map_err(BichonError::from)
}

/// [`complete`] with a classified error.
pub async fn complete_coded(
    config: &OidcConfig,
    state: &str,
    code: &str,
) -> Result<CompletedLogin, FlowError> {
    // Consuming the pending entry is what makes `state` single-use, and it is
    // done before any network call so a replayed callback cannot even reach the IdP.
    let pending = store::take_pending(state).ok_or(FlowError::StateInvalid)?;

    let metadata = discovery::provider_metadata_detailed(config)
        .await
        .map_err(discovery_error)?;
    let tokens = exchange_code(config, &metadata, code, &pending.code_verifier)
        .await
        .map_err(FlowError::Failed)?;

    let id_token = tokens.id_token.as_deref().ok_or_else(|| {
        FlowError::Failed(raise_error!(
            "The provider's token response contained no id_token. Check that the Bichon client is configured for OpenID Connect and that the 'openid' scope is allowed."
                .into(),
            ErrorCode::HttpResponseError
        ))
    })?;

    let claims = jwt::verify_id_token(id_token, config, &metadata.jwks_uri, &pending.nonce)
        .await
        .map_err(FlowError::Failed)?;

    let identity = build_identity(&claims, &metadata, &tokens.access_token).await;

    // Checked on the identity that resolution will use, so the address that
    // passed the allowlist is the one that gets linked or provisioned.
    if !email_domain_allowed(
        &config.allowed_email_domains,
        identity.email.as_deref(),
        identity.email_verified,
    ) {
        let domain = identity
            .email
            .as_deref()
            .and_then(|e| e.trim().rsplit_once('@'))
            .map(|(_, d)| d.to_lowercase());
        debug!(
            "OIDC login refused by the email-domain allowlist (domain={:?}, email_verified={:?})",
            domain, identity.email_verified
        );
        return Err(FlowError::EmailDomainNotAllowed);
    }

    let (user, resolution) =
        user::resolve_or_provision_coded(&identity, config).map_err(FlowError::Resolve)?;
    debug!(
        "OIDC login for '{}' resolved as {:?}",
        user.username, resolution
    );

    // A fresh WebUI token per login, matching what password login does.
    let access_token = AccessTokenModel::reset_webui_token(user.id).map_err(FlowError::Failed)?;

    let handoff_id = generate_token!(160);
    store::put_handoff(
        handoff_id.clone(),
        Handoff {
            access_token,
            username: user.username.clone(),
            theme: user.theme.clone(),
            language: user.language.clone(),
            redirect_to: pending.redirect_to.clone(),
            created_at: utc_now!(),
        },
    )
    .map_err(FlowError::Failed)?;

    Ok(CompletedLogin {
        handoff_id,
        redirect_to: pending.redirect_to,
        username: user.username,
    })
}

/// The provider's RP-initiated logout URL, if it supports one.
///
/// `client_id` plus `post_logout_redirect_uri` is used instead of
/// `id_token_hint`, so Bichon never has to retain ID tokens after login.
pub async fn logout_url(
    config: &OidcConfig,
    post_logout_redirect_uri: &str,
) -> BichonResult<Option<String>> {
    let metadata = discovery::provider_metadata(config).await?;
    let Some(endpoint) = metadata.end_session_endpoint.as_deref() else {
        return Ok(None);
    };

    let mut url = Url::parse(endpoint).map_err(|e| {
        raise_error!(
            format!(
                "The provider's end_session_endpoint '{}' is not a valid URL: {}",
                endpoint, e
            ),
            ErrorCode::HttpResponseError
        )
    })?;
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("post_logout_redirect_uri", post_logout_redirect_uri);

    Ok(Some(url.to_string()))
}

/// The token endpoint response. Only `access_token` and `id_token` are used.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

/// Error body defined by RFC 6749 §5.2, surfaced so operators see what the IdP
/// actually objected to.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

async fn exchange_code(
    config: &OidcConfig,
    metadata: &ProviderMetadata,
    code: &str,
    code_verifier: &str,
) -> BichonResult<TokenResponse> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &config.redirect_uri),
        ("code_verifier", code_verifier),
        // Sent unconditionally: required for public clients and harmless
        // alongside Basic authentication (RFC 6749 §4.1.3).
        ("client_id", &config.client_id),
    ];

    let method = metadata.token_auth_method();
    let mut request = HTTP.post(&metadata.token_endpoint);

    match (method, config.client_secret.as_deref()) {
        (TokenAuthMethod::Basic, Some(secret)) => {
            request = request.basic_auth(&config.client_id, Some(secret));
        }
        (TokenAuthMethod::Post, Some(secret)) => {
            form.push(("client_secret", secret));
        }
        (TokenAuthMethod::None, _) => {}
        (_, None) => {
            // The provider expects a secret but none is configured. PKCE still
            // protects the exchange, so try anyway and let the IdP decide.
            debug!("no OIDC client secret configured; attempting a public-client token exchange");
        }
    }

    let response = request
        .form(&form)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            raise_error!(
                format!(
                    "Could not reach the OIDC token endpoint {}: {}",
                    metadata.token_endpoint, e
                ),
                ErrorCode::NetworkError
            )
        })?;

    let status = response.status();
    let body = response.text().await.map_err(|e| {
        raise_error!(
            format!("Could not read the OIDC token response: {}", e),
            ErrorCode::HttpResponseError
        )
    })?;

    if !status.is_success() {
        let detail = serde_json::from_str::<TokenErrorResponse>(&body)
            .map(|e| match e.error_description {
                Some(description) => format!("{}: {}", e.error, description),
                None => e.error,
            })
            // Never echo an unparseable body: it may contain the request that
            // carried our client secret back to us.
            .unwrap_or_else(|_| format!("HTTP {}", status));
        return Err(raise_error!(
            format!("The OIDC token exchange was rejected ({}).", detail),
            ErrorCode::PermissionDenied
        ));
    }

    serde_json::from_str(&body).map_err(|e| {
        raise_error!(
            format!("The OIDC token response could not be parsed: {}", e),
            ErrorCode::HttpResponseError
        )
    })
}

/// Collect the identity attributes, consulting the userinfo endpoint only when
/// the ID token is missing something needed for provisioning.
async fn build_identity(
    claims: &IdTokenClaims,
    metadata: &ProviderMetadata,
    access_token: &str,
) -> SsoIdentity {
    let mut identity = SsoIdentity {
        subject: claims.sub.clone(),
        email: claims.email.clone(),
        email_verified: claims.email_verified,
        preferred_username: claims.preferred_username.clone(),
        name: claims.name.clone(),
    };

    if identity.email.is_some() {
        return identity;
    }

    let Some(endpoint) = metadata.userinfo_endpoint.as_deref() else {
        return identity;
    };

    match fetch_userinfo(endpoint, access_token, &claims.sub).await {
        Ok(info) => {
            // Both taken from userinfo together: a verification flag only says
            // anything about the address it was published next to.
            identity.email = info.email;
            identity.email_verified = info.email_verified;
            identity.preferred_username = identity.preferred_username.or(info.preferred_username);
            identity.name = identity.name.or(info.name);
        }
        Err(e) => {
            // Not fatal on its own: provisioning reports the missing email with
            // an actionable message, and existing users do not need it at all.
            warn!("could not read the OIDC userinfo endpoint: {}", e);
        }
    }

    identity
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, deserialize_with = "jwt::lenient_bool")]
    email_verified: Option<bool>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

async fn fetch_userinfo(
    endpoint: &str,
    access_token: &str,
    expected_subject: &str,
) -> BichonResult<UserInfo> {
    let response = HTTP
        .get(endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            raise_error!(
                format!("Could not reach the userinfo endpoint {}: {}", endpoint, e),
                ErrorCode::NetworkError
            )
        })?;

    let status = response.status();
    if !status.is_success() {
        return Err(raise_error!(
            format!("The userinfo endpoint {} returned HTTP {}.", endpoint, status),
            ErrorCode::HttpResponseError
        ));
    }

    let info: UserInfo = response.json().await.map_err(|e| {
        raise_error!(
            format!("The userinfo response could not be parsed: {}", e),
            ErrorCode::HttpResponseError
        )
    })?;

    // OIDC Core §5.3.2: the subject returned here must be the one in the ID
    // token, otherwise the response describes a different user.
    if info.sub != expected_subject {
        return Err(raise_error!(
            "The userinfo response is for a different subject than the ID token.".into(),
            ErrorCode::PermissionDenied
        ));
    }

    Ok(info)
}

/// The scope string to request.
///
/// `profile` and `email` are dropped when the provider explicitly lists its
/// supported scopes and does not include them, since some providers reject the
/// whole request over one unknown scope.
fn scopes(metadata: &ProviderMetadata) -> String {
    if metadata.scopes_supported.is_empty() {
        return WANTED_SCOPES.join(" ");
    }
    let mut requested: Vec<&str> = WANTED_SCOPES
        .iter()
        .copied()
        .filter(|s| *s == "openid" || metadata.scopes_supported.iter().any(|sup| sup == s))
        .collect();
    if !requested.contains(&"openid") {
        requested.insert(0, "openid");
    }
    requested.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(scopes_supported: &[&str], code_challenge_methods: &[&str]) -> ProviderMetadata {
        ProviderMetadata {
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "https://idp.example.com/auth".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            userinfo_endpoint: None,
            end_session_endpoint: None,
            token_endpoint_auth_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
            code_challenge_methods_supported: code_challenge_methods
                .iter()
                .map(|s| s.to_string())
                .collect(),
            scopes_supported: scopes_supported.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_allowlist_accepts_any_identity() {
        assert!(email_domain_allowed(&[], Some("a@anything.test"), Some(true)));
        // Skipped entirely: current behaviour for unverified or missing email.
        assert!(email_domain_allowed(&[], Some("a@anything.test"), None));
        assert!(email_domain_allowed(&[], None, None));
    }

    #[test]
    fn allowlist_accepts_a_verified_in_list_domain_case_insensitively() {
        let allowed = domains(&["example.com", "corp.example.org"]);
        assert!(email_domain_allowed(&allowed, Some("alice@example.com"), Some(true)));
        assert!(email_domain_allowed(&allowed, Some("Bob@EXAMPLE.Com"), Some(true)));
        assert!(email_domain_allowed(&allowed, Some("c@Corp.Example.Org"), Some(true)));
        // The domain is what follows the last '@'.
        assert!(email_domain_allowed(&allowed, Some("\"a@b\"@example.com"), Some(true)));
    }

    #[test]
    fn allowlist_rejects_an_off_list_domain() {
        let allowed = domains(&["example.com"]);
        assert!(!email_domain_allowed(&allowed, Some("a@evil.com"), Some(true)));
        assert!(!email_domain_allowed(&allowed, Some("a@sub.example.com"), Some(true)));
        assert!(!email_domain_allowed(&allowed, Some("a@example.com.evil.com"), Some(true)));
        assert!(!email_domain_allowed(&allowed, Some("example.com@evil.com"), Some(true)));
        assert!(!email_domain_allowed(&allowed, Some("no-at-sign"), Some(true)));
        assert!(!email_domain_allowed(&allowed, Some("a@"), Some(true)));
    }

    #[test]
    fn allowlist_rejects_a_missing_email() {
        let allowed = domains(&["example.com"]);
        assert!(!email_domain_allowed(&allowed, None, Some(true)));
        assert!(!email_domain_allowed(&allowed, Some("  "), Some(true)));
    }

    #[test]
    fn allowlist_rejects_an_unverified_email_even_in_an_allowed_domain() {
        let allowed = domains(&["example.com"]);
        assert!(!email_domain_allowed(&allowed, Some("a@example.com"), Some(false)));
        assert!(!email_domain_allowed(&allowed, Some("a@example.com"), None));
    }

    fn err(message: &str) -> BichonError {
        raise_error!(message.into(), ErrorCode::InternalError)
    }

    #[test]
    fn every_flow_error_has_its_code() {
        use crate::oidc::discovery::DiscoveryKind;
        let failure = DiscoveryFailure {
            kind: DiscoveryKind::Timeout,
            url: None,
            status: None,
            hint: None,
        };
        let cases: Vec<(FlowError, &str)> = vec![
            (FlowError::Unavailable(err("x")), "sso_unavailable"),
            (FlowError::StartFailed(err("x")), "sso_start_failed"),
            (FlowError::Failed(err("x")), "sso_failed"),
            (
                FlowError::Declined {
                    error: "access_denied".into(),
                },
                "sso_declined",
            ),
            (FlowError::Incomplete, "sso_incomplete"),
            (FlowError::StateInvalid, "sso_state_invalid"),
            (
                FlowError::Discovery {
                    failure,
                    error: err("x"),
                },
                "discovery_timeout",
            ),
            (FlowError::EmailDomainNotAllowed, "email_domain_not_allowed"),
            (FlowError::Resolve(ResolveError::LinkDisabled), "sso_link_disabled"),
            (
                FlowError::Resolve(ResolveError::LinkUnverifiedEmail),
                "sso_link_unverified_email",
            ),
            (FlowError::Resolve(ResolveError::NoEmail), "sso_no_email"),
            (FlowError::Resolve(ResolveError::Internal(err("x"))), "sso_failed"),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code, "{error:?}");
        }
    }

    #[test]
    fn legacy_wrappers_keep_the_original_messages() {
        let state: BichonError = FlowError::StateInvalid.into();
        assert_eq!(state.to_string(), STATE_INVALID_MESSAGE);
        assert_eq!(state.code(), ErrorCode::PermissionDenied);

        let inner: BichonError = FlowError::Failed(err("token exchange rejected")).into();
        assert_eq!(inner.to_string(), "token exchange rejected");

        // Display never echoes an email address for the allowlist refusal.
        assert!(!FlowError::EmailDomainNotAllowed.to_string().contains('@'));
    }

    #[test]
    fn scopes_default_to_the_full_set_when_unadvertised() {
        assert_eq!(scopes(&metadata(&[], &[])), "openid profile email");
    }

    #[test]
    fn scopes_drop_what_the_provider_does_not_support() {
        assert_eq!(
            scopes(&metadata(&["openid", "email"], &[])),
            "openid email"
        );
    }

    #[test]
    fn scopes_always_include_openid() {
        // Some providers omit `openid` from scopes_supported even though it is
        // mandatory; requesting it anyway is the only way the flow can work.
        assert_eq!(scopes(&metadata(&["email"], &[])), "openid email");
    }
}
