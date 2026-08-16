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

//! Public OIDC endpoints.
//!
//! These sit outside `ApiGuard` because they are what an unauthenticated
//! browser uses to obtain a session in the first place.

use bichon_core::error::BichonError;
use bichon_core::ext::event_bus::{emit, Event};
use bichon_core::oidc::config::OidcConfig;
use bichon_core::oidc::{flow, store};
use bichon_core::settings::cli::SETTINGS;
use bichon_core::token::AccessTokenModel;
use poem::web::headers::authorization::Bearer;
use poem::web::headers::{Authorization, HeaderMapExt};
use poem::web::{Json, Query, RealIp, Redirect};
use poem::{handler, FromRequest, IntoResponse, Request, Response};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

/// What the SPA needs to decide how to render the sign-in page.
#[derive(Serialize)]
pub struct OidcConfigResponse {
    /// True when SSO is switched on and configured well enough to attempt.
    enabled: bool,
    /// Send the user straight to the provider instead of showing the form.
    auto_redirect: bool,
}

/// SSO availability. Safe to call unauthenticated: it reveals whether SSO is on,
/// never the issuer, client id or secret.
#[handler]
pub async fn oidc_config() -> impl IntoResponse {
    let config = OidcConfig::load();
    if let Err(e) = &config {
        // Only interesting when the operator meant to switch SSO on.
        if SETTINGS.bichon_oidc_enabled {
            warn!("OIDC is enabled but not usable: {}", e);
        }
    }
    Json(OidcConfigResponse {
        auto_redirect: config.as_ref().map(|c| c.auto_redirect).unwrap_or(false),
        enabled: config.is_ok(),
    })
}

#[derive(Deserialize)]
pub struct LoginParams {
    /// In-app path to return to after signing in.
    redirect: Option<String>,
}

/// Start the flow: redirect the browser to the provider.
#[handler]
pub async fn oidc_login(Query(params): Query<LoginParams>) -> Response {
    let config = match OidcConfig::load() {
        Ok(config) => config,
        Err(e) => return sign_in_error("sso_unavailable", &e),
    };

    match flow::begin(&config, safe_redirect(params.redirect)).await {
        Ok(url) => Redirect::temporary(url).into_response(),
        Err(e) => {
            error!("could not start the OIDC login flow: {}", e);
            sign_in_error("sso_start_failed", &e)
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    /// Set instead of `code` when the provider or the user declines.
    error: Option<String>,
    error_description: Option<String>,
}

/// The provider's redirect target.
///
/// On success the browser is sent to the SPA with a one-shot handoff id — never
/// with the access token itself, which would end up in history and logs.
#[handler]
pub async fn oidc_callback(Query(params): Query<CallbackParams>, req: &Request) -> Response {
    if let Some(error) = params.error.as_deref() {
        let detail = params
            .error_description
            .as_deref()
            .map(|d| format!("{}: {}", error, d))
            .unwrap_or_else(|| error.to_string());
        warn!("the identity provider declined the sign-in ({})", detail);
        return redirect_to_sign_in(&format!(
            "?oidc_error={}",
            urlencoding::encode(&format!(
                "The identity provider declined the sign-in ({}).",
                detail
            ))
        ));
    }

    let (Some(code), Some(state)) = (params.code.as_deref(), params.state.as_deref()) else {
        return redirect_to_sign_in(&format!(
            "?oidc_error={}",
            urlencoding::encode(
                "The sign-in response from the identity provider was incomplete. Please try again."
            )
        ));
    };

    let config = match OidcConfig::load() {
        Ok(config) => config,
        Err(e) => return sign_in_error("sso_unavailable", &e),
    };

    let completed = match flow::complete(&config, state, code).await {
        Ok(completed) => completed,
        Err(e) => {
            error!("the OIDC callback failed: {}", e);
            return sign_in_error("sso_failed", &e);
        }
    };

    let ip = RealIp::from_request_without_body(req)
        .await
        .ok()
        .and_then(|r| r.0);
    info!("OIDC sign-in succeeded for '{}'", completed.username);
    emit(Event::SsoLogin {
        user: completed.username,
        ip,
    });

    redirect_to_sign_in(&format!(
        "?oidc_handoff={}",
        urlencoding::encode(&completed.handoff_id)
    ))
}

#[derive(Deserialize)]
pub struct HandoffRequest {
    id: String,
}

/// Shaped like the password-login response so the SPA can reuse `setToken`.
#[derive(Serialize)]
pub struct HandoffResponse {
    success: bool,
    error_message: Option<String>,
    access_token: Option<String>,
    theme: Option<String>,
    language: Option<String>,
    /// In-app path the user was heading to before signing in.
    redirect_to: Option<String>,
}

/// Redeem a handoff id for the access token.
///
/// A `POST` with the id in the body, so the token is only ever in a response
/// body: nothing lands in the URL, in `Referer`, or in an access log.
#[handler]
pub async fn oidc_handoff(Json(payload): Json<HandoffRequest>) -> Response {
    // One shot. A replayed id — from a shared link or a stale tab — finds nothing.
    let Some(handoff) = store::take_handoff(&payload.id) else {
        return Json(HandoffResponse {
            success: false,
            error_message: Some(
                "This sign-in has already been completed or has expired. Please sign in again."
                    .into(),
            ),
            access_token: None,
            theme: None,
            language: None,
            redirect_to: None,
        })
        .with_status(http::StatusCode::UNAUTHORIZED)
        .into_response();
    };

    Json(HandoffResponse {
        success: true,
        error_message: None,
        access_token: Some(handoff.access_token),
        theme: handoff.theme,
        language: handoff.language,
        redirect_to: handoff.redirect_to,
    })
    .into_response()
}

/// Sign out of Bichon while leaving the provider session alone.
///
/// The caller's WebUI token is revoked server-side, so clearing the SPA's local
/// storage is no longer the only thing standing between a stolen token and the API.
#[handler]
pub async fn oidc_local_logout(req: &Request) -> Response {
    let Some(token) = bearer_token(req) else {
        // Nothing to revoke; the SPA still clears its own state.
        return Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .finish();
    };

    match AccessTokenModel::resolve_user_from_token(&token) {
        Ok(user) => {
            if let Err(e) = AccessTokenModel::delete(&token) {
                error!("could not revoke the WebUI token on sign-out: {}", e);
            }
            emit(Event::SsoLogout { user: user.username });
        }
        Err(e) => {
            // An expired or unknown token: the session is already gone.
            warn!("sign-out with an unusable token: {}", e);
        }
    }

    Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .finish()
}

/// End the provider session too (RP-initiated logout), then come back here.
///
/// This is a top-level browser navigation, so it carries no `Authorization`
/// header and cannot revoke anything: the SPA calls `local-logout` first and
/// only then sends the browser here.
#[handler]
pub async fn oidc_logout() -> Response {
    let config = match OidcConfig::load() {
        Ok(config) => config,
        Err(e) => return sign_in_error("sso_unavailable", &e),
    };

    // Absolute, because the provider redirects the browser back to us.
    let post_logout = format!(
        "{}{}",
        SETTINGS.bichon_public_url.trim_end_matches('/'),
        app_url("/sign-in?local=1")
    );

    match flow::logout_url(&config, &post_logout).await {
        Ok(Some(url)) => Redirect::temporary(url).into_response(),
        Ok(None) => {
            // The provider offers no logout endpoint; a local sign-out is all
            // Bichon can do.
            warn!(
                "the identity provider publishes no end_session_endpoint, so the SSO session stays open"
            );
            redirect_to_sign_in("?local=1")
        }
        Err(e) => {
            error!("could not build the OIDC logout URL: {}", e);
            redirect_to_sign_in("?local=1")
        }
    }
}

/// Prefix a path with the configured UI base path.
fn app_url(path: &str) -> String {
    format!("{}{}", SETTINGS.bichon_base_url.trim_end_matches('/'), path)
}

fn redirect_to_sign_in(query: &str) -> Response {
    Redirect::temporary(app_url(&format!("/sign-in{}", query))).into_response()
}

fn sign_in_error(code: &str, error: &BichonError) -> Response {
    redirect_to_sign_in(&format!(
        "?oidc_error={}&oidc_error_code={}",
        urlencoding::encode(&error.to_string()),
        urlencoding::encode(code)
    ))
}

fn bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .typed_get::<Authorization<Bearer>>()
        .map(|auth| auth.0.token().to_string())
}

/// Accept only in-app paths as a post-login destination.
///
/// Without this the `redirect` parameter would be an open redirect: an attacker
/// could send `?redirect=https://look-alike.example` and have Bichon's own
/// domain bounce the user to a credential-harvesting page after a real login.
fn safe_redirect(raw: Option<String>) -> Option<String> {
    let value = raw?;
    let is_safe = value.starts_with('/')
        // "//host" and "/\host" are protocol-relative URLs, not local paths.
        && !value.starts_with("//")
        && !value.starts_with("/\\")
        && !value.contains('\\')
        && !value.chars().any(char::is_control);

    if is_safe {
        Some(value)
    } else {
        warn!("ignoring an unsafe OIDC redirect target: {:?}", value);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_redirect_accepts_in_app_paths() {
        assert_eq!(
            safe_redirect(Some("/mailboxes/42".into())).as_deref(),
            Some("/mailboxes/42")
        );
        assert_eq!(safe_redirect(Some("/".into())).as_deref(), Some("/"));
        assert_eq!(
            safe_redirect(Some("/search?q=a&b=c".into())).as_deref(),
            Some("/search?q=a&b=c")
        );
    }

    #[test]
    fn safe_redirect_rejects_off_site_targets() {
        for hostile in [
            "https://evil.example.com",
            "//evil.example.com",
            "/\\evil.example.com",
            "\\\\evil.example.com",
            "javascript:alert(1)",
            "/path\\with-backslash",
            "/path\nwith-newline",
            "mailboxes/42",
            "",
        ] {
            assert!(
                safe_redirect(Some(hostile.into())).is_none(),
                "accepted {:?}",
                hostile
            );
        }
    }

    #[test]
    fn safe_redirect_passes_through_absence() {
        assert!(safe_redirect(None).is_none());
    }
}
