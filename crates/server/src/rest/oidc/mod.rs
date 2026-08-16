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

//! Everything the HTTP layer needs for OIDC single sign-on.
//!
//! Upstream Bichon ships SSO only in its paid edition, so this whole directory
//! is fork-only code and will never come back from a resync. It is written to
//! keep that resync cheap: [`rest`](crate::rest) reaches in through exactly
//! three call sites — [`attach`], [`guard_stray_callbacks`] and
//! [`advertised_features`] — and nothing else in the server knows OIDC exists.
//!
//! [`handlers`] holds the endpoints themselves.

use bichon_core::oidc::config::callback_path;
use bichon_core::settings::cli::SETTINGS;
use poem::web::Redirect;
use poem::{get, post, Endpoint, EndpointExt, IntoResponse, Request, Response, Route};

use handlers::{
    oidc_callback, oidc_config, oidc_handoff, oidc_local_logout, oidc_login, oidc_logout,
};

pub mod handlers;

/// Mount the OIDC endpoints.
///
/// Unauthenticated by design: this is how a browser without a token obtains
/// one. Each handler does its own validation.
pub fn attach(route: Route) -> Route {
    route
        .nest("/api/auth/oidc/config", get(oidc_config))
        .nest("/api/auth/oidc/login", get(oidc_login))
        .nest("/api/auth/oidc/callback", get(oidc_callback))
        .nest("/api/auth/oidc/handoff", post(oidc_handoff))
        .nest("/api/auth/oidc/local-logout", post(oidc_local_logout))
        .nest("/api/auth/oidc/logout", get(oidc_logout))
}

/// What `/api/v1/features` advertises, so the SPA can offer the SSO button
/// without a second round trip.
pub fn advertised_features() -> Vec<String> {
    if bichon_core::oidc::is_available() {
        vec!["sso".to_owned()]
    } else {
        Vec::new()
    }
}

/// Forward a provider callback that arrived at the wrong URL.
///
/// A callback landing on an SPA URL means `BICHON_OIDC_REDIRECT_URI` names
/// something other than the callback endpoint — the app root being the usual
/// mistake. Serving `index.html` would strand the browser on a page with no
/// session, which bounces it to the sign-in page; with
/// `BICHON_OIDC_AUTO_REDIRECT` on, that is an endless round trip to the
/// provider. Sending it to the endpoint that can complete the sign-in turns the
/// misconfiguration into a working login and a log line.
///
/// A wrapper rather than a branch inside the SPA handler, so that handler stays
/// byte-identical to upstream's.
pub fn guard_stray_callbacks(ep: impl Endpoint + 'static) -> impl Endpoint {
    ep.around(|ep, req| async move {
        match stray_callback_redirect(&req) {
            Some(response) => Ok(response),
            None => ep.call(req).await.map(IntoResponse::into_response),
        }
    })
}

/// The redirect to send, if this request is a misdirected callback.
fn stray_callback_redirect(req: &Request) -> Option<Response> {
    let callback = callback_path(&SETTINGS.bichon_base_url);
    // `original_uri` because `Route::nest` strips `BICHON_BASE_URL` from the
    // path it passes on, while `callback_path` includes it.
    let path = req.original_uri().path();
    if path == callback {
        return None;
    }

    let query = req.uri().query().filter(|q| looks_like_oidc_callback(q))?;
    tracing::warn!(
        "an OIDC callback arrived at '{}' instead of '{}'; forwarding it. \
         Check BICHON_OIDC_REDIRECT_URI and the redirect URI registered with the provider.",
        path,
        callback
    );
    Some(Redirect::temporary(format!("{}?{}", callback, query)).into_response())
}

/// Whether a query string is an OAuth2/OIDC callback rather than an app URL.
///
/// `state` is what distinguishes it: it is present in every response the
/// provider sends back, successful or not, and nothing in the SPA uses that name.
fn looks_like_oidc_callback(query: &str) -> bool {
    let names = query
        .split('&')
        .map(|pair| pair.split('=').next().unwrap_or_default());

    let mut has_state = false;
    let mut has_outcome = false;
    for name in names {
        match name {
            "state" => has_state = true,
            "code" | "error" => has_outcome = true,
            _ => {}
        }
    }
    has_state && has_outcome
}

#[cfg(test)]
mod tests {
    use super::looks_like_oidc_callback;

    #[test]
    fn recognises_a_provider_callback() {
        assert!(looks_like_oidc_callback("code=abc&state=xyz"));
        assert!(looks_like_oidc_callback(
            "state=xyz&code=abc&iss=https%3A%2F%2Fidp"
        ));
        // A declined sign-in carries `error` where `code` would have been.
        assert!(looks_like_oidc_callback("error=access_denied&state=xyz"));
    }

    #[test]
    fn leaves_ordinary_app_urls_alone() {
        for query in [
            "",
            "redirect=%2Fmailboxes",
            // No `state`: a search for the word "code", not a callback.
            "q=code",
            "code=abc",
            "state=xyz",
            "oidc_handoff=abc",
        ] {
            assert!(
                !looks_like_oidc_callback(query),
                "treated {:?} as a callback",
                query
            );
        }
    }
}
