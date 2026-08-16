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

use std::sync::Once;

use tracing::warn;
use url::Url;

use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::raise_error;
use crate::settings::cli::SETTINGS;

/// Path the callback handler is mounted at, relative to `BICHON_BASE_URL`.
///
/// The provider must send the browser here, so this is also what a derived
/// `redirect_uri` ends with and what a configured one is checked against.
pub const CALLBACK_PATH: &str = "/api/auth/oidc/callback";

/// The `BICHON_OIDC_*` settings after validation.
///
/// Constructing one of these is the single place that decides whether OIDC is
/// usable, so handlers never have to re-check individual settings.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    /// Issuer URL with any trailing slash removed. The discovery document is
    /// fetched from `{issuer_url}/.well-known/openid-configuration` and the
    /// `iss` claim of every ID token must equal this value exactly.
    pub issuer_url: String,
    pub client_id: String,
    /// Optional: public clients (PKCE only) have no secret. Required for
    /// HS256-signed ID tokens, since the secret *is* the verification key.
    pub client_secret: Option<String>,
    /// Where the provider sends the browser back to. Defaults to the callback
    /// endpoint on `BICHON_PUBLIC_URL` when `BICHON_OIDC_REDIRECT_URI` is unset.
    pub redirect_uri: String,
    /// Role granted to users auto-provisioned on first login.
    pub default_role_id: u64,
    /// Send `/sign-in` straight to the IdP.
    pub auto_redirect: bool,
}

impl OidcConfig {
    /// Read and validate the settings.
    ///
    /// Returns `MissingConfiguration` when SSO is off or a required value is
    /// absent, so the error message doubles as operator-facing diagnostics.
    pub fn load() -> BichonResult<Self> {
        if !SETTINGS.bichon_oidc_enabled {
            return Err(raise_error!(
                "OIDC single sign-on is disabled. Set BICHON_OIDC_ENABLED=true to enable it."
                    .into(),
                ErrorCode::MissingConfiguration
            ));
        }

        let issuer_url = required(&SETTINGS.bichon_oidc_issuer_url, "BICHON_OIDC_ISSUER_URL")?;
        let client_id = required(&SETTINGS.bichon_oidc_client_id, "BICHON_OIDC_CLIENT_ID")?;

        let expected_path = callback_path(&SETTINGS.bichon_base_url);
        // Derived rather than required: the callback lives at a fixed path, so
        // the public URL is enough to name it. An operator only has to set
        // BICHON_OIDC_REDIRECT_URI when Bichon is reached under some other name.
        let redirect_uri = match optional(&SETTINGS.bichon_oidc_redirect_uri) {
            Some(configured) => configured,
            None => format!(
                "{}{}",
                SETTINGS.bichon_public_url.trim_end_matches('/'),
                expected_path
            ),
        };
        check_redirect_uri(&redirect_uri, &expected_path)?;

        if !issuer_url.starts_with("https://") && !issuer_url.starts_with("http://") {
            return Err(raise_error!(
                format!(
                    "BICHON_OIDC_ISSUER_URL must be an absolute http(s) URL, got '{}'.",
                    issuer_url
                ),
                ErrorCode::MissingConfiguration
            ));
        }

        let client_secret = SETTINGS
            .bichon_oidc_client_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        Ok(Self {
            // Trimmed so `{issuer}/.well-known/...` never doubles the slash and
            // so an operator's trailing slash cannot break the `iss` comparison.
            issuer_url: issuer_url.trim_end_matches('/').to_owned(),
            client_id,
            client_secret,
            redirect_uri,
            default_role_id: SETTINGS.bichon_oidc_default_role_id,
            auto_redirect: SETTINGS.bichon_oidc_auto_redirect,
        })
    }

    /// URL of the provider's discovery document.
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer_url)
    }
}

/// The callback path a browser must reach, including the configured UI base path.
pub fn callback_path(base_url: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), CALLBACK_PATH)
}

/// Reject a redirect URI a provider could not send a browser back to, and warn
/// about one that does not name the callback endpoint.
///
/// Pointing it at the app root instead is the usual mistake, and it used to be
/// invisible: the provider would drop the browser on the SPA with a `code` in
/// the query, no session would come of it, and with `BICHON_OIDC_AUTO_REDIRECT`
/// on the sign-in page would bounce back to the provider forever. The server
/// forwards such a callback to the right endpoint, so this only warns — but the
/// warning is the one place an operator learns the value is wrong.
fn check_redirect_uri(value: &str, expected_path: &str) -> BichonResult<()> {
    let url = Url::parse(value).map_err(|e| {
        raise_error!(
            format!(
                "BICHON_OIDC_REDIRECT_URI must be an absolute URL, got '{}': {}.",
                value, e
            ),
            ErrorCode::MissingConfiguration
        )
    })?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(raise_error!(
            format!(
                "BICHON_OIDC_REDIRECT_URI must be an http(s) URL, got '{}'.",
                value
            ),
            ErrorCode::MissingConfiguration
        ));
    }

    if url.path().trim_end_matches('/') != expected_path.trim_end_matches('/') {
        // Once per process: OidcConfig::load() runs on every OIDC request.
        static WARNED: Once = Once::new();
        WARNED.call_once(|| {
            warn!(
                "BICHON_OIDC_REDIRECT_URI is '{}', which does not point at Bichon's OIDC callback. \
                 Set it to '{}' (and register that value with the provider) so the sign-in lands \
                 where Bichon can complete it.",
                value,
                format_args!(
                    "{}{}",
                    SETTINGS.bichon_public_url.trim_end_matches('/'),
                    expected_path
                )
            );
        });
    }

    Ok(())
}

/// A setting that is present and not blank.
fn optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn required(value: &Option<String>, name: &str) -> BichonResult<String> {
    optional(value).ok_or_else(|| {
        raise_error!(
            format!("OIDC is enabled but {} is not set.", name),
            ErrorCode::MissingConfiguration
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_path_follows_the_ui_base_path() {
        assert_eq!(callback_path("/"), "/api/auth/oidc/callback");
        assert_eq!(callback_path("/bichon"), "/bichon/api/auth/oidc/callback");
        assert_eq!(callback_path("/bichon/"), "/bichon/api/auth/oidc/callback");
    }

    #[test]
    fn check_redirect_uri_accepts_the_callback_endpoint() {
        assert!(check_redirect_uri(
            "https://mail.example.com/api/auth/oidc/callback",
            &callback_path("/")
        )
        .is_ok());
        assert!(check_redirect_uri(
            "https://mail.example.com/bichon/api/auth/oidc/callback",
            &callback_path("/bichon")
        )
        .is_ok());
    }

    #[test]
    fn check_redirect_uri_tolerates_a_different_path() {
        // Warns rather than fails: the server forwards these to the callback.
        assert!(check_redirect_uri("https://mail.example.com/", &callback_path("/")).is_ok());
    }

    #[test]
    fn check_redirect_uri_rejects_what_a_browser_cannot_follow() {
        for hostile in [
            "/api/auth/oidc/callback",
            "mail.example.com/api/auth/oidc/callback",
            "javascript:alert(1)",
            "",
        ] {
            assert!(
                check_redirect_uri(hostile, &callback_path("/")).is_err(),
                "accepted {:?}",
                hostile
            );
        }
    }
}
