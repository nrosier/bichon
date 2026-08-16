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

/// Built-in Member role, granted to auto-provisioned users by default.
const DEFAULT_ROLE_ID: u64 = 100200000000000;

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
            default_role_id: default_role_id()?,
            auto_redirect: auto_redirect()?,
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

/// A setting read straight from the environment rather than from [`SETTINGS`].
///
/// The five `BICHON_OIDC_*` values above are fields of upstream's `Settings`
/// struct. These two are this fork's own, and keeping them out of that struct
/// keeps every OIDC change confined to this module — nothing to re-apply when
/// the fork is resynced, and no clash should upstream ever add the same names.
/// Reading the variable directly is what clap's `env` attribute would do anyway;
/// the cost is that these two have no `--flag` form.
fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// `BICHON_OIDC_DEFAULT_ROLE_ID`: role granted on first SSO login.
fn default_role_id() -> BichonResult<u64> {
    parse_role_id(env_var("BICHON_OIDC_DEFAULT_ROLE_ID").as_deref())
}

fn parse_role_id(raw: Option<&str>) -> BichonResult<u64> {
    match raw {
        None => Ok(DEFAULT_ROLE_ID),
        Some(raw) => raw.parse().map_err(|e| {
            raise_error!(
                format!(
                    "BICHON_OIDC_DEFAULT_ROLE_ID must be a role id, got '{}': {}.",
                    raw, e
                ),
                ErrorCode::MissingConfiguration
            )
        }),
    }
}

/// `BICHON_OIDC_AUTO_REDIRECT`: skip the sign-in page's choice of login.
fn auto_redirect() -> BichonResult<bool> {
    parse_auto_redirect(env_var("BICHON_OIDC_AUTO_REDIRECT").as_deref())
}

/// Accepts what clap accepts for a `bool`, so an operator moving the value
/// between this fork and upstream's setting sees it behave the same. A typo is
/// an error rather than a silent `false`: quietly ignoring it would turn
/// `AUTO_REDIRECT=yes` into a sign-in page that never redirects, with nothing
/// to explain why.
fn parse_auto_redirect(raw: Option<&str>) -> BichonResult<bool> {
    match raw {
        None => Ok(false),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(raise_error!(
                format!(
                    "BICHON_OIDC_AUTO_REDIRECT must be 'true' or 'false', got '{}'.",
                    other
                ),
                ErrorCode::MissingConfiguration
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_only_settings_fall_back_to_their_defaults() {
        // Unset means "behave as before the setting existed", which is what an
        // upstream resync leaves an existing deployment with.
        assert_eq!(parse_role_id(None).unwrap(), DEFAULT_ROLE_ID);
        assert!(!parse_auto_redirect(None).unwrap());
    }

    #[test]
    fn fork_only_settings_parse_what_an_operator_writes() {
        assert_eq!(parse_role_id(Some("100200000000001")).unwrap(), 100200000000001);
        for (raw, expected) in [("true", true), ("TRUE", true), ("false", false)] {
            assert_eq!(parse_auto_redirect(Some(raw)).unwrap(), expected, "{}", raw);
        }
    }

    #[test]
    fn fork_only_settings_reject_a_typo_rather_than_ignoring_it() {
        assert!(parse_role_id(Some("member")).is_err());
        for raw in ["yes", "1", "on"] {
            assert!(parse_auto_redirect(Some(raw)).is_err(), "accepted {:?}", raw);
        }
    }

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
