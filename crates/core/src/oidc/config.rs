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
use url::{Host, Url};

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
    /// Adopt an existing Bichon account whose email matches the one the provider
    /// asserts. Off by default: see [`crate::oidc::user::resolve_or_provision`].
    pub link_by_email: bool,
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

        check_issuer_url(&issuer_url, allow_insecure_issuer()?)?;

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
            link_by_email: link_by_email()?,
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

/// Require HTTPS for the issuer, with two deliberate exceptions.
///
/// Everything Bichon sends the provider over this URL is a bearer secret: the
/// client secret on the token request, the authorization code, and the ID token
/// coming back. Over plain HTTP all of it is readable and rewritable by anything
/// on the path, which also means an attacker who can answer for the issuer can
/// mint an ID token and sign in as anybody.
///
/// Loopback is exempt because there is no network to be on the path of, and that
/// is how the flow is usually developed against. Everything else needs
/// `BICHON_OIDC_ALLOW_INSECURE_ISSUER=true`, which exists so a working LAN
/// deployment is not broken by an upgrade — the operator has to say so.
fn check_issuer_url(value: &str, allow_insecure: bool) -> BichonResult<()> {
    let url = Url::parse(value).map_err(|e| {
        raise_error!(
            format!(
                "BICHON_OIDC_ISSUER_URL must be an absolute URL, got '{}': {}.",
                value, e
            ),
            ErrorCode::MissingConfiguration
        )
    })?;

    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&url) => Ok(()),
        "http" if allow_insecure => {
            // Once per process: OidcConfig::load() runs on every OIDC request.
            static WARNED: Once = Once::new();
            WARNED.call_once(|| {
                warn!(
                    "BICHON_OIDC_ISSUER_URL is '{}', so the client secret, authorization code \
                     and ID token all travel unencrypted. BICHON_OIDC_ALLOW_INSECURE_ISSUER is \
                     set, so this is permitted — but anything on the network path can read them \
                     and can impersonate the provider.",
                    value
                );
            });
            Ok(())
        }
        "http" => Err(raise_error!(
            format!(
                "BICHON_OIDC_ISSUER_URL is '{}', but plain HTTP would expose the client secret, \
                 the authorization code and the ID token to anything on the network path. Use \
                 https, or set BICHON_OIDC_ALLOW_INSECURE_ISSUER=true to accept that risk \
                 (loopback addresses need no such setting).",
                value
            ),
            ErrorCode::MissingConfiguration
        )),
        other => Err(raise_error!(
            format!(
                "BICHON_OIDC_ISSUER_URL must be an http(s) URL, got scheme '{}'.",
                other
            ),
            ErrorCode::MissingConfiguration
        )),
    }
}

/// Whether a URL names this machine, and so cannot be observed on a network.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        // RFC 6761: `localhost` and anything under it resolve to loopback.
        Some(Host::Domain(domain)) => {
            let domain = domain.to_ascii_lowercase();
            domain == "localhost" || domain.ends_with(".localhost")
        }
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
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
/// struct. The rest are this fork's own, and keeping them out of that struct
/// keeps every OIDC change confined to this module — nothing to re-apply when
/// the fork is resynced, and no clash should upstream ever add the same names.
/// Reading the variable directly is what clap's `env` attribute would do anyway;
/// the cost is that these have no `--flag` form.
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
    env_bool("BICHON_OIDC_AUTO_REDIRECT")
}

/// `BICHON_OIDC_LINK_BY_EMAIL`: let a provider-asserted email adopt an existing
/// Bichon account. Off by default because it makes the provider's word about an
/// address sufficient to inherit that account.
fn link_by_email() -> BichonResult<bool> {
    env_bool("BICHON_OIDC_LINK_BY_EMAIL")
}

/// `BICHON_OIDC_ALLOW_INSECURE_ISSUER`: permit a non-loopback `http://` issuer.
fn allow_insecure_issuer() -> BichonResult<bool> {
    env_bool("BICHON_OIDC_ALLOW_INSECURE_ISSUER")
}

fn env_bool(name: &str) -> BichonResult<bool> {
    parse_bool(name, env_var(name).as_deref())
}

/// Accepts what clap accepts for a `bool`, so an operator moving a value between
/// this fork and upstream's settings sees it behave the same. A typo is an error
/// rather than a silent `false`: quietly ignoring it would turn
/// `AUTO_REDIRECT=yes` into a sign-in page that never redirects, with nothing to
/// explain why — and `LINK_BY_EMAIL=yes` into a security setting that reads as
/// enabled but is not.
fn parse_bool(name: &str, raw: Option<&str>) -> BichonResult<bool> {
    match raw {
        None => Ok(false),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(raise_error!(
                format!("{} must be 'true' or 'false', got '{}'.", name, other),
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
        // upstream resync leaves an existing deployment with. For the two
        // security settings that default is also the safe one.
        assert_eq!(parse_role_id(None).unwrap(), DEFAULT_ROLE_ID);
        for name in [
            "BICHON_OIDC_AUTO_REDIRECT",
            "BICHON_OIDC_LINK_BY_EMAIL",
            "BICHON_OIDC_ALLOW_INSECURE_ISSUER",
        ] {
            assert!(!parse_bool(name, None).unwrap(), "{}", name);
        }
    }

    #[test]
    fn fork_only_settings_parse_what_an_operator_writes() {
        assert_eq!(parse_role_id(Some("100200000000001")).unwrap(), 100200000000001);
        for (raw, expected) in [("true", true), ("TRUE", true), ("false", false)] {
            assert_eq!(parse_bool("SETTING", Some(raw)).unwrap(), expected, "{}", raw);
        }
    }

    #[test]
    fn fork_only_settings_reject_a_typo_rather_than_ignoring_it() {
        assert!(parse_role_id(Some("member")).is_err());
        for raw in ["yes", "1", "on"] {
            assert!(
                parse_bool("SETTING", Some(raw)).is_err(),
                "accepted {:?}",
                raw
            );
        }
    }

    #[test]
    fn a_typo_names_the_setting_it_came_from() {
        let message = parse_bool("BICHON_OIDC_LINK_BY_EMAIL", Some("yes"))
            .unwrap_err()
            .to_string();
        assert!(message.contains("BICHON_OIDC_LINK_BY_EMAIL"), "{}", message);
    }

    #[test]
    fn issuer_url_must_use_https() {
        assert!(check_issuer_url("https://idp.example.com", false).is_ok());
        assert!(check_issuer_url("http://idp.example.com", false).is_err());
    }

    #[test]
    fn issuer_url_may_be_plain_http_on_loopback() {
        for local in [
            "http://localhost:9000",
            "http://LOCALHOST:9000/application/o/bichon/",
            "http://authentik.localhost",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            assert!(check_issuer_url(local, false).is_ok(), "rejected {}", local);
        }
    }

    #[test]
    fn issuer_url_may_be_plain_http_when_the_operator_opts_in() {
        // A LAN IdP: insecure, but breaking a working deployment on upgrade is
        // worse than letting the operator say they accept it.
        assert!(check_issuer_url("http://192.168.1.10:9000", false).is_err());
        assert!(check_issuer_url("http://192.168.1.10:9000", true).is_ok());
    }

    #[test]
    fn issuer_url_rejects_what_is_not_a_web_url() {
        for hostile in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "idp.example.com",
            "",
        ] {
            assert!(
                check_issuer_url(hostile, true).is_err(),
                "accepted {:?}",
                hostile
            );
        }
    }

    #[test]
    fn opting_into_insecure_http_does_not_also_allow_other_schemes() {
        assert!(check_issuer_url("ftp://idp.example.com", true).is_err());
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
