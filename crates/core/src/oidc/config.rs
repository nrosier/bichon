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

use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::raise_error;
use crate::settings::cli::SETTINGS;

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
        let redirect_uri = required(
            &SETTINGS.bichon_oidc_redirect_uri,
            "BICHON_OIDC_REDIRECT_URI",
        )?;

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

fn required(value: &Option<String>, name: &str) -> BichonResult<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            raise_error!(
                format!("OIDC is enabled but {} is not set.", name),
                ErrorCode::MissingConfiguration
            )
        })
}
