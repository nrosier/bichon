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

//! OpenID Connect single sign-on.
//!
//! Implements the Authorization Code flow with PKCE (S256) against any
//! spec-compliant provider. The provider is described entirely by its
//! discovery document, so nothing about a particular IdP is hardcoded.
//!
//! Layout:
//! - [`config`]: the validated view of the `BICHON_OIDC_*` settings.
//! - [`discovery`]: cached `.well-known/openid-configuration` fetch.
//! - [`jwks`]: cached signing-key set, looked up by `kid`.
//! - [`jwt`]: ID token signature and claim verification.
//! - [`store`]: short-lived in-memory pending-auth and handoff state.
//! - [`user`]: mapping an verified identity onto a Bichon user.
//! - [`flow`]: the login / callback / logout orchestration.

pub mod config;
pub mod discovery;
pub mod flow;
pub mod jwks;
pub mod jwt;
pub mod store;
pub mod user;

/// Value stored in [`crate::users::BichonUserV2::sso_provider`] for users
/// authenticated through this module.
pub const SSO_PROVIDER: &str = "oidc";

/// Whether OIDC login is switched on *and* configured well enough to attempt.
///
/// Used by the public `/api/auth/oidc/config` endpoint and the feature list so
/// the SPA only offers the SSO button when it would actually work.
pub fn is_available() -> bool {
    config::OidcConfig::load().is_ok()
}
