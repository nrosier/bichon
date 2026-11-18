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

//! SSO administration: read, update and test the provider configuration.
//!
//! Mounted behind `ApiGuard` (so 401 without a token) and gated here on
//! `system:root` or `user:manage` (403 otherwise). Nothing in this file logs or
//! emits the client secret.

use bichon_core::error::code::ErrorCode;
use bichon_core::ext::event_bus::{emit, Event};
use bichon_core::oidc::config::{env_effective, OidcConfig};
use bichon_core::oidc::discovery;
use bichon_core::oidc::{
    apply_update, empty_view, invalidate_all, load_stored, save_stored, SsoConfigView, SsoUpdate,
};
use bichon_core::users::permissions::Permission;
use bichon_core::utc_now;
use poem::web::Json;
use poem::{handler, http::StatusCode, IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::common::auth::WrappedContext;
use crate::common::{create_api_error_response, BichonServerError};

fn require_sso_admin(context: &WrappedContext) -> Result<(), poem::Error> {
    if context.has_permission(None, Permission::ROOT)
        || context.has_permission(None, Permission::USER_MANAGE)
    {
        Ok(())
    } else {
        Err(create_api_error_response(
            "Missing permission: system:root or user:manage",
            ErrorCode::Forbidden,
        ))
    }
}

fn active() -> bool {
    OidcConfig::load().is_ok()
}

fn current_view() -> SsoConfigView {
    match load_stored() {
        Some(stored) => stored.to_view(active()),
        None => empty_view(active()),
    }
}

/// The current configuration. Never contains the secret.
#[handler]
pub async fn get_sso(context: WrappedContext) -> Result<Json<SsoConfigView>, poem::Error> {
    require_sso_admin(&context)?;
    Ok(Json(current_view()))
}

/// Merge a partial update into the stored configuration.
#[handler]
pub async fn put_sso(
    context: WrappedContext,
    Json(update): Json<SsoUpdate>,
) -> Result<Response, poem::Error> {
    require_sso_admin(&context)?;

    let current = load_stored();
    let effective = env_effective();
    let updated = match apply_update(current.as_ref(), &effective, update, utc_now!()) {
        Ok(updated) => updated,
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .content_type("application/json")
                .body(
                    serde_json::json!({
                        "code": ErrorCode::InvalidParameter.to_u32(),
                        "message": e.to_string(),
                        "field": e.field,
                    })
                    .to_string(),
                ));
        }
    };

    // Rejected with 429 by the store while a backup window is open.
    if let Err(e) = save_stored(&updated) {
        error!("could not save the SSO configuration: {}", e);
        return Err(BichonServerError(e).into());
    }

    let user = context.user.username.clone();
    info!("SSO configuration updated by '{}'", user);
    emit(Event::SsoConfigUpdated { user });
    invalidate_all().await;

    Ok(Json(updated.to_view(active())).into_response())
}

#[derive(Deserialize)]
pub struct SsoTestRequest {
    /// `null` or absent tests the issuer currently in effect.
    #[serde(default)]
    issuer_url: Option<String>,
}

/// Outcome of a discovery probe. Always served with 200; `ok` says which.
#[derive(Serialize, Default)]
pub struct SsoTestResult {
    ok: bool,
    kind: Option<String>,
    url: Option<String>,
    status: Option<u16>,
    hint: Option<String>,
    error: Option<String>,
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: Option<String>,
    end_session_endpoint: Option<String>,
}

fn invalid_issuer(hint: &str) -> SsoTestResult {
    SsoTestResult {
        kind: Some(discovery::DiscoveryKind::InvalidIssuer.to_string()),
        hint: Some(hint.to_owned()),
        error: Some(hint.to_owned()),
        ..Default::default()
    }
}

/// Fetch the discovery document for an issuer, without touching any cache.
#[handler]
pub async fn test_sso(
    context: WrappedContext,
    Json(body): Json<SsoTestRequest>,
) -> Result<Json<SsoTestResult>, poem::Error> {
    require_sso_admin(&context)?;

    let issuer = match body.issuer_url {
        Some(issuer) => Some(issuer),
        None => match load_stored() {
            Some(stored) => stored.issuer_url,
            None => env_effective().issuer_url,
        },
    };
    let issuer = issuer
        .map(|i| i.trim().to_owned())
        .filter(|i| !i.is_empty());
    let Some(issuer) = issuer else {
        return Ok(Json(invalid_issuer(
            "No issuer URL is configured or given.",
        )));
    };

    let result = match discovery::probe_uncached(&issuer).await {
        Ok(doc) => SsoTestResult {
            ok: true,
            issuer: Some(doc.issuer),
            authorization_endpoint: Some(doc.authorization_endpoint),
            token_endpoint: Some(doc.token_endpoint),
            userinfo_endpoint: doc.userinfo_endpoint,
            jwks_uri: Some(doc.jwks_uri),
            end_session_endpoint: doc.end_session_endpoint,
            ..Default::default()
        },
        Err(f) => SsoTestResult {
            ok: false,
            kind: Some(f.kind.to_string()),
            url: f.url.clone(),
            status: f.status,
            hint: f.hint.clone(),
            error: Some(f.to_string()),
            ..Default::default()
        },
    };
    Ok(Json(result))
}
