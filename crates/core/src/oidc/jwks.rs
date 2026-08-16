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

//! The provider's JSON Web Key Set, cached and looked up by `kid`.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::oidc::discovery::HTTP;
use crate::raise_error;
use crate::utc_now;

/// Normal lifetime of a cached key set.
const CACHE_TTL_MS: i64 = 60 * 60 * 1000;

/// Floor on how often an unknown `kid` may trigger an out-of-band re-fetch.
/// Without it, a stream of tokens carrying random `kid`s would turn every login
/// attempt into an outbound request to the IdP.
const MIN_REFETCH_INTERVAL_MS: i64 = 60 * 1000;

/// A single JSON Web Key. Only the members needed to verify RSA and P-256
/// signatures are modelled; everything else in the key is ignored.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Jwk {
    /// Key type: `RSA` or `EC`.
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    /// Algorithm the key is intended for, when the provider states it.
    #[serde(default)]
    pub alg: Option<String>,
    /// `sig` or `enc`. Encryption keys are never signature candidates.
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
    /// RSA modulus (base64url, unpadded).
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent (base64url, unpadded).
    #[serde(default)]
    pub e: Option<String>,
    /// EC curve name, e.g. `P-256`.
    #[serde(default)]
    pub crv: Option<String>,
    /// EC x coordinate (base64url, unpadded).
    #[serde(default)]
    pub x: Option<String>,
    /// EC y coordinate (base64url, unpadded).
    #[serde(default)]
    pub y: Option<String>,
}

impl Jwk {
    /// True when the key could be used to verify a signature.
    fn is_signature_key(&self) -> bool {
        !matches!(self.key_use.as_deref(), Some("enc"))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct JwkSet {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Find the key a token's header points at.
    ///
    /// With a `kid` the match must be exact. Without one the set must contain
    /// exactly one signature key, otherwise the choice would be a guess.
    pub fn find(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self
                .keys
                .iter()
                .find(|k| k.is_signature_key() && k.kid.as_deref() == Some(kid)),
            None => {
                let mut candidates = self.keys.iter().filter(|k| k.is_signature_key());
                let first = candidates.next()?;
                candidates.next().is_none().then_some(first)
            }
        }
    }
}

struct Cached {
    jwks_uri: String,
    keys: JwkSet,
    fetched_at: i64,
}

static CACHE: LazyLock<RwLock<Option<Cached>>> = LazyLock::new(|| RwLock::new(None));

/// Resolve the signing key for a token header.
///
/// Serves from cache when possible. A cache miss on the `kid` re-fetches once
/// (subject to [`MIN_REFETCH_INTERVAL_MS`]) so that a key rotation at the IdP
/// does not require a Bichon restart.
pub async fn signing_key(jwks_uri: &str, kid: Option<&str>) -> BichonResult<Jwk> {
    let now = utc_now!();

    let (hit, stale, may_refetch) = {
        let guard = CACHE.read().await;
        match guard.as_ref() {
            Some(cached) if cached.jwks_uri == jwks_uri => (
                cached.keys.find(kid).cloned(),
                now - cached.fetched_at >= CACHE_TTL_MS,
                now - cached.fetched_at >= MIN_REFETCH_INTERVAL_MS,
            ),
            _ => (None, true, true),
        }
    };

    if let Some(key) = hit {
        if !stale {
            return Ok(key);
        }
    } else if !may_refetch {
        return Err(unknown_key(kid));
    }

    let keys = match fetch(jwks_uri).await {
        Ok(keys) => keys,
        Err(e) => {
            // A fresh copy could not be obtained. If the cached set already
            // answers the question, a transient IdP outage should not fail logins.
            let guard = CACHE.read().await;
            if let Some(key) = guard
                .as_ref()
                .filter(|c| c.jwks_uri == jwks_uri)
                .and_then(|c| c.keys.find(kid).cloned())
            {
                debug!("serving a stale JWKS entry after a refresh failure: {}", e);
                return Ok(key);
            }
            return Err(e);
        }
    };

    let found = keys.find(kid).cloned();

    let mut guard = CACHE.write().await;
    *guard = Some(Cached {
        jwks_uri: jwks_uri.to_owned(),
        keys,
        fetched_at: utc_now!(),
    });
    drop(guard);

    found.ok_or_else(|| unknown_key(kid))
}

fn unknown_key(kid: Option<&str>) -> crate::error::BichonError {
    match kid {
        Some(kid) => raise_error!(
            format!(
                "The ID token was signed with key '{}', which is not published in the provider's JWKS.",
                kid
            ),
            ErrorCode::PermissionDenied
        ),
        None => raise_error!(
            "The ID token has no 'kid' header and the provider publishes more than one signing key, so the key cannot be determined."
                .into(),
            ErrorCode::PermissionDenied
        ),
    }
}

async fn fetch(jwks_uri: &str) -> BichonResult<JwkSet> {
    debug!("fetching OIDC signing keys from {}", jwks_uri);

    let response = HTTP.get(jwks_uri).send().await.map_err(|e| {
        raise_error!(
            format!("Could not reach the OIDC JWKS endpoint {}: {}", jwks_uri, e),
            ErrorCode::NetworkError
        )
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(raise_error!(
            format!("The OIDC JWKS endpoint {} returned HTTP {}.", jwks_uri, status),
            ErrorCode::HttpResponseError
        ));
    }

    let keys: JwkSet = response.json().await.map_err(|e| {
        raise_error!(
            format!("The JWKS at {} could not be parsed: {}", jwks_uri, e),
            ErrorCode::HttpResponseError
        )
    })?;

    if keys.keys.is_empty() {
        return Err(raise_error!(
            format!("The JWKS at {} contains no keys.", jwks_uri),
            ErrorCode::HttpResponseError
        ));
    }

    Ok(keys)
}

/// Replace the cached key set. Used by tests to avoid network access.
#[cfg(test)]
pub(crate) async fn seed_cache(jwks_uri: &str, keys: JwkSet) {
    *CACHE.write().await = Some(Cached {
        jwks_uri: jwks_uri.to_owned(),
        keys,
        fetched_at: utc_now!(),
    });
}

/// Drop the cached key set.
pub async fn invalidate_cache() {
    *CACHE.write().await = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kid: Option<&str>, key_use: Option<&str>) -> Jwk {
        Jwk {
            kty: "RSA".into(),
            kid: kid.map(str::to_owned),
            alg: Some("RS256".into()),
            key_use: key_use.map(str::to_owned),
            n: Some("abc".into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
            y: None,
        }
    }

    #[test]
    fn find_matches_on_kid() {
        let set = JwkSet {
            keys: vec![key(Some("a"), None), key(Some("b"), None)],
        };
        assert_eq!(set.find(Some("b")).unwrap().kid.as_deref(), Some("b"));
        assert!(set.find(Some("c")).is_none());
    }

    #[test]
    fn find_without_kid_requires_a_single_key() {
        let single = JwkSet {
            keys: vec![key(Some("a"), None)],
        };
        assert!(single.find(None).is_some());

        let many = JwkSet {
            keys: vec![key(Some("a"), None), key(Some("b"), None)],
        };
        assert!(many.find(None).is_none());
    }

    #[test]
    fn find_skips_encryption_keys() {
        let set = JwkSet {
            keys: vec![key(Some("a"), Some("enc")), key(Some("b"), Some("sig"))],
        };
        assert!(set.find(Some("a")).is_none());
        // 'a' is an encryption key, so 'b' is the only signature candidate.
        assert_eq!(set.find(None).unwrap().kid.as_deref(), Some("b"));
    }
}
