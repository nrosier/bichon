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

//! Cached health probe for the configured SSO provider.
//!
//! The sign-in page and the settings UI both ask "can SSO be used right now?".
//! Answering that needs a discovery fetch, so the result is cached for
//! [`STATUS_TTL_MS`] and concurrent callers share a single probe.

use std::future::Future;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::oidc::config::{env_effective, OidcConfig};
use crate::oidc::discovery::{self, DiscoveryDocument, DiscoveryFailure};
use crate::oidc::settings::load_stored;
use crate::utc_now;

/// How long a probe result (success or failure) is reused.
const STATUS_TTL_MS: i64 = 30 * 1000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SsoStatus {
    /// The issuer, client id and redirect URI are all present.
    pub configured: bool,
    /// SSO is enabled and the provider's discovery document is reachable.
    pub available: bool,
    /// `discovery_<kind>` when the last probe failed.
    pub code: Option<String>,
    /// UTC milliseconds at which the probe (or the inactive check) ran.
    pub checked_at: i64,
}

struct Entry {
    issuer: String,
    result: SsoStatus,
}

/// Held across the probe, which is what makes concurrent callers share it.
static CACHE: LazyLock<Mutex<Option<Entry>>> = LazyLock::new(|| Mutex::new(None));

/// Current status of SSO. Makes no outbound request while SSO is inactive.
pub async fn status() -> SsoStatus {
    let configured = match load_stored() {
        Some(stored) => stored.is_configured(),
        None => env_effective().is_configured(),
    };
    let issuer = OidcConfig::load().ok().map(|c| c.issuer_url);
    status_with(configured, issuer, |issuer| async move {
        discovery::probe_uncached(&issuer).await
    })
    .await
}

/// `issuer` is `Some` only when SSO is active.
async fn status_with<F, Fut>(configured: bool, issuer: Option<String>, probe: F) -> SsoStatus
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<DiscoveryDocument, DiscoveryFailure>>,
{
    let Some(issuer) = issuer else {
        return SsoStatus {
            configured,
            available: false,
            code: None,
            checked_at: utc_now!(),
        };
    };

    let mut guard = CACHE.lock().await;
    if let Some(entry) = guard.as_ref() {
        if entry.issuer == issuer
            && entry.result.configured == configured
            && utc_now!() - entry.result.checked_at < STATUS_TTL_MS
        {
            return entry.result.clone();
        }
    }

    let outcome = probe(issuer.clone()).await;
    let result = SsoStatus {
        configured,
        available: outcome.is_ok(),
        code: outcome.err().map(|f| f.code()),
        checked_at: utc_now!(),
    };
    *guard = Some(Entry {
        issuer,
        result: result.clone(),
    });
    result
}

/// Drop the cached status.
pub async fn invalidate_cache() {
    *CACHE.lock().await = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::discovery::{DiscoveryKind, ProviderMetadata};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // The status cache is process-global, so these tests must not interleave.
    static SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn doc() -> ProviderMetadata {
        ProviderMetadata {
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "a".into(),
            token_endpoint: "t".into(),
            jwks_uri: "j".into(),
            userinfo_endpoint: None,
            end_session_endpoint: None,
            token_endpoint_auth_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
            code_challenge_methods_supported: vec![],
            scopes_supported: vec![],
        }
    }

    async fn counted(
        calls: &Arc<AtomicUsize>,
        issuer: &str,
        outcome: Result<DiscoveryDocument, DiscoveryFailure>,
    ) -> SsoStatus {
        let calls = calls.clone();
        status_with(true, Some(issuer.into()), move |_| async move {
            calls.fetch_add(1, Ordering::SeqCst);
            outcome
        })
        .await
    }

    #[tokio::test]
    async fn inactive_makes_no_probe() {
        let _s = SERIAL.lock().await;
        invalidate_cache().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let st = status_with(false, None, move |_| async move {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(doc())
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!st.available && !st.configured && st.code.is_none());
        assert!(st.checked_at > 0);
    }

    #[tokio::test]
    async fn result_is_cached_and_invalidate_clears_it() {
        let _s = SERIAL.lock().await;
        invalidate_cache().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let first = counted(&calls, "https://a.example", Ok(doc())).await;
        assert!(first.available && first.code.is_none());
        let second = counted(&calls, "https://a.example", Ok(doc())).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(first, second);

        crate::oidc::invalidate_all().await;
        counted(&calls, "https://a.example", Ok(doc())).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failures_are_cached_with_a_code() {
        let _s = SERIAL.lock().await;
        invalidate_cache().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = || DiscoveryFailure {
            kind: DiscoveryKind::NotFound,
            url: None,
            status: Some(404),
            hint: None,
        };
        let a = counted(&calls, "https://b.example", Err(fail())).await;
        let b = counted(&calls, "https://b.example", Err(fail())).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!a.available);
        assert_eq!(a.code.as_deref(), Some("discovery_not_found"));
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_probe() {
        let _s = SERIAL.lock().await;
        invalidate_cache().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                status_with(
                    true,
                    Some("https://c.example".into()),
                    move |_| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        Ok(doc())
                    },
                )
                .await
            }));
        }
        for t in tasks {
            assert!(t.await.unwrap().available);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_changed_issuer_is_probed_again() {
        let _s = SERIAL.lock().await;
        invalidate_cache().await;
        let calls = Arc::new(AtomicUsize::new(0));
        counted(&calls, "https://d.example", Ok(doc())).await;
        counted(&calls, "https://e.example", Ok(doc())).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
