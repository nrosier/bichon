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

//! Short-lived state for an in-flight login.
//!
//! Both stores are deliberately in-memory only. They hold a PKCE verifier and,
//! briefly, a freshly minted access token — secrets that should not be written
//! to the database or its write-ahead log. Losing them on restart only means an
//! in-flight login has to be retried.
//!
//! Entries are removed by TTL, and both maps are capacity-capped so a flood of
//! unfinished logins cannot grow memory without bound.

use std::sync::LazyLock;

use dashmap::DashMap;

use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::raise_error;
use crate::utc_now;

/// How long the user has to complete authentication at the IdP.
const PENDING_TTL_MS: i64 = 10 * 60 * 1000;

/// How long the SPA has to redeem a handoff id. Only one page load, so this can
/// be short: the shorter the window, the less useful a leaked id is.
const HANDOFF_TTL_MS: i64 = 2 * 60 * 1000;

/// Upper bound on concurrent unfinished logins.
const MAX_PENDING: usize = 4096;

/// Upper bound on unredeemed handoffs.
const MAX_HANDOFF: usize = 1024;

/// State Bichon must remember between the authorization request and the callback.
#[derive(Clone, Debug)]
pub struct PendingAuth {
    /// PKCE code verifier, sent to the token endpoint to prove this callback
    /// belongs to the authorization request Bichon started.
    pub code_verifier: String,
    /// Expected `nonce` claim of the returned ID token.
    pub nonce: String,
    /// In-app path to land on after a successful login.
    pub redirect_to: Option<String>,
    pub created_at: i64,
}

/// A minted WebUI session, waiting to be collected by the SPA.
#[derive(Clone, Debug)]
pub struct Handoff {
    pub access_token: String,
    pub username: String,
    pub theme: Option<String>,
    pub language: Option<String>,
    pub redirect_to: Option<String>,
    pub created_at: i64,
}

static PENDING: LazyLock<DashMap<String, PendingAuth>> = LazyLock::new(DashMap::new);
static HANDOFF: LazyLock<DashMap<String, Handoff>> = LazyLock::new(DashMap::new);

/// Record an authorization request, keyed by its `state` value.
pub fn put_pending(state: String, pending: PendingAuth) -> BichonResult<()> {
    sweep_pending();
    if PENDING.len() >= MAX_PENDING {
        return Err(raise_error!(
            "Too many sign-in attempts are in progress. Please try again in a few minutes.".into(),
            ErrorCode::TooManyRequest
        ));
    }
    PENDING.insert(state, pending);
    Ok(())
}

/// Consume the state recorded for `state`.
///
/// Removing on read makes the `state` value single-use, which is what stops a
/// captured callback URL from being replayed.
pub fn take_pending(state: &str) -> Option<PendingAuth> {
    let (_, pending) = PENDING.remove(state)?;
    if utc_now!() - pending.created_at > PENDING_TTL_MS {
        return None;
    }
    Some(pending)
}

/// Park a minted session and return the id the SPA will redeem it with.
pub fn put_handoff(id: String, handoff: Handoff) -> BichonResult<()> {
    sweep_handoff();
    if HANDOFF.len() >= MAX_HANDOFF {
        return Err(raise_error!(
            "Too many sign-ins are waiting to complete. Please try again in a moment.".into(),
            ErrorCode::TooManyRequest
        ));
    }
    HANDOFF.insert(id, handoff);
    Ok(())
}

/// Redeem a handoff id. One shot: a second attempt with the same id finds nothing.
pub fn take_handoff(id: &str) -> Option<Handoff> {
    let (_, handoff) = HANDOFF.remove(id)?;
    if utc_now!() - handoff.created_at > HANDOFF_TTL_MS {
        return None;
    }
    Some(handoff)
}

/// Drop expired entries from both stores.
///
/// Nothing schedules this: each `put_*` above sweeps its own store first, which
/// is enough because that is the only way an entry is ever added. Reclaiming the
/// memory needs no periodic task, so this fork adds no hook to one — expired
/// entries are already ignored on read, so a sweep is housekeeping, not
/// correctness. Both maps are bounded (4096 pending, 1024 handoffs) and a sign-in
/// touches them once, so sweeping per insert costs nothing measurable.
pub fn clean() {
    sweep_pending();
    sweep_handoff();
}

fn sweep_pending() {
    let now = utc_now!();
    PENDING.retain(|_, p| now - p.created_at <= PENDING_TTL_MS);
}

fn sweep_handoff() {
    let now = utc_now!();
    HANDOFF.retain(|_, h| now - h.created_at <= HANDOFF_TTL_MS);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(created_at: i64) -> PendingAuth {
        PendingAuth {
            code_verifier: "verifier".into(),
            nonce: "nonce".into(),
            redirect_to: None,
            created_at,
        }
    }

    fn handoff(created_at: i64) -> Handoff {
        Handoff {
            access_token: "token".into(),
            username: "alice".into(),
            theme: None,
            language: None,
            redirect_to: None,
            created_at,
        }
    }

    #[test]
    fn pending_state_is_single_use() {
        put_pending("state-single-use".into(), pending(utc_now!())).unwrap();
        assert!(take_pending("state-single-use").is_some());
        assert!(take_pending("state-single-use").is_none());
    }

    #[test]
    fn expired_pending_state_is_not_returned() {
        put_pending(
            "state-expired".into(),
            pending(utc_now!() - PENDING_TTL_MS - 1),
        )
        .unwrap();
        assert!(take_pending("state-expired").is_none());
    }

    #[test]
    fn unknown_pending_state_is_not_returned() {
        assert!(take_pending("state-never-issued").is_none());
    }

    #[test]
    fn handoff_is_single_use() {
        put_handoff("handoff-single-use".into(), handoff(utc_now!())).unwrap();
        let taken = take_handoff("handoff-single-use").unwrap();
        assert_eq!(taken.access_token, "token");
        assert!(take_handoff("handoff-single-use").is_none());
    }

    #[test]
    fn expired_handoff_is_not_returned() {
        put_handoff(
            "handoff-expired".into(),
            handoff(utc_now!() - HANDOFF_TTL_MS - 1),
        )
        .unwrap();
        assert!(take_handoff("handoff-expired").is_none());
    }

    #[test]
    fn clean_drops_only_expired_entries() {
        put_handoff("handoff-fresh".into(), handoff(utc_now!())).unwrap();
        put_handoff(
            "handoff-stale".into(),
            handoff(utc_now!() - HANDOFF_TTL_MS - 1),
        )
        .unwrap();
        clean();
        assert!(HANDOFF.contains_key("handoff-fresh"));
        assert!(!HANDOFF.contains_key("handoff-stale"));
        HANDOFF.remove("handoff-fresh");
    }
}
