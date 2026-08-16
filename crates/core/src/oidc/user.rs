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

//! Mapping a verified OIDC identity onto a Bichon user.

use tracing::{info, warn};

use crate::database::manager::DB_MANAGER;
use crate::database::{filter_impl, insert_impl, update_impl};
use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::oidc::config::OidcConfig;
use crate::oidc::SSO_PROVIDER;
use crate::users::role::{UserRole, DEFAULT_MEMBER_ROLE_ID};
use crate::users::UserModel;
use crate::{id, raise_error, utc_now};

/// Username length accepted by `UserCreateRequest::validate`; derived usernames
/// stay inside the same bounds so SSO users look like any other user.
const USERNAME_MIN: usize = 3;
const USERNAME_MAX: usize = 32;

/// The parts of a verified identity Bichon stores or matches on.
#[derive(Clone, Debug, Default)]
pub struct SsoIdentity {
    /// The `sub` claim: stable and unique within the issuer.
    pub subject: String,
    pub email: Option<String>,
    /// Whether the provider vouches for `email`, from the claim of the same name
    /// alongside whichever source `email` came from. `None` means the provider
    /// said nothing, which counts as not verified.
    pub email_verified: Option<bool>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

/// How an identity was matched. Reported in the logs so operators can see when
/// an existing account was adopted versus a new one created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// Matched on `(sso_provider, sso_id)`.
    ExistingSsoUser,
    /// Matched on email and linked to the SSO identity.
    LinkedByEmail,
    /// No match; a new user was created.
    Provisioned,
}

/// Find the user behind a verified identity, creating one if necessary.
///
/// Lookup order (`docs/OIDC.md`, "User resolution"): `(sso_provider, sso_id)`,
/// then `email` if linking is enabled, then auto-provision with the configured
/// default role.
pub fn resolve_or_provision(
    identity: &SsoIdentity,
    config: &OidcConfig,
) -> BichonResult<(UserModel, Resolution)> {
    let subject = identity.subject.clone();
    let existing = filter_impl::<UserModel, _>(DB_MANAGER.db(), move |u| {
        u.sso_provider.as_deref() == Some(SSO_PROVIDER) && u.sso_id.as_deref() == Some(&subject)
    })?;
    if let Some(user) = existing.into_iter().next() {
        return Ok((user, Resolution::ExistingSsoUser));
    }

    // Second chance: an account created locally (or by an earlier import) with
    // the same address. Linking it means the user keeps their roles and data
    // instead of silently getting a second, empty account — but see
    // `link_check` for why it has to be asked for.
    if let Some(email) = identity.email.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
        let needle = email.to_lowercase();
        let matches = filter_impl::<UserModel, _>(DB_MANAGER.db(), move |u| {
            u.email.to_lowercase() == needle
        })?;
        if let Some(user) = matches.into_iter().next() {
            if let Some(refusal) = link_check(identity, config.link_by_email) {
                warn!(
                    "refusing to link the OIDC identity '{}' to existing user '{}' by email <{}>: {}",
                    identity.subject, user.username, email, refusal.log
                );
                return Err(raise_error!(refusal.user_facing.into(), ErrorCode::PermissionDenied));
            }
            let linked = link_to_sso(&user, &identity.subject)?;
            info!(
                "linked existing user '{}' to the OIDC identity '{}'",
                linked.username, identity.subject
            );
            return Ok((linked, Resolution::LinkedByEmail));
        }
    }

    let user = provision(identity, config.default_role_id)?;
    info!(
        "provisioned user '{}' from the OIDC identity '{}'",
        user.username, identity.subject
    );
    Ok((user, Resolution::Provisioned))
}

/// Why a link was refused: one message for the operator, one for the browser.
struct LinkRefusal {
    log: &'static str,
    /// Deliberately says nothing about the account that was matched. The person
    /// reading it authenticated at the provider, not at Bichon, so naming the
    /// Bichon username would confirm it exists to someone who has not proved
    /// they own it.
    user_facing: &'static str,
}

/// Whether a provider-asserted email may adopt an existing Bichon account.
///
/// Linking hands over that account's roles, ACLs and mailbox access on the
/// strength of an email address, so it needs the provider to be authoritative
/// about addresses. Many are not: anywhere a principal can self-register, or edit
/// their own profile email without confirming it, someone can claim an address
/// they do not own and inherit the Bichon account behind it. Two conditions have
/// to hold, and neither is safe to infer.
///
/// A refusal fails the login rather than falling through to provisioning. A second
/// account with the same address is confusing on its own, and it would bury the
/// fact that a real account was nearly handed out.
fn link_check(identity: &SsoIdentity, link_by_email: bool) -> Option<LinkRefusal> {
    if !link_by_email {
        return Some(LinkRefusal {
            log: "BICHON_OIDC_LINK_BY_EMAIL is not enabled",
            user_facing: "An account with this email address already exists in Bichon, and \
                          linking accounts by email is switched off. An administrator can set \
                          BICHON_OIDC_LINK_BY_EMAIL=true to allow it, or change the address on \
                          the existing account so a separate one is created instead.",
        });
    }

    if identity.email_verified != Some(true) {
        return Some(LinkRefusal {
            log: "the provider did not assert email_verified=true for the address",
            user_facing: "An account with this email address already exists in Bichon, but the \
                          identity provider does not confirm that this address has been verified, \
                          so the two cannot be linked automatically. Have the address verified at \
                          the provider, or change the address on the existing Bichon account so a \
                          separate one is created instead.",
        });
    }

    None
}

/// Stamp the SSO identity onto an existing user so the next login matches on
/// `(sso_provider, sso_id)` directly.
fn link_to_sso(user: &UserModel, subject: &str) -> BichonResult<UserModel> {
    let subject = subject.to_owned();
    update_impl(DB_MANAGER.db(), &user.id.to_string(), move |current: UserModel| {
        let mut updated = current;
        updated.sso_provider = Some(SSO_PROVIDER.to_string());
        updated.sso_id = Some(subject.clone());
        updated.updated_at = utc_now!();
        Ok(updated)
    })?;

    UserModel::find(user.id)?.ok_or_else(|| {
        raise_error!(
            format!("User {} disappeared while linking the SSO identity.", user.id),
            ErrorCode::InternalError
        )
    })
}

fn provision(identity: &SsoIdentity, default_role_id: u64) -> BichonResult<UserModel> {
    let email = identity
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| {
            raise_error!(
                "The identity provider returned no email address for this user, so an account cannot be created. Grant the 'email' scope to the Bichon client, or create the user in Bichon first."
                    .into(),
                ErrorCode::InvalidParameter
            )
        })?
        .to_owned();

    let now = utc_now!();
    let user = UserModel {
        id: id!(96),
        username: unique_username(identity, &email)?,
        email,
        // No local password: this account can only ever authenticate via the IdP.
        password: None,
        account_access_map: Default::default(),
        description: Some(format!(
            "Provisioned automatically on first SSO login{}",
            identity
                .name
                .as_deref()
                .map(|n| format!(" ({})", n))
                .unwrap_or_default()
        )),
        global_roles: vec![resolve_role(default_role_id)],
        avatar: None,
        created_at: now,
        updated_at: now,
        acl: None,
        theme: None,
        language: None,
        sso_id: Some(identity.subject.clone()),
        sso_provider: Some(SSO_PROVIDER.to_string()),
    };

    insert_impl(DB_MANAGER.db(), user.clone())?;
    Ok(user)
}

/// Check the configured role still exists.
///
/// A stale `BICHON_OIDC_DEFAULT_ROLE_ID` (a deleted custom role, say) would
/// otherwise produce users with no permissions at all, which looks like a broken
/// login rather than a misconfiguration. Falling back to Member keeps the user
/// able to sign in, and the warning says why.
fn resolve_role(default_role_id: u64) -> u64 {
    match UserRole::find(default_role_id) {
        Ok(Some(_)) => default_role_id,
        Ok(None) => {
            warn!(
                "BICHON_OIDC_DEFAULT_ROLE_ID={} does not match any role; falling back to the built-in Member role.",
                default_role_id
            );
            DEFAULT_MEMBER_ROLE_ID
        }
        Err(e) => {
            warn!(
                "could not look up BICHON_OIDC_DEFAULT_ROLE_ID={} ({}); falling back to the built-in Member role.",
                default_role_id, e
            );
            DEFAULT_MEMBER_ROLE_ID
        }
    }
}

/// Pick a username that is free.
///
/// Preference order: `preferred_username`, the local part of the email, then the
/// subject. Collisions get a numeric suffix rather than failing the login, since
/// the user has already authenticated successfully at this point.
fn unique_username(identity: &SsoIdentity, email: &str) -> BichonResult<String> {
    let base = identity
        .preferred_username
        .as_deref()
        .map(sanitize)
        .filter(|s| s.len() >= USERNAME_MIN)
        .or_else(|| {
            let local = email.split('@').next().unwrap_or_default();
            Some(sanitize(local)).filter(|s| s.len() >= USERNAME_MIN)
        })
        .or_else(|| Some(sanitize(&identity.subject)).filter(|s| s.len() >= USERNAME_MIN))
        // Nothing usable survived sanitising (e.g. a purely non-ASCII subject).
        .unwrap_or_else(|| format!("sso-{}", &crate::utils::hex_hash(&identity.subject)[..8]));

    if UserModel::check_username_conflict(&base).is_ok() {
        return Ok(base);
    }

    for suffix in 2..=999u32 {
        let suffix = suffix.to_string();
        // Keep room for the suffix instead of overflowing the 32-char limit.
        let trimmed = truncate(&base, USERNAME_MAX - suffix.len() - 1);
        let candidate = format!("{}-{}", trimmed, suffix);
        if UserModel::check_username_conflict(&candidate).is_ok() {
            return Ok(candidate);
        }
    }

    Err(raise_error!(
        format!(
            "Could not derive a free username from the SSO identity '{}'.",
            identity.subject
        ),
        ErrorCode::AlreadyExists
    ))
}

/// Reduce an IdP-supplied name to characters that read well as a username.
fn sanitize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(USERNAME_MAX));
    let mut last_was_separator = false;
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if matches!(ch, '.' | '-' | '_' | ' ' | '@' | '+') {
            // Collapse runs of separators and never lead with one.
            if !last_was_separator && !out.is_empty() {
                out.push('-');
                last_was_separator = true;
            }
        }
        if out.len() >= USERNAME_MAX {
            break;
        }
    }
    out.trim_end_matches('-').to_string()
}

fn truncate(value: &str, max: usize) -> &str {
    if value.len() <= max {
        value
    } else {
        &value[..max]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_normalises_idp_names() {
        assert_eq!(sanitize("Alice.Smith"), "alice-smith");
        assert_eq!(sanitize("alice@example.com"), "alice-example-com");
        assert_eq!(sanitize("  Bob  Jones  "), "bob-jones");
        assert_eq!(sanitize("--weird--"), "weird");
        // Non-ASCII characters are dropped, which can leave too little to use.
        assert_eq!(sanitize("ünïcødé"), "ncd");
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn sanitize_respects_the_length_limit() {
        let long = "a".repeat(100);
        assert_eq!(sanitize(&long).len(), USERNAME_MAX);
    }

    #[test]
    fn truncate_leaves_room_for_a_suffix() {
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("ab", 5), "ab");
    }
}
