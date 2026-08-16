//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project

//! DB-backed tests for the OIDC login path.
//!
//! The algorithm and store logic is unit-tested in `bichon-core`; what is left
//! to cover here is the part that needs a real database and a real HTTP stack:
//! how a verified identity turns into a user, and how the SPA collects its
//! access token.

use bichon_core::oidc::store::{self, Handoff};
use bichon_core::oidc::user::{resolve_or_provision, Resolution, SsoIdentity};
use bichon_core::oidc::SSO_PROVIDER;
use bichon_core::users::role::DEFAULT_MEMBER_ROLE_ID;
use bichon_core::users::{UserModel, DEFAULT_ADMIN_USER_ID};
use bichon_core::utc_now;
use serde::Deserialize;

use crate::rest::public::oidc::oidc_handoff;
use crate::tests::setup;

/// Mirrors `HandoffResponse`, whose fields are private to the handler module.
#[derive(Debug, Deserialize)]
struct HandoffBody {
    success: bool,
    error_message: Option<String>,
    access_token: Option<String>,
    theme: Option<String>,
    language: Option<String>,
    redirect_to: Option<String>,
}

fn handoff_route() -> poem::Route {
    poem::Route::new().at("/api/auth/oidc/handoff", poem::post(oidc_handoff))
}

/// Distinct per test: `setup()` shares one database across the whole binary, so
/// tests that provision users must not collide on subject or email.
fn identity(tag: &str) -> SsoIdentity {
    SsoIdentity {
        subject: format!("subject-{tag}"),
        email: Some(format!("{tag}@oidc.example.com")),
        preferred_username: Some(format!("user-{tag}")),
        name: Some(format!("Test {tag}")),
    }
}

// ── User resolution ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_identity_is_provisioned_with_the_default_role() {
    setup().await;

    let identity = identity("provision");
    let (user, resolution) =
        resolve_or_provision(&identity, DEFAULT_MEMBER_ROLE_ID).expect("provisioning should succeed");

    assert_eq!(resolution, Resolution::Provisioned);
    assert_eq!(user.sso_provider.as_deref(), Some(SSO_PROVIDER));
    assert_eq!(user.sso_id.as_deref(), Some(identity.subject.as_str()));
    assert_eq!(user.email, "provision@oidc.example.com");
    assert!(
        user.global_roles.contains(&DEFAULT_MEMBER_ROLE_ID),
        "expected the default role, got {:?}",
        user.global_roles
    );
}

#[tokio::test]
async fn a_second_login_matches_the_same_user() {
    setup().await;

    let identity = identity("repeat");
    let (first, first_resolution) =
        resolve_or_provision(&identity, DEFAULT_MEMBER_ROLE_ID).expect("first login should succeed");
    assert_eq!(first_resolution, Resolution::Provisioned);

    // Same subject, different profile claims: the match is on (provider, sub),
    // so this must find the existing account rather than create a second one.
    let returning = SsoIdentity {
        subject: identity.subject.clone(),
        email: Some("renamed@oidc.example.com".into()),
        preferred_username: Some("renamed".into()),
        name: Some("Renamed".into()),
    };
    let (second, second_resolution) =
        resolve_or_provision(&returning, DEFAULT_MEMBER_ROLE_ID).expect("second login should succeed");

    assert_eq!(second_resolution, Resolution::ExistingSsoUser);
    assert_eq!(second.id, first.id);
}

#[tokio::test]
async fn an_existing_local_user_is_linked_by_email() {
    setup().await;

    // A local account the operator created before turning SSO on. `setup()`
    // seeds the built-in admin, which is exactly that: a password user with no
    // SSO identity.
    let local = UserModel::find(DEFAULT_ADMIN_USER_ID)
        .expect("lookup should succeed")
        .expect("the admin user exists after setup");
    assert!(
        local.sso_provider.is_none(),
        "the admin user should start without an SSO identity"
    );

    let identity = SsoIdentity {
        subject: "subject-link".into(),
        email: Some(local.email.to_uppercase()), // also checks case-insensitive matching
        preferred_username: Some("admin-from-idp".into()),
        name: Some("Admin".into()),
    };
    let (linked, resolution) =
        resolve_or_provision(&identity, DEFAULT_MEMBER_ROLE_ID).expect("linking should succeed");

    assert_eq!(resolution, Resolution::LinkedByEmail);
    assert_eq!(linked.id, local.id, "must adopt the account, not clone it");
    assert_eq!(linked.sso_id.as_deref(), Some("subject-link"));
    assert_eq!(
        linked.global_roles, local.global_roles,
        "linking must not change the roles the user already had"
    );
}

// ── Handoff redemption ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_handoff_is_redeemed_once_and_only_once() {
    setup().await;

    store::put_handoff(
        "handoff-once".into(),
        Handoff {
            access_token: "token-once".into(),
            username: "sso-user".into(),
            theme: Some("dark".into()),
            language: Some("nl".into()),
            redirect_to: Some("/mailboxes/42".into()),
            created_at: utc_now!(),
        },
    )
    .expect("parking a handoff should succeed");

    let cli = poem::test::TestClient::new(handoff_route());

    let resp = cli
        .post("/api/auth/oidc/handoff")
        .body_json(&serde_json::json!({ "id": "handoff-once" }))
        .send()
        .await;
    resp.assert_status_is_ok();

    let body: HandoffBody = resp.json().await.value().deserialize();
    assert!(body.success);
    assert_eq!(body.access_token.as_deref(), Some("token-once"));
    assert_eq!(body.theme.as_deref(), Some("dark"));
    assert_eq!(body.language.as_deref(), Some("nl"));
    assert_eq!(body.redirect_to.as_deref(), Some("/mailboxes/42"));
    assert!(body.error_message.is_none());

    // Replaying the same id must not hand out the token a second time: the id
    // travels in a URL, so a copied link has to be worthless once used.
    let replay = cli
        .post("/api/auth/oidc/handoff")
        .body_json(&serde_json::json!({ "id": "handoff-once" }))
        .send()
        .await;
    assert_eq!(replay.0.status(), poem::http::StatusCode::UNAUTHORIZED);

    let replay_body: HandoffBody = replay.json().await.value().deserialize();
    assert!(!replay_body.success);
    assert!(replay_body.access_token.is_none());
    assert!(
        replay_body.error_message.is_some(),
        "the SPA shows this message, so it must be present"
    );
}

#[tokio::test]
async fn an_unknown_handoff_id_is_rejected() {
    setup().await;

    let cli = poem::test::TestClient::new(handoff_route());
    let resp = cli
        .post("/api/auth/oidc/handoff")
        .body_json(&serde_json::json!({ "id": "no-such-handoff" }))
        .send()
        .await;

    assert_eq!(resp.0.status(), poem::http::StatusCode::UNAUTHORIZED);
    let body: HandoffBody = resp.json().await.value().deserialize();
    assert!(!body.success);
    assert!(body.access_token.is_none());
}
