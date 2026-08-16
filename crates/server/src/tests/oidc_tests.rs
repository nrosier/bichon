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

use bichon_core::oidc::config::OidcConfig;
use bichon_core::oidc::store::{self, Handoff};
use bichon_core::oidc::user::{resolve_or_provision, Resolution, SsoIdentity};
use bichon_core::oidc::SSO_PROVIDER;
use bichon_core::users::role::DEFAULT_MEMBER_ROLE_ID;
use bichon_core::users::{UserModel, DEFAULT_ADMIN_USER_ID};
use bichon_core::utc_now;
use serde::Deserialize;

use crate::rest::oidc::handlers::oidc_handoff;
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
        // Only consulted when an email is about to adopt an existing account.
        email_verified: Some(true),
        preferred_username: Some(format!("user-{tag}")),
        name: Some(format!("Test {tag}")),
    }
}

/// A config built directly, since `OidcConfig::load()` reads the environment the
/// test binary happens to run in.
fn config(link_by_email: bool) -> OidcConfig {
    OidcConfig {
        issuer_url: "https://idp.example.com".into(),
        client_id: "bichon".into(),
        client_secret: None,
        redirect_uri: "https://mail.example.com/api/auth/oidc/callback".into(),
        default_role_id: DEFAULT_MEMBER_ROLE_ID,
        auto_redirect: false,
        link_by_email,
    }
}

/// The seeded admin: the local account an operator already has before turning
/// SSO on, and so the one an email match would adopt.
fn local_admin() -> UserModel {
    UserModel::find(DEFAULT_ADMIN_USER_ID)
        .expect("lookup should succeed")
        .expect("the admin user exists after setup")
}

// ── User resolution ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_identity_is_provisioned_with_the_default_role() {
    setup().await;

    let identity = identity("provision");
    let (user, resolution) =
        resolve_or_provision(&identity, &config(false)).expect("provisioning should succeed");

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
        resolve_or_provision(&identity, &config(false)).expect("first login should succeed");
    assert_eq!(first_resolution, Resolution::Provisioned);

    // Same subject, different profile claims: the match is on (provider, sub),
    // so this must find the existing account rather than create a second one.
    // Nothing about the email — not even a missing verification flag — can get
    // in the way once an identity is attached.
    let returning = SsoIdentity {
        subject: identity.subject.clone(),
        email: Some("renamed@oidc.example.com".into()),
        email_verified: None,
        preferred_username: Some("renamed".into()),
        name: Some("Renamed".into()),
    };
    let (second, second_resolution) =
        resolve_or_provision(&returning, &config(false)).expect("second login should succeed");

    assert_eq!(second_resolution, Resolution::ExistingSsoUser);
    assert_eq!(second.id, first.id);
}

#[tokio::test]
async fn an_existing_local_user_is_linked_by_email_when_asked_for() {
    setup().await;

    let local = local_admin();
    assert!(
        local.sso_provider.is_none(),
        "the admin user should start without an SSO identity"
    );

    let identity = SsoIdentity {
        subject: "subject-link".into(),
        email: Some(local.email.to_uppercase()), // also checks case-insensitive matching
        email_verified: Some(true),
        preferred_username: Some("admin-from-idp".into()),
        name: Some("Admin".into()),
    };
    let (linked, resolution) =
        resolve_or_provision(&identity, &config(true)).expect("linking should succeed");

    assert_eq!(resolution, Resolution::LinkedByEmail);
    assert_eq!(linked.id, local.id, "must adopt the account, not clone it");
    assert_eq!(linked.sso_id.as_deref(), Some("subject-link"));
    assert_eq!(
        linked.global_roles, local.global_roles,
        "linking must not change the roles the user already had"
    );
}

/// The default. Adopting an account on the strength of an email address hands
/// over its roles and mailbox access, so it has to be switched on deliberately.
#[tokio::test]
async fn linking_is_refused_unless_it_is_switched_on() {
    setup().await;

    let identity = SsoIdentity {
        subject: "subject-link-disabled".into(),
        email: Some(local_admin().email),
        email_verified: Some(true),
        ..Default::default()
    };

    let error = resolve_or_provision(&identity, &config(false))
        .expect_err("the login must fail rather than link or clone");
    let message = error.to_string();
    assert!(
        message.contains("BICHON_OIDC_LINK_BY_EMAIL"),
        "the operator has to learn which setting to flip: {}",
        message
    );

    assert!(
        no_user_has_subject("subject-link-disabled"),
        "a refused link must not fall through to provisioning a second account"
    );
}

/// A provider that will not say the address is verified is a provider whose
/// users may have typed it themselves.
#[tokio::test]
async fn linking_is_refused_when_the_provider_does_not_vouch_for_the_email() {
    setup().await;

    let email = local_admin().email;
    for (tag, email_verified) in [
        ("subject-link-unverified", Some(false)),
        // The provider published no such claim at all, which is not a promise.
        ("subject-link-silent", None),
    ] {
        let identity = SsoIdentity {
            subject: tag.into(),
            email: Some(email.clone()),
            email_verified,
            ..Default::default()
        };

        let error = match resolve_or_provision(&identity, &config(true)) {
            Err(e) => e.to_string(),
            Ok((user, resolution)) => {
                panic!("email_verified={email_verified:?} was {resolution:?} as '{}'", user.username)
            }
        };
        assert!(
            error.contains("verified"),
            "the message should say what was missing: {}",
            error
        );
        assert!(
            no_user_has_subject(tag),
            "a refused link must not fall through to provisioning a second account"
        );
    }
}

/// Whether any account carries this SSO subject, i.e. whether a login created or
/// adopted one.
fn no_user_has_subject(subject: &str) -> bool {
    let subject = subject.to_owned();
    UserModel::list_all()
        .expect("listing users should succeed")
        .into_iter()
        .all(|u| u.sso_id.as_deref() != Some(subject.as_str()))
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
