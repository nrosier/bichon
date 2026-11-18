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
        allowed_email_domains: vec![],
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

// ── SSO admin API, status, features and code-only callbacks ─────────────────
//
// These go through the real routes. The SSO settings are one process-wide
// document in the shared test database, so every test that reads or writes them
// holds `sso_lock()` and starts from `reset_sso()`. None of them makes an
// outbound request: building an active config does no I/O, and every branch
// asserted below returns before the provider would be contacted.

use poem::http::StatusCode;
use poem::test::{TestClient, TestResponse};
use poem::Endpoint;
use serde_json::{json, Value};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};

use crate::rest::oidc::attach;
use crate::rest::public::features::get_features;
use crate::tests::admin_token;

/// A value that appears nowhere else, so finding it in a body means a leak.
const SECRET: &str = "s3cr3t-test-value";

static SSO_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

async fn sso_lock() -> MutexGuard<'static, ()> {
    SSO_LOCK.lock().await
}

/// The routes under test. `attach` puts `ApiGuard` on the admin routes itself,
/// exactly as in production; the public ones stay open.
fn sso_route() -> impl Endpoint {
    attach(poem::Route::new().nest("/api/v1/features", poem::get(get_features)))
}

fn client() -> TestClient<impl Endpoint> {
    TestClient::new(sso_route()).default_header("X-Forwarded-For", "127.0.0.1")
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn body_text(resp: TestResponse) -> (StatusCode, String) {
    let status = resp.0.status();
    let text = resp
        .0
        .into_body()
        .into_string()
        .await
        .expect("the body should be text");
    (status, text)
}

async fn put_sso(cli: &TestClient<impl Endpoint>, token: &str, body: Value) -> (StatusCode, String) {
    body_text(
        cli.put("/api/v1/sso")
            .header("Authorization", bearer(token))
            .body_json(&body)
            .send()
            .await,
    )
    .await
}

async fn get_sso(cli: &TestClient<impl Endpoint>, token: &str) -> (StatusCode, String) {
    body_text(
        cli.get("/api/v1/sso")
            .header("Authorization", bearer(token))
            .send()
            .await,
    )
    .await
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

/// Back to "SSO off, nothing configured, no secret".
async fn reset_sso(cli: &TestClient<impl Endpoint>, token: &str) {
    let (status, text) = put_sso(
        cli,
        token,
        json!({
            "enabled": false,
            "issuer_url": null,
            "client_id": null,
            "redirect_uri": null,
            "client_secret": "",
            "allowed_email_domains": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reset failed: {text}");
}

/// A config that `OidcConfig::load()` accepts, with no I/O to get there.
fn active_body() -> Value {
    json!({
        "enabled": true,
        "issuer_url": "https://idp.example.com",
        "client_id": "bichon",
        "redirect_uri": "https://mail.example.com/api/auth/oidc/callback",
    })
}

fn location(resp: &TestResponse) -> String {
    resp.0
        .headers()
        .get("location")
        .expect("a redirect carries a Location")
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn sso_config_round_trip_reports_the_secret_as_set_without_returning_it() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;

    let mut body = active_body();
    body["client_secret"] = json!(SECRET);
    body["allowed_email_domains"] = json!(["example.com"]);
    let (status, put_text) = put_sso(&cli, &token, body).await;
    assert_eq!(status, StatusCode::OK, "{put_text}");
    assert!(!put_text.contains(SECRET), "PUT response leaked the secret");

    let (status, get_text) = get_sso(&cli, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!get_text.contains(SECRET), "GET response leaked the secret");
    let view = json_of(&get_text);
    assert_eq!(view["client_secret_set"], json!(true));
    assert_eq!(view["issuer_url"], json!("https://idp.example.com"));
    assert_eq!(view["enabled"], json!(true));
    assert_eq!(view["allowed_email_domains"], json!(["example.com"]));

    reset_sso(&cli, &token).await;
}

#[tokio::test]
async fn sso_client_secret_is_kept_masked_cleared_or_replaced_as_asked() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;

    let (status, text) = put_sso(&cli, &token, json!({ "client_secret": SECRET })).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(json_of(&text)["client_secret_set"], json!(true));

    // (what is sent, whether a secret is stored afterwards)
    let steps: [(Value, bool, &str); 4] = [
        (json!({ "client_id": "bichon" }), true, "absent keeps"),
        (json!({ "client_secret": "********" }), true, "the mask keeps"),
        (json!({ "client_secret": "" }), false, "empty clears"),
        (json!({ "client_secret": "new" }), true, "a value sets"),
    ];
    for (body, expect_set, why) in steps {
        let (status, text) = put_sso(&cli, &token, body).await;
        assert_eq!(status, StatusCode::OK, "{why}: {text}");
        assert!(!text.contains(SECRET), "{why}: PUT leaked the secret");
        assert!(!text.contains("\"new\""), "{why}: PUT leaked the new secret");
        assert_eq!(json_of(&text)["client_secret_set"], json!(expect_set), "{why} (PUT)");

        let (status, text) = get_sso(&cli, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!text.contains(SECRET), "{why}: GET leaked the secret");
        assert_eq!(json_of(&text)["client_secret_set"], json!(expect_set), "{why} (GET)");
    }

    reset_sso(&cli, &token).await;
}

#[tokio::test]
async fn sso_admin_routes_reject_a_missing_token_with_401() {
    setup().await;
    let cli = client();

    let resp = cli.get("/api/v1/sso").send().await;
    assert_eq!(resp.0.status(), StatusCode::UNAUTHORIZED, "GET /sso");

    let resp = cli.put("/api/v1/sso").body_json(&json!({})).send().await;
    assert_eq!(resp.0.status(), StatusCode::UNAUTHORIZED, "PUT /sso");

    let resp = cli
        .post("/api/v1/sso/test")
        .body_json(&json!({ "issuer_url": "not a url" }))
        .send()
        .await;
    assert_eq!(resp.0.status(), StatusCode::UNAUTHORIZED, "POST /sso/test");
}

#[tokio::test]
async fn sso_admin_routes_reject_a_user_without_user_manage_or_root_with_403() {
    setup().await;
    let _guard = sso_lock().await;
    let admin = admin_token().await;
    let cli = client();

    // A regular member: the default role carries `system:access` only.
    let username = "sso-plain-member";
    let password = "member-pass-123";
    let api = crate::tests::build_api_route();
    let api = TestClient::new(api).default_header("X-Forwarded-For", "127.0.0.1");
    let resp = api
        .post("/api/v1/users")
        .header("Authorization", bearer(&admin))
        .body_json(&json!({
            "username": username,
            "email": "sso-plain-member@example.com",
            "password": password,
            "global_roles": [DEFAULT_MEMBER_ROLE_ID],
            "account_access_map": {},
        }))
        .send()
        .await;
    resp.assert_status_is_ok();

    let login = TestClient::new(
        poem::Route::new().at("/api/login", poem::post(crate::rest::public::login::login)),
    );
    let resp = login
        .post("/api/login")
        .body_json(&json!({ "username": username, "password": password }))
        .send()
        .await;
    resp.assert_status_is_ok();
    let login_body: Value = resp.json().await.value().deserialize();
    let member = login_body["access_token"]
        .as_str()
        .expect("the member should be able to log in")
        .to_owned();

    let (status, text) = get_sso(&cli, &member).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "GET: {text}");

    let (status, text) = put_sso(&cli, &member, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "PUT: {text}");
}

#[tokio::test]
async fn sso_update_names_the_field_it_rejects_with_400() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;

    let (status, text) = put_sso(&cli, &token, json!({ "enabled": true })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    let field = json_of(&text)["field"].as_str().unwrap_or_default().to_owned();
    assert!(
        field == "issuer_url" || field == "enabled",
        "expected issuer_url or enabled, got {field:?}: {text}"
    );

    let (status, text) = put_sso(
        &cli,
        &token,
        json!({ "allowed_email_domains": ["-x.com"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert_eq!(json_of(&text)["field"], json!("allowed_email_domains"), "{text}");

    // A rejected update must leave nothing half-applied.
    let (_, text) = get_sso(&cli, &token).await;
    let view = json_of(&text);
    assert_eq!(view["enabled"], json!(false));
    assert_eq!(view["allowed_email_domains"], json!([]));

    reset_sso(&cli, &token).await;
}

#[tokio::test]
async fn sso_test_endpoint_rejects_an_unparseable_issuer_without_contacting_anything() {
    setup().await;
    let token = admin_token().await;
    let cli = client();

    let (status, text) = body_text(
        cli.post("/api/v1/sso/test")
            .header("Authorization", bearer(&token))
            .body_json(&json!({ "issuer_url": "not a url" }))
            .send()
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let result = json_of(&text);
    assert_eq!(result["ok"], json!(false), "{text}");
    assert_eq!(result["kind"], json!("invalid_issuer"), "{text}");
}

#[tokio::test]
async fn oidc_status_with_sso_off_is_unavailable_and_needs_no_token() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;

    let (status, text) = body_text(cli.get("/api/auth/oidc/status").send().await).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let st = json_of(&text);
    assert_eq!(st["available"], json!(false), "{text}");
    assert_eq!(st["configured"], json!(false), "{text}");
    assert!(st.get("code").is_some_and(Value::is_null), "code must be null: {text}");
    assert!(st["checked_at"].is_i64(), "checked_at must be a number: {text}");
}

#[tokio::test]
async fn features_reports_community_edition_and_sso_support() {
    setup().await;
    let _guard = sso_lock().await;
    let cli = client();

    let (status, text) = body_text(cli.get("/api/v1/features").send().await).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let f = json_of(&text);
    assert!(f["sso_enabled"].is_boolean(), "{text}");
    assert_eq!(f["sso_supported"], json!(true), "{text}");
    assert_eq!(f["edition"], json!("community"), "{text}");
    assert!(f["features"].is_array(), "{text}");
    assert!(f["version"].is_string(), "{text}");
}

#[tokio::test]
async fn logout_with_sso_off_is_a_plain_local_sign_out_with_no_error() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;

    let resp = cli.get("/api/auth/oidc/logout").send().await;
    assert_eq!(resp.0.status(), StatusCode::TEMPORARY_REDIRECT);
    let loc = location(&resp);
    assert_eq!(loc, "/sign-in?local=1");
    assert!(!loc.contains("oidc_error"), "{loc}");
}

#[tokio::test]
async fn callback_with_sso_off_redirects_with_a_bare_code() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;

    let resp = cli
        .get("/api/auth/oidc/callback?error=access_denied&error_description=Please%20phish&state=x")
        .send()
        .await;
    assert_eq!(resp.0.status(), StatusCode::TEMPORARY_REDIRECT);
    let loc = location(&resp);
    assert_eq!(loc, "/sign-in?oidc_error=sso_unavailable");
    assert!(!loc.contains("oidc_error_code"), "{loc}");
    assert!(!loc.contains(' ') && !loc.contains("%20") && !loc.contains("phish"), "{loc}");
}

#[tokio::test]
async fn callback_reports_a_declined_sign_in_by_code_only() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;
    let (status, text) = put_sso(&cli, &token, active_body()).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    let resp = cli
        .get("/api/auth/oidc/callback?error=access_denied&error_description=Please%20phish&state=x")
        .send()
        .await;
    assert_eq!(resp.0.status(), StatusCode::TEMPORARY_REDIRECT);
    let loc = location(&resp);
    assert_eq!(loc, "/sign-in?oidc_error=sso_declined");
    assert!(!loc.contains("phish") && !loc.contains("access_denied"), "{loc}");

    reset_sso(&cli, &token).await;
}

#[tokio::test]
async fn callback_without_code_or_state_reports_an_incomplete_callback() {
    setup().await;
    let _guard = sso_lock().await;
    let token = admin_token().await;
    let cli = client();
    reset_sso(&cli, &token).await;
    let (status, text) = put_sso(&cli, &token, active_body()).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    for path in [
        "/api/auth/oidc/callback",
        "/api/auth/oidc/callback?code=abc",
        "/api/auth/oidc/callback?state=xyz",
    ] {
        let resp = cli.get(path).send().await;
        assert_eq!(resp.0.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        assert_eq!(location(&resp), "/sign-in?oidc_error=sso_incomplete", "{path}");
    }

    reset_sso(&cli, &token).await;
}
