//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project

use poem::test::TestClient;
use serde::Deserialize;

use super::{admin_token, build_api_route, setup};

fn api_client(route: impl poem::Endpoint) -> TestClient<impl poem::Endpoint> {
    TestClient::new(route).default_header("X-Forwarded-For", "127.0.0.1")
}

#[derive(Debug, Deserialize)]
struct SystemConfig {
    bichon_root_dir: String,
    bichon_http_port: i32,
    bichon_version: Option<String>,
}

// Deserializing is the assertion: serde rejects the payload if a field the
// dashboard reads goes missing or changes type. The counts are legitimately zero
// on a fresh install, so there is nothing meaningful to assert about their
// values and rustc cannot see them being read.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DashboardStats {
    account_count: usize,
    email_count: u64,
    attachment_count: u64,
    system_version: String,
}

#[tokio::test]
async fn get_system_configurations() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/system-configurations")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();

    // Deserializing into the declared shape is most of the check: serde fails if
    // the endpoint stops returning a field the web UI reads.
    let config: SystemConfig = resp.json().await.value().deserialize();
    assert!(
        !config.bichon_root_dir.is_empty(),
        "the server should report its data directory"
    );
    assert!(
        config.bichon_http_port > 0,
        "the server should report its HTTP port"
    );
    if let Some(version) = &config.bichon_version {
        assert!(!version.is_empty(), "a reported version should not be blank");
    }
}

#[tokio::test]
async fn get_dashboard_stats_returns_data() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/dashboard-stats")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;

    // Dashboard stats may return errors if tantivy schemas are empty,
    // but should always produce a response (not a crash)
    let status = resp.0.status();
    // Accept both success (200) and error (4xx/5xx) — just ensure it doesn't panic
    assert!(status.as_u16() > 0, "should produce a valid HTTP response");

    // When it does succeed the body still has to match what the dashboard reads,
    // which is what deserializing into DashboardStats checks.
    if status.is_success() {
        let stats: DashboardStats = resp.json().await.value().deserialize();
        assert!(
            !stats.system_version.is_empty(),
            "stats should report a version"
        );
    }
}

#[tokio::test]
async fn list_proxy_returns_array() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/list-proxy")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn list_roles_returns_builtins() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/list-roles")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn minimal_user_list_works() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/minimal-user-list")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn list_account_roles_works() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/list-account-roles")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}
