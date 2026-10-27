//! Vault KV v2 integration against a mock HTTP server: payload shape,
//! X-Vault-Token / X-Vault-Namespace headers, error reporting, refusal of a
//! plain-HTTP address that is not loopback.

use httpmock::prelude::*;
use httpmock::MockServer;
use pgpp::vault::{build_payload, write_secret, VaultConfig, VaultTarget};
use serde_json::{json, Value};

fn no_namespace_header(req: &HttpMockRequest) -> bool {
    match &req.headers {
        None => true,
        Some(h) => !h
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-vault-namespace")),
    }
}

fn body_is_expected_payload(req: &HttpMockRequest) -> bool {
    let Some(body) = &req.body else { return false };
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    v == json!({"data": {"username": "app", "password": "s3cret-Value!", "rotated_at": "2026-10-27T10:00:00Z"}})
}

#[tokio::test]
async fn writes_kv_v2_payload_with_token_header() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v1/secret/data/db/app")
                .header("X-Vault-Token", "t-test-token")
                .header("X-Vault-Namespace", "team-a")
                .header("content-type", "application/json")
                .matches(body_is_expected_payload);
            then.status(200)
                .json_body(json!({"data": {"version": 3, "created_time": "2026-10-27T10:00:00Z"}}));
        })
        .await;

    let cfg = VaultConfig::new(
        format!("{}/", server.base_url()),
        "t-test-token",
        Some("team-a".into()),
    )
    .unwrap();
    let target = VaultTarget::parse("secret/db/app", None).unwrap();
    let payload = build_payload("app", "s3cret-Value!", "2026-10-27T10:00:00Z");
    write_secret(&cfg, &target, &payload).await.unwrap();
    mock.assert_async().await;
}

#[tokio::test]
async fn explicit_mount_without_namespace() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v1/kv/data/db/app")
                .header("X-Vault-Token", "tok")
                .matches(no_namespace_header)
                .json_body_partial(r#"{"data": {"username": "app"}}"#);
            then.status(204);
        })
        .await;
    let cfg = VaultConfig::new(server.base_url(), "tok", None).unwrap();
    let target = VaultTarget::parse("db/app", Some("kv")).unwrap();
    write_secret(&cfg, &target, &build_payload("app", "x", "now"))
        .await
        .unwrap();
    mock.assert_async().await;
}

#[tokio::test]
async fn http_error_is_reported_without_payload() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/db/app");
            then.status(403)
                .json_body(json!({"errors": ["permission denied"]}));
        })
        .await;
    let cfg = VaultConfig::new(server.base_url(), "bad", None).unwrap();
    let target = VaultTarget::parse("secret/db/app", None).unwrap();
    let err = write_secret(&cfg, &target, &build_payload("app", "hidden-pw", "now"))
        .await
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("403"), "{text}");
    assert!(text.contains("permission denied"), "{text}");
    assert!(!text.contains("hidden-pw"), "payload must not leak: {text}");
    mock.assert_async().await;
}

#[tokio::test]
async fn connection_error_is_clear() {
    let cfg = VaultConfig::new("http://127.0.0.1:9", "tok", None).unwrap();
    let target = VaultTarget::parse("secret/app", None).unwrap();
    let err = write_secret(&cfg, &target, &build_payload("app", "pw", "now"))
        .await
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("http://127.0.0.1:9/v1/secret/data/app"),
        "{text}"
    );
}

/// The mock server listens on loopback, so its http:// address is accepted;
/// the same server reached through a non-loopback name is refused before any
/// request is sent.
#[tokio::test]
async fn plain_http_is_refused_unless_loopback() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/app");
            then.status(204);
        })
        .await;
    assert!(VaultConfig::new(server.base_url(), "tok", None).is_ok());
    let remote = format!("http://vault.example.invalid:{}", server.port());
    let err = VaultConfig::new(&remote, "tok", None).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("loopback"), "{text}");
    assert!(text.contains("https://"), "{text}");
    assert_eq!(mock.hits_async().await, 0, "nothing must be sent");
}
