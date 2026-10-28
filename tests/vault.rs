//! Vault KV v2 integration against a mock HTTP server: payload shape,
//! X-Vault-Token / X-Vault-Namespace headers, error reporting, refusal of a
//! plain-HTTP address that is not loopback, token and capability preflight.

use httpmock::prelude::*;
use httpmock::{Mock, MockServer};
use pgpp::vault::{build_payload, preflight, write_secret, VaultConfig, VaultTarget};
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

#[tokio::test]
async fn redirects_are_not_followed() {
    let server = MockServer::start_async().await;
    let elsewhere = MockServer::start_async().await;
    let redirect = server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/db/app");
            then.status(307).header(
                "Location",
                format!("{}/v1/secret/data/db/app", elsewhere.base_url()),
            );
        })
        .await;
    let sink = elsewhere
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/db/app");
            then.status(200);
        })
        .await;
    let cfg = VaultConfig::new(server.base_url(), "tok", None).unwrap();
    let target = VaultTarget::parse("secret/db/app", None).unwrap();
    let err = write_secret(&cfg, &target, &build_payload("app", "hidden-pw", "now"))
        .await
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("307"), "{text}");
    assert!(!text.contains("hidden-pw"), "payload must not leak: {text}");
    redirect.assert_async().await;
    assert_eq!(
        sink.hits_async().await,
        0,
        "the redirect target must never be contacted"
    );
}

fn target() -> VaultTarget {
    VaultTarget::parse("secret/db/app", None).unwrap()
}

fn cfg(server: &MockServer) -> VaultConfig {
    VaultConfig::new(server.base_url(), "good-token", Some("team-a".into())).unwrap()
}

fn asks_for_target_path(req: &HttpMockRequest) -> bool {
    let Some(body) = &req.body else { return false };
    serde_json::from_slice::<Value>(body).ok() == Some(json!({"paths": ["secret/data/db/app"]}))
}

/// Mocks lookup-self and capabilities-self with the given answers.
async fn preflight_mocks(
    server: &MockServer,
    lookup_status: u16,
    caps_status: u16,
    caps_body: Value,
) -> (Mock<'_>, Mock<'_>) {
    let lookup = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/v1/auth/token/lookup-self")
                .header("X-Vault-Token", "good-token")
                .header("X-Vault-Namespace", "team-a");
            let body = if lookup_status == 200 {
                json!({"data": {"ttl": 3600, "policies": ["default"]}})
            } else {
                json!({"errors": ["permission denied"]})
            };
            then.status(lookup_status).json_body(body);
        })
        .await;
    let caps = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v1/sys/capabilities-self")
                .header("X-Vault-Token", "good-token")
                .header("X-Vault-Namespace", "team-a")
                .matches(asks_for_target_path);
            then.status(caps_status).json_body(caps_body);
        })
        .await;
    (lookup, caps)
}

#[tokio::test]
async fn preflight_checks_the_token_and_the_write_capability() {
    for caps in [
        json!({"capabilities": ["create", "read", "update"], "secret/data/db/app": ["create", "read", "update"]}),
        json!({"data": {"secret/data/db/app": ["update", "create"]}}),
        json!({"capabilities": ["root"]}),
    ] {
        let server = MockServer::start_async().await;
        let (lookup, cap) = preflight_mocks(&server, 200, 200, caps.clone()).await;
        let warnings = preflight(&cfg(&server), &target()).await.unwrap();
        assert!(warnings.is_empty(), "{caps}: {warnings:?}");
        lookup.assert_async().await;
        cap.assert_async().await;
    }
}

#[tokio::test]
async fn preflight_refuses_a_token_that_cannot_write() {
    // `create` alone fails on the second rotation (the secret exists),
    // `update` alone on the first one; `sudo` grants no write by itself
    for caps in [
        json!({"capabilities": ["read", "list"]}),
        json!({"capabilities": ["deny"]}),
        json!({"capabilities": ["create", "read"]}),
        json!({"data": {"secret/data/db/app": ["update"]}}),
        json!({"capabilities": ["sudo"]}),
        json!({"capabilities": ["create", "sudo"]}),
    ] {
        let server = MockServer::start_async().await;
        preflight_mocks(&server, 200, 200, caps.clone()).await;
        let text = format!(
            "{:#}",
            preflight(&cfg(&server), &target()).await.unwrap_err()
        );
        assert!(
            text.contains("may not write") && text.contains("secret/data/db/app"),
            "{caps}: {text}"
        );
        assert!(
            text.contains("create and update required, or root"),
            "{caps}: {text}"
        );
        assert!(!text.contains("good-token"), "{text}");
    }
}

/// Vault answers 403 "permission denied" (never 401) for an expired,
/// revoked or unknown token: a 403 on lookup-self or on capabilities-self is
/// a refusal, before any rotation (fail-closed).  A token without the
/// default policy needs --vault-skip-preflight, which bypasses `preflight`.
#[tokio::test]
async fn preflight_refuses_a_403() {
    let server = MockServer::start_async().await;
    let (lookup, cap) =
        preflight_mocks(&server, 403, 200, json!({"capabilities": ["create"]})).await;
    let text = format!(
        "{:#}",
        preflight(&cfg(&server), &target()).await.unwrap_err()
    );
    assert!(
        text.contains("lookup-self") && text.contains("403") && text.contains("VAULT_TOKEN"),
        "{text}"
    );
    assert!(text.contains("--vault-skip-preflight"), "{text}");
    assert!(!text.contains("good-token"), "token must not leak: {text}");
    lookup.assert_async().await;
    assert_eq!(cap.hits_async().await, 0, "stops at lookup-self");

    // capabilities-self denied: refused as well
    let server = MockServer::start_async().await;
    let (_, cap) =
        preflight_mocks(&server, 200, 403, json!({"errors": ["permission denied"]})).await;
    let text = format!(
        "{:#}",
        preflight(&cfg(&server), &target()).await.unwrap_err()
    );
    assert!(
        text.contains("capabilities-self") && text.contains("403"),
        "{text}"
    );
    assert!(text.contains("permission denied"), "{text}");
    cap.assert_async().await;

    // unreadable answer: warning only (the token itself was accepted)
    let server = MockServer::start_async().await;
    preflight_mocks(&server, 200, 200, json!({"unexpected": true})).await;
    let warnings = preflight(&cfg(&server), &target()).await.unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("unexpected answer"), "{warnings:?}");
}

#[tokio::test]
async fn preflight_reports_a_refused_token() {
    for status in [401, 403, 500, 503] {
        let server = MockServer::start_async().await;
        let (lookup, cap) =
            preflight_mocks(&server, status, 200, json!({"capabilities": ["create"]})).await;
        let text = format!(
            "{:#}",
            preflight(&cfg(&server), &target()).await.unwrap_err()
        );
        assert!(
            text.contains(&status.to_string()) && text.contains("lookup-self"),
            "{text}"
        );
        if status < 500 {
            assert!(text.contains("refused VAULT_TOKEN"), "{text}");
        }
        assert!(text.contains("permission denied"), "{text}");
        assert!(!text.contains("good-token"), "token must not leak: {text}");
        lookup.assert_async().await;
        assert_eq!(cap.hits_async().await, 0, "stops at lookup-self");
    }
    // a server error on capabilities-self is an error too
    let server = MockServer::start_async().await;
    preflight_mocks(&server, 200, 500, json!({"errors": ["internal"]})).await;
    let text = format!(
        "{:#}",
        preflight(&cfg(&server), &target()).await.unwrap_err()
    );
    assert!(
        text.contains("500") && text.contains("capabilities-self"),
        "{text}"
    );
}

#[tokio::test]
async fn preflight_refuses_a_redirect_and_an_unreachable_host() {
    let server = MockServer::start_async().await;
    let elsewhere = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(307).header(
                "Location",
                format!("{}/v1/auth/token/lookup-self", elsewhere.base_url()),
            );
        })
        .await;
    let sink = elsewhere
        .mock_async(|when, then| {
            when.any_request();
            then.status(200);
        })
        .await;
    let cfg = VaultConfig::new(server.base_url(), "tok", None).unwrap();
    let text = format!("{:#}", preflight(&cfg, &target()).await.unwrap_err());
    assert!(text.contains("307") && text.contains("redirect"), "{text}");

    // redirect on capabilities-self
    let server2 = MockServer::start_async().await;
    server2
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(200);
        })
        .await;
    server2
        .mock_async(|when, then| {
            when.method(POST).path("/v1/sys/capabilities-self");
            then.status(308).header(
                "Location",
                format!("{}/v1/sys/capabilities-self", elsewhere.base_url()),
            );
        })
        .await;
    let cfg = VaultConfig::new(server2.base_url(), "tok", None).unwrap();
    let text = format!("{:#}", preflight(&cfg, &target()).await.unwrap_err());
    assert!(text.contains("308") && text.contains("redirect"), "{text}");
    assert_eq!(sink.hits_async().await, 0);

    let cfg = VaultConfig::new("http://127.0.0.1:9", "tok", None).unwrap();
    let text = format!("{:#}", preflight(&cfg, &target()).await.unwrap_err());
    assert!(
        text.contains("http://127.0.0.1:9/v1/auth/token/lookup-self"),
        "{text}"
    );
}

/// A path prefix of VAULT_ADDR (Vault behind a reverse proxy) is kept for
/// both endpoints.
#[tokio::test]
async fn path_prefix_of_vault_addr_is_kept() {
    let server = MockServer::start_async().await;
    let lookup = server
        .mock_async(|when, then| {
            when.method(GET).path("/vault/v1/auth/token/lookup-self");
            then.status(200);
        })
        .await;
    let caps = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/vault/v1/sys/capabilities-self")
                .matches(asks_for_target_path);
            then.status(200)
                .json_body(json!({"capabilities": ["create", "update"]}));
        })
        .await;
    let write = server
        .mock_async(|when, then| {
            when.method(POST).path("/vault/v1/secret/data/db/app");
            then.status(204);
        })
        .await;
    let cfg = VaultConfig::new(format!("{}/vault/", server.base_url()), "tok", None).unwrap();
    let target = target();
    assert!(preflight(&cfg, &target).await.unwrap().is_empty());
    write_secret(&cfg, &target, &build_payload("app", "x", "now"))
        .await
        .unwrap();
    lookup.assert_async().await;
    caps.assert_async().await;
    write.assert_async().await;
}

/// `http://localhost` is accepted once resolved to loopback addresses only;
/// the client then reaches the server through those pinned addresses.
#[tokio::test]
async fn http_localhost_reaches_the_pinned_loopback_address() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v1/kv/data/db/app")
                .header("content-type", "application/json")
                .json_body_partial(r#"{"data": {"username": "app", "password": "x"}}"#);
            then.status(204);
        })
        .await;
    let cfg = VaultConfig::new(format!("http://localhost:{}", server.port()), "tok", None).unwrap();
    let target = VaultTarget::parse("db/app", Some("kv")).unwrap();
    write_secret(&cfg, &target, &build_payload("app", "x", "now"))
        .await
        .unwrap();
    mock.assert_async().await;
}

/// Minimal keep-alive HTTP/1.1 server: answers `lookup-self` with a token
/// metadata body and `capabilities-self` with a write capability, and
/// counts the TCP connections it accepts.
async fn counting_vault() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    let accepted = std::sync::Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    // one request: headers, then Content-Length bytes
                    let head_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse().unwrap());
                    while buf.len() < head_end + len {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let body = if head.contains("lookup-self") {
                        // large enough not to be read along with the headers
                        json!({"data": {"ttl": 3600, "meta": "m".repeat(60_000)}})
                    } else {
                        json!({"capabilities": ["create", "update"]})
                    }
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    buf.drain(..head_end + len);
                }
            });
        }
    });
    (addr, accepted)
}

/// The body of `lookup-self` is read to its end (and discarded): the
/// connection is reused by `capabilities-self` instead of a new one.
#[tokio::test]
async fn preflight_reuses_the_connection() {
    let (addr, accepted) = counting_vault().await;
    let cfg = VaultConfig::new(addr, "good-token", None).unwrap();
    let target = VaultTarget::parse("secret/db/app", None).unwrap();
    let warnings = preflight(&cfg, &target).await.unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one connection for both preflight requests"
    );
}
