//! Vault KV v2 integration against a mock HTTP server: payload shape,
//! X-Vault-Token / X-Vault-Namespace headers, error reporting, refusal of a
//! plain-HTTP address that is not loopback, token and capability preflight.

use httpmock::prelude::*;
use httpmock::{Mock, MockServer};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use pgpp::vault::{
    build_payload, explain_refusal, preflight, send_write, VaultConfig, VaultTarget,
    METADATA_DISAPPEARED, REFUSED_SINCE_PREFLIGHT,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// [`send_write`] without tracking of the body (the flag is not read).
async fn write(cfg: &VaultConfig, target: &VaultTarget, payload: &Value) -> anyhow::Result<()> {
    send_write(cfg, target, payload, Arc::new(AtomicBool::new(false))).await
}

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
    write(&cfg, &target, &payload).await.unwrap();
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
    write(&cfg, &target, &build_payload("app", "x", "now"))
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
    let err = write(&cfg, &target, &build_payload("app", "hidden-pw", "now"))
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
    let err = write(&cfg, &target, &build_payload("app", "pw", "now"))
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
    let err = write(&cfg, &target, &build_payload("app", "hidden-pw", "now"))
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
        let pre = preflight(&cfg(&server), &target()).await.unwrap();
        assert!(pre.warnings.is_empty(), "{caps}: {pre:?}");
        assert!(!pre.update_only, "{caps}: {pre:?}");
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
    let warnings = preflight(&cfg(&server), &target()).await.unwrap().warnings;
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
    let mock = server
        .mock_async(|when, then| {
            when.method(POST).path("/vault/v1/secret/data/db/app");
            then.status(204);
        })
        .await;
    let cfg = VaultConfig::new(format!("{}/vault/", server.base_url()), "tok", None).unwrap();
    let target = target();
    assert!(preflight(&cfg, &target).await.unwrap().warnings.is_empty());
    write(&cfg, &target, &build_payload("app", "x", "now"))
        .await
        .unwrap();
    lookup.assert_async().await;
    caps.assert_async().await;
    mock.assert_async().await;
}

/// `http://localhost` is accepted without any resolution: the client
/// reaches the server on 127.0.0.1, the address the name is pinned to.
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
    write(&cfg, &target, &build_payload("app", "x", "now"))
        .await
        .unwrap();
    mock.assert_async().await;
}

/// `http://localhost` never reaches an agent that listens on `[::1]` alone:
/// the name is pinned to 127.0.0.1, so the write fails.
#[tokio::test]
async fn http_localhost_does_not_reach_an_ipv6_only_agent() {
    let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
        eprintln!("skipped: no IPv6 loopback in this environment");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    // the port is reserved on 127.0.0.1 by a socket bound without listen,
    // kept until the end: the connection is refused, with no race
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    if reserved.bind(([127, 0, 0, 1], port).into()).is_err() {
        eprintln!("skipped: port {port} is taken on 127.0.0.1");
        return;
    }
    // short timeout: a regression reaching [::1] (accepted by the kernel,
    // never answered) fails fast instead of waiting for REQUEST_TIMEOUT
    let cfg = VaultConfig::with_timeout(
        format!("http://localhost:{port}"),
        "tok",
        None,
        Duration::from_secs(2),
    )
    .unwrap();
    let err = write(&cfg, &target(), &build_payload("app", "x", "now"))
        .await
        .unwrap_err();
    assert!(
        err.chain()
            .filter_map(|e| e.downcast_ref::<std::io::Error>())
            .any(|e| e.kind() == std::io::ErrorKind::ConnectionRefused),
        "{err:#}"
    );
    drop((reserved, listener));
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
    let warnings = preflight(&cfg, &target).await.unwrap().warnings;
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one connection for both preflight requests"
    );
}

/// Mocks the KV v2 metadata endpoint of the target with the given status.
async fn metadata_mock(server: &MockServer, status: u16) -> Mock<'_> {
    server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/v1/secret/metadata/db/app")
                .header("X-Vault-Token", "good-token")
                .header("X-Vault-Namespace", "team-a");
            let body = if status == 200 {
                json!({"data": {"current_version": 4, "versions": {}}})
            } else {
                json!({"errors": []})
            };
            then.status(status).json_body(body);
        })
        .await
}

/// `update` without `create` is enough for a secret that already exists
/// (every write is then an update): the metadata read by the preflight
/// tells it.  A secret not written yet (404) needs `create`; metadata
/// that cannot be read leaves the question open and both are required.
#[tokio::test]
async fn preflight_accepts_update_alone_on_an_existing_secret() {
    for caps in [
        json!({"capabilities": ["update"]}),
        json!({"data": {"secret/data/db/app": ["read", "update"]}}),
    ] {
        let server = MockServer::start_async().await;
        preflight_mocks(&server, 200, 200, caps.clone()).await;
        let meta = metadata_mock(&server, 200).await;
        let pre = preflight(&cfg(&server), &target()).await.unwrap();
        assert!(pre.warnings.is_empty(), "{caps}: {pre:?}");
        assert!(pre.update_only, "{caps}: {pre:?}");
        meta.assert_async().await;
    }

    let refused = |status: u16| async move {
        let server = MockServer::start_async().await;
        preflight_mocks(&server, 200, 200, json!({"capabilities": ["update"]})).await;
        let meta = metadata_mock(&server, status).await;
        let text = format!(
            "{:#}",
            preflight(&cfg(&server), &target()).await.unwrap_err()
        );
        meta.assert_async().await;
        assert!(text.contains("may not write"), "{status}: {text}");
        assert!(text.contains("[update]"), "{status}: {text}");
        assert!(!text.contains("good-token"), "{text}");
        text
    };
    let text = refused(404).await;
    assert!(
        text.contains("does not exist yet") && text.contains("needs create"),
        "{text}"
    );
    for status in [403, 500] {
        let text = refused(status).await;
        assert!(
            text.contains("could not be checked") && text.contains(&status.to_string()),
            "{text}"
        );
        assert!(text.contains("create and update required"), "{text}");
    }
}

/// The metadata is only read for a token with `update` and no `create`:
/// `create` + `update` or `root` pass without it, `create` alone (or no
/// write capability) is refused without it.
#[tokio::test]
async fn preflight_reads_the_metadata_only_when_needed() {
    for (caps, ok) in [
        (json!({"capabilities": ["create", "update"]}), true),
        (json!({"capabilities": ["root"]}), true),
        (json!({"capabilities": ["create"]}), false),
        (json!({"capabilities": ["read"]}), false),
    ] {
        let server = MockServer::start_async().await;
        preflight_mocks(&server, 200, 200, caps.clone()).await;
        let meta = metadata_mock(&server, 200).await;
        assert_eq!(
            preflight(&cfg(&server), &target()).await.is_ok(),
            ok,
            "{caps}"
        );
        assert_eq!(meta.hits_async().await, 0, "{caps}");
    }
}

/// Environment variable that marks the child process of
/// [`a_loopback_address_bypasses_the_proxy_of_the_environment`].
const PROXY_CHILD: &str = "PGPP_TEST_PROXY_CHILD";

/// A loopback VAULT_ADDR never goes through the proxy of the environment:
/// the proxy would resolve `localhost` on its own side and see the token.
/// The proxy variables are set for a child process (this test binary,
/// running [`loopback_writes_with_a_proxy_in_the_environment`] alone), never
/// in this process: the other tests are left untouched.
#[tokio::test]
async fn a_loopback_address_bypasses_the_proxy_of_the_environment() {
    let proxy = MockServer::start_async().await;
    let relayed = proxy
        .mock_async(|when, then| {
            when.any_request();
            then.status(502);
        })
        .await;
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "loopback_writes_with_a_proxy_in_the_environment",
            "--include-ignored",
            "--test-threads=1",
        ])
        .env(PROXY_CHILD, "1")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for var in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
    ] {
        child.env(var, proxy.base_url());
    }
    let out = tokio::task::spawn_blocking(move || child.output())
        .await
        .unwrap()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("1 passed"),
        "the child test did not run: {stdout}"
    );
    assert_eq!(relayed.hits_async().await, 0, "the proxy must not be used");
}

/// Body of [`a_loopback_address_bypasses_the_proxy_of_the_environment`],
/// in the child process that has the proxy variables (does nothing
/// elsewhere).  `https://localhost` points at the plain HTTP mock: the TLS
/// handshake fails, directly (through the proxy, it would reach it).
#[tokio::test]
#[ignore = "run in a child process by a_loopback_address_bypasses_the_proxy_of_the_environment"]
async fn loopback_writes_with_a_proxy_in_the_environment() {
    if std::env::var_os(PROXY_CHILD).is_none() {
        return;
    }
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/db/app");
            then.status(204);
        })
        .await;
    for addr in [
        server.base_url(),
        format!("http://localhost:{}", server.port()),
    ] {
        let cfg = VaultConfig::new(&addr, "tok", None).unwrap();
        write(&cfg, &target(), &build_payload("app", "x", "now"))
            .await
            .unwrap_or_else(|e| panic!("{addr}: {e:#}"));
    }
    mock.assert_hits_async(2).await;
    let addr = format!("https://localhost:{}", server.port());
    let cfg = VaultConfig::new(&addr, "tok", None).unwrap();
    let err = write(&cfg, &target(), &build_payload("app", "x", "now"))
        .await
        .unwrap_err();
    assert!(!format!("{err:#}").contains("502"), "{addr}: {err:#}");
}

/// Mocks a write refused with 403 "permission denied".
async fn refused_write(server: &MockServer) -> Mock<'_> {
    server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/db/app");
            then.status(403)
                .json_body(json!({"errors": ["permission denied"]}));
        })
        .await
}

/// The secret found by the preflight of an `update`-only token may be
/// deleted before the write (check-then-act): the 403 of the write is then
/// confirmed by a new read of the metadata.  A 404 there says that the
/// secret disappeared; any other answer (the metadata still readable, or
/// refused too) is a permission withdrawn since the preflight (token
/// expired or revoked, policy changed), not a deletion.
#[tokio::test]
async fn a_write_refused_after_an_update_only_preflight_says_why() {
    // the path of a rotation (commands::vault_delivery): the write, then
    // the explanation of its refusal
    let rotate = |cfg: VaultConfig, update_only: bool| async move {
        let refused = write(&cfg, &target(), &build_payload("app", "x", "now"))
            .await
            .unwrap_err();
        let err = explain_refusal(
            &cfg,
            &target(),
            refused,
            update_only,
            pgpp::vault::REREAD_TIMEOUT,
            std::future::pending(),
        )
        .await;
        assert!(!pgpp::vault::may_have_been_received(&err), "{err:#}");
        format!("{err:#}")
    };

    // the secret was deleted after the preflight
    let server = MockServer::start_async().await;
    preflight_mocks(&server, 200, 200, json!({"capabilities": ["update"]})).await;
    let meta = metadata_mock(&server, 200).await;
    refused_write(&server).await;
    let checked = cfg(&server);
    let pre = preflight(&checked, &target()).await.unwrap();
    assert!(pre.update_only, "{pre:?}");
    meta.delete_async().await;
    let gone = metadata_mock(&server, 404).await;
    let m = rotate(checked.clone(), pre.update_only).await;
    gone.assert_async().await;
    assert!(m.contains("HTTP 403"), "{m}");
    assert!(m.contains(METADATA_DISAPPEARED), "{m}");
    assert!(!m.contains(REFUSED_SINCE_PREFLIGHT), "{m}");

    // the secret is still there (or its metadata now refused): the
    // permission changed, the message does not claim a deletion
    for status in [200, 403] {
        let server = MockServer::start_async().await;
        preflight_mocks(&server, 200, 200, json!({"capabilities": ["update"]})).await;
        refused_write(&server).await;
        let meta = metadata_mock(&server, status).await;
        let m = rotate(cfg(&server), true).await;
        meta.assert_async().await;
        assert!(m.contains("HTTP 403"), "{status}: {m}");
        assert!(m.contains(REFUSED_SINCE_PREFLIGHT), "{status}: {m}");
        // the status quoted is the one of the new read, not of the write
        let reread = format!(
            "{REFUSED_SINCE_PREFLIGHT} ({}/v1/secret/metadata/db/app answered HTTP {})",
            server.base_url(),
            StatusCode::from_u16(status).unwrap()
        );
        assert!(m.ends_with(&reread), "{status}: {m}");
        assert!(!m.contains(METADATA_DISAPPEARED), "{status}: {m}");
        assert!(!m.contains("good-token"), "{m}");
    }

    // without that preflight result, a 403 is reported as it is and the
    // metadata is not read
    let server = MockServer::start_async().await;
    refused_write(&server).await;
    let meta = metadata_mock(&server, 404).await;
    let m = rotate(cfg(&server), false).await;
    assert_eq!(meta.hits_async().await, 0);
    assert!(m.contains("HTTP 403"), "{m}");
    assert!(!m.contains(METADATA_DISAPPEARED), "{m}");
    assert!(!m.contains(REFUSED_SINCE_PREFLIGHT), "{m}");
    let err = write(&cfg(&server), &target(), &build_payload("app", "x", "now"))
        .await
        .unwrap_err();
    assert!(
        !format!("{err:#}").contains(METADATA_DISAPPEARED),
        "{err:#}"
    );
}

/// The 403 of the write is a refusal as soon as Vault answers it: a new
/// read of the metadata that does not end (slow Vault) is abandoned at the
/// timeout, or at once on Ctrl-C (`cancel`), and the result is the
/// cautious refusal, which says which of the two ended the read, never a
/// write that may have happened.
#[tokio::test]
async fn a_slow_reread_after_a_refused_write_stays_a_refusal() {
    let server = MockServer::start_async().await;
    refused_write(&server).await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/v1/secret/metadata/db/app");
            then.status(404).delay(Duration::from_secs(20));
        })
        .await;
    let refused = || async {
        let e = write(&cfg(&server), &target(), &build_payload("app", "x", "now"))
            .await
            .unwrap_err();
        assert!(format!("{e:#}").contains("HTTP 403"), "{e:#}");
        e
    };
    let expected =
        |e: &anyhow::Error, why: &str| format!("{e:#}: {REFUSED_SINCE_PREFLIGHT} ({why})");

    // timeout of the new read
    let e = refused().await;
    let want = expected(&e, "no answer within 300ms");
    let started = Instant::now();
    let err = explain_refusal(
        &cfg(&server),
        &target(),
        e,
        true,
        Duration::from_millis(300),
        std::future::pending(),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(5), "{err:#}");
    assert_eq!(format!("{err:#}"), want);
    assert!(!pgpp::vault::may_have_been_received(&err), "{err:#}");

    // Ctrl-C during the new read
    let e = refused().await;
    let want = expected(&e, "interrupted");
    let started = Instant::now();
    let err = explain_refusal(
        &cfg(&server),
        &target(),
        e,
        true,
        Duration::from_secs(60),
        tokio::time::sleep(Duration::from_millis(300)),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(5), "{err:#}");
    assert_eq!(format!("{err:#}"), want);
    assert!(
        !format!("{err:#}").contains(METADATA_DISAPPEARED),
        "{err:#}"
    );
    assert!(!pgpp::vault::may_have_been_received(&err), "{err:#}");

    // a Ctrl-C already received: no new read at all
    let server = MockServer::start_async().await;
    refused_write(&server).await;
    let meta = metadata_mock(&server, 404).await;
    let e = write(&cfg(&server), &target(), &build_payload("app", "x", "now"))
        .await
        .unwrap_err();
    let want = expected(&e, "interrupted before the check");
    let err = explain_refusal(
        &cfg(&server),
        &target(),
        e,
        true,
        Duration::from_secs(60),
        std::future::ready(()),
    )
    .await;
    assert_eq!(format!("{err:#}"), want);
    assert_eq!(meta.hits_async().await, 0);
}
