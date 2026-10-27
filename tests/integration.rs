//! End-to-end tests of the `pgpp` binary against a real database where
//! pg_pass_policy is installed.  The database tests are `#[ignore]`d: run
//! them with `cargo test --test integration -- --include-ignored` once
//! `PGPP_TEST_URL` (connection URL of a member of pass_policy_admin with
//! CREATEROLE; the password may come from PGPASSFILE) is set.  Without the
//! variable they panic instead of passing silently.

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::str::FromStr;

use httpmock::prelude::*;
use httpmock::MockServer;
use serde_json::Value;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgConnection};

fn test_url() -> Option<String> {
    std::env::var("PGPP_TEST_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

macro_rules! db_url {
    () => {
        test_url().expect("PGPP_TEST_URL must be set to run the database integration tests")
    };
}

fn pgpp(url: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_pgpp"));
    c.env("DATABASE_URL", url)
        .env_remove("VAULT_ADDR")
        .env_remove("VAULT_TOKEN")
        .env_remove("VAULT_NAMESPACE")
        .env_remove("PGPP_VAULT_SKIP_PREFLIGHT");
    c
}

fn run(url: &str, args: &[&str]) -> Output {
    pgpp(url).args(args).output().expect("cannot run pgpp")
}

fn run_ok(url: &str, args: &[&str]) -> String {
    let out = run(url, args);
    assert!(
        out.status.success(),
        "pgpp {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn run_json(url: &str, args: &[&str]) -> Value {
    let mut full = vec!["-f", "json"];
    full.extend_from_slice(args);
    let out = run_ok(url, &full);
    serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("invalid JSON from pgpp {args:?}: {e}: {out}"))
}

async fn admin() -> PgConnection {
    let url = test_url().unwrap();
    PgConnection::connect(&url)
        .await
        .expect("cannot connect with PGPP_TEST_URL")
}

/// Runs a statement, ignoring its error (idempotent fixtures).
async fn exec_lenient(conn: &mut PgConnection, sql: &str) {
    let _ = conn.execute(sql).await;
}

/// (Re)creates an empty login role; names are test constants, not user input.
async fn fresh_login_role(conn: &mut PgConnection, name: &str) {
    exec_lenient(conn, &format!("DROP ROLE IF EXISTS {name}")).await;
    conn.execute(format!("CREATE ROLE {name} LOGIN").as_str())
        .await
        .unwrap_or_else(|e| panic!("cannot create role {name}: {e}"));
}

/// Checks that `role` can authenticate with `password` (SCRAM over TCP).
async fn can_login(role: &str, password: &str) -> bool {
    let opts = PgConnectOptions::from_str(&test_url().unwrap())
        .unwrap()
        .username(role)
        .password(password);
    match PgConnection::connect_with(&opts).await {
        Ok(c) => {
            let _ = c.close().await;
            true
        }
        Err(e) => {
            eprintln!("login as {role} failed: {e}");
            false
        }
    }
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn status_lists_login_roles() {
    let url = db_url!();
    let all = run_json(&url, &["status"]);
    let rows = all.as_array().expect("array");
    assert!(rows
        .iter()
        .any(|r| r["status"].is_string() && r["profile"].is_string()));
    let table = run_ok(&url, &["status"]);
    assert!(table.contains("role_name") && table.contains("status"));

    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_status").await;
    let one = run_json(&url, &["status", "--role", "pgpp_t_status"]);
    assert_eq!(one.as_array().unwrap().len(), 1);
    assert_eq!(one[0]["role_name"], "pgpp_t_status");
    assert_eq!(one[0]["status"], "unknown");

    let missing = run(&url, &["status", "--role", "pgpp_t_does_not_exist"]);
    assert_eq!(missing.status.code(), Some(1));
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn rotate_show_returns_a_working_password() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_rot").await;

    let out = run_json(&url, &["rotate", "pgpp_t_rot", "--length", "30", "--show"]);
    assert_eq!(out["role"], "pgpp_t_rot");
    let pw = out["password"].as_str().expect("password shown");
    assert_eq!(pw.chars().count(), 30);
    assert!(out["valid_until"].is_string(), "{out}");
    assert_eq!(out["valid_until_known"], true, "{out}");
    assert!(can_login("pgpp_t_rot", pw).await, "new password must work");

    // without --show the password is not printed
    let hidden = run_ok(&url, &["rotate", "pgpp_t_rot", "--exec", "cat >/dev/null"]);
    assert!(hidden.contains("delivered_to: exec"), "{hidden}");
    assert!(hidden.contains("not shown"), "{hidden}");
    assert!(!hidden.contains(pw));

    // status now knows the change date
    let st = run_json(&url, &["status", "--role", "pgpp_t_rot"]);
    assert_eq!(st[0]["status"], "ok");
}

/// Asserts that a refused rotation did not happen: exit `code` (2 for a
/// local validation error, 1 for a failed Vault preflight request), nothing
/// that looks like a password on stdout, no `password_rotated` event for the
/// role.
fn assert_refused_before_rotation_with(url: &str, role: &str, out: Output, code: i32) {
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(!stdout.contains("password"), "{stdout}");
    assert!(stdout.trim().is_empty(), "{stdout}");
    let audit = run_json(
        url,
        &["audit", "--role", role, "--type", "password_rotated"],
    );
    assert_eq!(audit, serde_json::json!([]), "no rotation for {role}");
}

/// [`assert_refused_before_rotation_with`] for a usage error (exit 2).
fn assert_refused_before_rotation(url: &str, role: &str, out: Output) {
    assert_refused_before_rotation_with(url, role, out, 2);
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn rotation_is_refused_before_anything_is_rotated() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_rot2").await;

    // no delivery option at all
    let out = run(&url, &["-f", "json", "rotate", "pgpp_t_rot2"]);
    assert_refused_before_rotation(&url, "pgpp_t_rot2", out);
    let out = run(&url, &["switch-pair", "pgpp_t_pair"]);
    assert_eq!(out.status.code(), Some(2));

    // Vault requested but not configured / badly configured
    let out = run(&url, &["rotate", "pgpp_t_rot2", "--vault-kv", "secret/app"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("VAULT_ADDR"));
    assert_refused_before_rotation(&url, "pgpp_t_rot2", out);
    let out = pgpp(&url)
        .args(["rotate", "pgpp_t_rot2", "--vault-kv", "secret"])
        .env("VAULT_ADDR", "https://127.0.0.1:9")
        .env("VAULT_TOKEN", "t")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("expected <mount>/<path>"));
    assert_refused_before_rotation(&url, "pgpp_t_rot2", out);
    let out = pgpp(&url)
        .args(["rotate", "pgpp_t_rot2", "--vault-kv", "secret/db/app#prod"])
        .env("VAULT_ADDR", "https://127.0.0.1:9")
        .env("VAULT_TOKEN", "t")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid path segment"));
    assert_refused_before_rotation(&url, "pgpp_t_rot2", out);
    let out = pgpp(&url)
        .args(["rotate", "pgpp_t_rot2", "--vault-kv", ""])
        .env("VAULT_ADDR", "https://127.0.0.1:9")
        .env("VAULT_TOKEN", "t")
        .output()
        .unwrap();
    assert_refused_before_rotation(&url, "pgpp_t_rot2", out);
    let out = pgpp(&url)
        .args(["rotate", "pgpp_t_rot2", "--vault-kv", "secret/app"])
        .env("VAULT_ADDR", "http://vault.example.invalid:8200")
        .env("VAULT_TOKEN", "t")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("loopback"));
    assert_refused_before_rotation(&url, "pgpp_t_rot2", out);
    let out = pgpp(&url)
        .args(["rotate", "pgpp_t_rot2", "--vault-kv", "secret/app"])
        .env("VAULT_ADDR", "https://127.0.0.1:9")
        .env("VAULT_TOKEN", "t")
        .env("VAULT_CACERT", "/nonexistent/ca.pem")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("VAULT_CACERT"));
    assert_refused_before_rotation(&url, "pgpp_t_rot2", out);

    // the role is still usable: a valid request rotates it
    let st = run_json(&url, &["status", "--role", "pgpp_t_rot2"]);
    assert_eq!(st[0]["status"], "unknown");
    run_ok(&url, &["rotate", "pgpp_t_rot2", "--exec", "cat >/dev/null"]);
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn exec_receives_password_on_stdin_and_env() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_exec").await;
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(dir).unwrap();
    let pw_file = dir.join(format!("pgpp_exec_{}.pw", std::process::id()));
    let env_file = dir.join(format!("pgpp_exec_{}.env", std::process::id()));
    let cmd = format!(
        "umask 077; cat > '{}'; printf '%s|%s\\n' \"$PGPP_ROLE\" \"$PGPP_VALID_UNTIL\" > '{}'",
        pw_file.display(),
        env_file.display()
    );
    let out = run_json(&url, &["rotate", "pgpp_t_exec", "--exec", &cmd]);
    assert_eq!(out["delivered_to"], serde_json::json!(["exec"]));
    assert!(
        out.get("password").is_none(),
        "password must not be printed: {out}"
    );

    let pw = std::fs::read_to_string(&pw_file).unwrap();
    let pw = pw.trim_end_matches('\n');
    assert!(pw.len() >= 12);
    let env = std::fs::read_to_string(&env_file).unwrap();
    let (role, valid_until) = env.trim().split_once('|').unwrap();
    assert_eq!(role, "pgpp_t_exec");
    assert_eq!(Some(valid_until), out["valid_until"].as_str());
    assert!(can_login("pgpp_t_exec", pw).await);
    let _ = std::fs::remove_file(&pw_file);
    let _ = std::fs::remove_file(&env_file);

    // a failing command is reported and the password is not printed
    let failed = run(
        &url,
        &["rotate", "pgpp_t_exec", "--exec", "cat >/dev/null; exit 3"],
    );
    assert_eq!(failed.status.code(), Some(1));
    let stderr = String::from_utf8(failed.stderr).unwrap();
    assert!(stderr.contains("exit status: 3"), "{stderr}");

    // a command that never reads its stdin loses the password: failed delivery
    for cmd in ["true", "exec 0<&-; sleep 0.2"] {
        let out = run(
            &url,
            &["-f", "json", "rotate", "pgpp_t_exec", "--exec", cmd],
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(1), "{cmd}: {stdout} {stderr}");
        assert!(
            stderr.contains("without reading the password"),
            "{cmd}: {stderr}"
        );
        let v: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(v["delivered_to"], serde_json::json!([]), "{cmd}: {stdout}");
    }

    // the standard output of the hook goes to stderr: the JSON stays clean
    let out = run(
        &url,
        &[
            "-f",
            "json",
            "rotate",
            "pgpp_t_exec",
            "--exec",
            "cat >/dev/null; echo hook-stdout-line; echo hook-stderr-line >&2",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be the JSON alone: {e}: {stdout}"));
    assert_eq!(v["delivered_to"], serde_json::json!(["exec"]));
    assert!(!stdout.contains("hook-"), "{stdout}");
    assert!(stderr.contains("hook-stdout-line"), "{stderr}");
    assert!(stderr.contains("hook-stderr-line"), "{stderr}");
}

/// Waits (up to 10 s) for `path` to hold a complete line, returned trimmed.
fn wait_for_line(path: &std::path::Path) -> String {
    for _ in 0..200 {
        if let Ok(s) = std::fs::read_to_string(path) {
            if s.ends_with('\n') {
                return s.trim().to_string();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("{} not written", path.display());
}

/// Asserts that process `pid` ends within 5 s (`kill(pid, 0)`: `ESRCH`), and
/// kills it otherwise so that the test leaves nothing behind.
fn assert_gone(pid: libc::pid_t) {
    for _ in 0..100 {
        // SAFETY: signal 0 only checks that the process exists.
        let gone = unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit(')')
                    .next()
                    .map(|r| r.trim_start().starts_with('Z'))
            })
            .unwrap_or(false);
        if gone || zombie {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // SAFETY: plain system call on a process started by the test.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    panic!("hook sub-process {pid} survived");
}

/// `--exec-timeout` and Ctrl-C (SIGINT sent to pgpp) end a hook that does
/// not finish: its process group is killed, the delivery fails (exit 1).
#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn exec_timeout_and_interruption_kill_the_hook() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_exec_stop").await;
    let pidfile = std::env::temp_dir().join(format!("pgpp_exec_stop_{}.pid", std::process::id()));

    // --exec-timeout: the hook closed its stdin and keeps running
    let _ = std::fs::remove_file(&pidfile);
    let cmd = format!(
        "sleep 100000 & echo $! > '{}'; exec 0<&-; sleep 100000",
        pidfile.display()
    );
    let started = std::time::Instant::now();
    let out = run(
        &url,
        &[
            "-f",
            "json",
            "rotate",
            "pgpp_t_exec_stop",
            "--exec",
            &cmd,
            "--exec-timeout",
            "1",
        ],
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stdout} {stderr}");
    assert!(stderr.contains("within 1 s (--exec-timeout"), "{stderr}");
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["delivered_to"], serde_json::json!([]), "{stdout}");
    assert_gone(wait_for_line(&pidfile).parse().unwrap());

    // Ctrl-C: SIGINT to pgpp while the hook runs
    let _ = std::fs::remove_file(&pidfile);
    let cmd = format!(
        "sleep 100000 & echo $! > '{}'; cat >/dev/null; sleep 100000",
        pidfile.display()
    );
    let started = std::time::Instant::now();
    let child = pgpp(&url)
        .args([
            "rotate",
            "pgpp_t_exec_stop",
            "--exec",
            &cmd,
            "--exec-timeout",
            "0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cannot run pgpp");
    let sub: libc::pid_t = wait_for_line(&pidfile).parse().unwrap();
    // the handler is installed before the hook starts; leave it a margin
    std::thread::sleep(std::time::Duration::from_millis(300));
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: plain system call on the pgpp process started above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stdout} {stderr}");
    assert!(stderr.contains("interrupted (Ctrl-C)"), "{stderr}");
    assert!(stdout.contains("delivery failed: rotate again"), "{stdout}");
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert_gone(sub);
    let _ = std::fs::remove_file(&pidfile);
    exec_lenient(&mut conn, "DROP ROLE IF EXISTS pgpp_t_exec_stop").await;
}

fn vault_body_from_cli(req: &HttpMockRequest) -> bool {
    let Some(body) = &req.body else { return false };
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    v["data"]["username"] == "pgpp_t_vault"
        && v["data"]["password"]
            .as_str()
            .is_some_and(|p| p.chars().count() == 24)
        && v["data"]["rotated_at"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z'))
        && v["data"].as_object().unwrap().len() == 3
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn rotate_writes_to_vault_mock() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_vault").await;

    let server = MockServer::start_async().await;
    let lookup = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/v1/auth/token/lookup-self")
                .header("X-Vault-Token", "t-cli-token");
            then.status(200)
                .json_body(serde_json::json!({"data": {"ttl": 600}}));
        })
        .await;
    let caps = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v1/sys/capabilities-self")
                .header("X-Vault-Token", "t-cli-token");
            then.status(200)
                .json_body(serde_json::json!({"capabilities": ["create", "update"]}));
        })
        .await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v1/secret/data/pgpp/test")
                .header("X-Vault-Token", "t-cli-token")
                .header("X-Vault-Namespace", "ns1")
                .matches(vault_body_from_cli);
            then.status(200)
                .json_body(serde_json::json!({"data": {"version": 1}}));
        })
        .await;

    let out = pgpp(&url)
        .args([
            "-f",
            "json",
            "rotate",
            "pgpp_t_vault",
            "--vault-kv",
            "secret/pgpp/test",
        ])
        .env("VAULT_ADDR", server.base_url())
        .env("VAULT_TOKEN", "t-cli-token")
        .env("VAULT_NAMESPACE", "ns1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["delivered_to"], serde_json::json!(["vault"]));
    assert!(v.get("password").is_none());
    mock.assert_async().await;
    assert_eq!(
        lookup.hits_async().await,
        1,
        "token checked before the rotation"
    );

    // Vault failure: exit 1, password not shown, rotation still happened
    let fail = pgpp(&url)
        .args(["rotate", "pgpp_t_vault", "--vault-kv", "secret/other"])
        .env("VAULT_ADDR", server.base_url())
        .env("VAULT_TOKEN", "t-cli-token")
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
    let stderr = String::from_utf8(fail.stderr).unwrap();
    assert!(stderr.contains("Vault delivery failed"), "{stderr}");
    assert!(stderr.contains("404"), "{stderr}");
    assert_eq!(lookup.hits_async().await, 2);
    assert_eq!(caps.hits_async().await, 2);
}

/// Ctrl-C (SIGINT sent to pgpp) while the new password is being written to
/// Vault: pgpp does not die silently (the password would be lost without a
/// word) but abandons the write, skips the deliveries still to come
/// (`--exec`), and exits with 1 asking to rotate again.
#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn interruption_during_the_vault_write_asks_to_rotate_again() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_vault_int").await;
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(200)
                .json_body(serde_json::json!({"data": {"ttl": 600}}));
        })
        .await;
    server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/sys/capabilities-self");
            then.status(200)
                .json_body(serde_json::json!({"capabilities": ["create", "update"]}));
        })
        .await;
    // slow write: the hit is recorded at once, the answer comes 20 s later
    let write = server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/pgpp/int");
            then.status(200)
                .delay(std::time::Duration::from_secs(20))
                .json_body(serde_json::json!({"data": {"version": 1}}));
        })
        .await;
    let marker = std::env::temp_dir().join(format!("pgpp_vault_int_{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let cmd = format!("cat > '{}'", marker.display());

    let started = std::time::Instant::now();
    let child = pgpp(&url)
        .args([
            "rotate",
            "pgpp_t_vault_int",
            "--vault-kv",
            "secret/pgpp/int",
            "--exec",
            &cmd,
        ])
        .env("VAULT_ADDR", server.base_url())
        .env("VAULT_TOKEN", "t-cli-token")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cannot run pgpp");
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let mut waited = 0;
    while write.hits_async().await == 0 {
        assert!(waited < 200, "the Vault write never started");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        waited += 1;
    }
    // SAFETY: plain system call on the pgpp process started above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stdout} {stderr}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(15),
        "the write was not abandoned"
    );
    assert!(
        stderr.contains("Vault delivery failed: interrupted (Ctrl-C)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--exec delivery not attempted: interrupted (Ctrl-C)"),
        "{stderr}"
    );
    assert!(stderr.contains("2 delivery error(s)"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(stdout.contains("delivery failed: rotate again"), "{stdout}");
    assert!(!marker.exists(), "the --exec command must not run");
    exec_lenient(&mut conn, "DROP ROLE IF EXISTS pgpp_t_vault_int").await;
}

/// A standard output closed by its reader (`pgpp status | head -0`) ends
/// pgpp quietly with 0 instead of a panic; with `--show` the password is
/// lost and the failure is reported (exit 1).
#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn closed_stdout_is_not_a_panic() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_epipe").await;
    let closed = |args: &[&str]| {
        let mut child = pgpp(&url)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot run pgpp");
        // the read end is closed before pgpp has connected and printed
        drop(child.stdout.take());
        let out = child.wait_with_output().unwrap();
        (out.status.code(), String::from_utf8(out.stderr).unwrap())
    };
    for args in [
        &["status"][..],
        &["-f", "json", "status"],
        &["profile", "show", "default"],
    ] {
        let (code, stderr) = closed(args);
        assert_eq!(code, Some(0), "{args:?}: {stderr}");
        assert_eq!(stderr, "", "{args:?}");
    }
    let (code, stderr) = closed(&["rotate", "pgpp_t_epipe", "--show"]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("could not be printed") && stderr.contains("rotate again"),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
    exec_lenient(&mut conn, "DROP ROLE IF EXISTS pgpp_t_epipe").await;
}

/// The token and its permission on the path are checked (lookup-self,
/// capabilities-self) before the rotation: a refused token, a token that may
/// not write the path, a redirect or an unreachable Vault exit with 2 and
/// rotate nothing.
#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn vault_preflight_failure_rotates_nothing() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_vpre").await;

    let refused = MockServer::start_async().await;
    let lookup = refused
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(401)
                .json_body(serde_json::json!({"errors": ["permission denied"]}));
        })
        .await;
    // Vault answers 403 (not 401) for an expired, revoked or unknown token
    let denied = MockServer::start_async().await;
    let denied_lookup = denied
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(403)
                .json_body(serde_json::json!({"errors": ["permission denied"]}));
        })
        .await;
    let read_only = MockServer::start_async().await;
    read_only
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(200);
        })
        .await;
    read_only
        .mock_async(|when, then| {
            when.method(POST).path("/v1/sys/capabilities-self");
            then.status(200)
                .json_body(serde_json::json!({"capabilities": ["read"]}));
        })
        .await;
    let mut writes = Vec::new();
    for server in [&refused, &denied, &read_only] {
        writes.push(
            server
                .mock_async(|when, then| {
                    when.method(POST).path_contains("/data/");
                    then.status(204);
                })
                .await,
        );
    }
    for (addr, expected) in [
        (refused.base_url(), "lookup-self"),
        (denied.base_url(), "403"),
        ("http://127.0.0.1:9".to_string(), "lookup-self"),
        (read_only.base_url(), "may not write"),
    ] {
        let out = pgpp(&url)
            .args([
                "-f",
                "json",
                "rotate",
                "pgpp_t_vpre",
                "--vault-kv",
                "secret/app",
            ])
            .env("VAULT_ADDR", &addr)
            .env("VAULT_TOKEN", "t-expired")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(stderr.contains(expected), "{addr}: {stderr}");
        assert!(!stderr.contains("t-expired"), "{stderr}");
        // a failed preflight request is not a usage error
        assert_refused_before_rotation_with(&url, "pgpp_t_vpre", out, 1);
    }
    assert_eq!(lookup.hits_async().await, 1);
    assert_eq!(denied_lookup.hits_async().await, 1);
    for w in &writes {
        assert_eq!(w.hits_async().await, 0, "nothing written to Vault");
    }
    let st = run_json(&url, &["status", "--role", "pgpp_t_vpre"]);
    assert_eq!(st[0]["status"], "unknown", "password never changed");
}

/// A token without the default policy (lookup-self and capabilities-self
/// denied) is refused by default; with --vault-skip-preflight (or
/// PGPP_VAULT_SKIP_PREFLIGHT=1) no preflight request is sent, a warning is
/// printed and the write succeeds after the rotation.
#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn vault_token_without_introspection_still_rotates() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_vnodef").await;

    let server = MockServer::start_async().await;
    let introspection = server
        .mock_async(|when, then| {
            when.path_matches(
                httpmock::Regex::new("^/v1/(auth/token/lookup-self|sys/capabilities-self)$")
                    .unwrap(),
            );
            then.status(403)
                .json_body(serde_json::json!({"errors": ["permission denied"]}));
        })
        .await;
    let write = server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/secret/data/nodef");
            then.status(200);
        })
        .await;
    let rotate = |extra: &[&str], env: Option<&str>| {
        let mut cmd = pgpp(&url);
        cmd.args([
            "-f",
            "json",
            "rotate",
            "pgpp_t_vnodef",
            "--vault-kv",
            "secret/nodef",
        ])
        .args(extra)
        .env("VAULT_ADDR", server.base_url())
        .env("VAULT_TOKEN", "t-no-default\n");
        if let Some(v) = env {
            cmd.env("PGPP_VAULT_SKIP_PREFLIGHT", v);
        }
        cmd.output().unwrap()
    };

    // default: refused before the rotation
    let out = rotate(&[], None);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("--vault-skip-preflight"), "{stderr}");
    assert_refused_before_rotation_with(&url, "pgpp_t_vnodef", out, 1);
    assert_eq!(introspection.hits_async().await, 1, "stops at lookup-self");
    assert_eq!(write.hits_async().await, 0);

    let rotations = || {
        run_json(
            &url,
            &[
                "audit",
                "--role",
                "pgpp_t_vnodef",
                "--type",
                "password_rotated",
            ],
        )
        .as_array()
        .unwrap()
        .len()
    };
    let before = rotations();

    // explicit opt-out, by option or by environment variable
    for (extra, env) in [
        (&["--vault-skip-preflight"][..], None),
        (&[][..], Some("1")),
        (&[][..], Some("true")),
    ] {
        let out = rotate(extra, env);
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(out.status.success(), "{extra:?} {env:?}: {stderr}");
        assert_eq!(stderr.matches("pgpp: warning:").count(), 1, "{stderr}");
        assert!(stderr.contains("preflight skipped"), "{stderr}");
        assert!(!stderr.contains("t-no-default"), "{stderr}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["delivered_to"], serde_json::json!(["vault"]));
    }
    assert_eq!(introspection.hits_async().await, 1, "no preflight request");
    assert_eq!(write.hits_async().await, 3);

    // a falsy value keeps the preflight: refused, no further rotation
    let out = rotate(&[], Some("0"));
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(rotations(), before + 3);
    assert_eq!(introspection.hits_async().await, 2);
    assert_eq!(write.hits_async().await, 3);
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn lock_and_unlock() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_lock").await;

    let out = run_json(
        &url,
        &[
            "lock",
            "pgpp_t_lock",
            "--for",
            "30m",
            "--reason",
            "integration test",
        ],
    );
    assert_eq!(out["ok"], true);
    assert!(out["locked_until"]
        .as_str()
        .is_some_and(|s| s != "infinity"));

    let locked = run_json(&url, &["locked"]);
    let row = locked
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["role_name"] == "pgpp_t_lock")
        .expect("role listed as locked");
    assert_eq!(row["locked_by"], "manual");
    assert_eq!(row["lock_reason"], "integration test");
    let st = run_json(&url, &["status", "--role", "pgpp_t_lock"]);
    assert_eq!(st[0]["status"], "locked");

    run_ok(&url, &["unlock", "pgpp_t_lock"]);
    let locked = run_json(&url, &["locked"]);
    assert!(!locked
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["role_name"] == "pgpp_t_lock"));

    // manual lock without duration
    let out = run_json(&url, &["lock", "pgpp_t_lock"]);
    assert_eq!(out["locked_until"], "infinity");
    run_ok(&url, &["unlock", "pgpp_t_lock"]);

    // after a rename, role_state.role_name keeps the old name until the next
    // maintenance pass: v_role_status and v_locked join role_state by OID, so
    // locked_until, locked_by and lock_reason must still be reported
    exec_lenient(&mut conn, "DROP ROLE IF EXISTS pgpp_t_lock_renamed").await;
    conn.execute("ALTER ROLE pgpp_t_lock RENAME TO pgpp_t_lock_renamed")
        .await
        .unwrap();
    let out = run_json(
        &url,
        &[
            "lock",
            "pgpp_t_lock_renamed",
            "--for",
            "1h",
            "--reason",
            "after rename",
        ],
    );
    assert!(
        out["locked_until"]
            .as_str()
            .is_some_and(|s| s != "infinity"),
        "{out}"
    );
    // ... and `locked` (view v_locked) must still show who locked it and why
    let locked = run_json(&url, &["locked"]);
    let row = locked
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["role_name"] == "pgpp_t_lock_renamed")
        .unwrap_or_else(|| panic!("renamed role listed as locked: {locked}"));
    assert_eq!(row["locked_by"], "manual", "{row}");
    assert_eq!(row["lock_reason"], "after rename", "{row}");
    run_ok(&url, &["unlock", "pgpp_t_lock_renamed"]);
    exec_lenient(&mut conn, "DROP ROLE IF EXISTS pgpp_t_lock_renamed").await;

    let missing = run(&url, &["lock", "pgpp_t_missing_role"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("does not exist"));
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn profile_create_assign_unassign_drop() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_prof").await;
    exec_lenient(
        &mut conn,
        "SELECT pass_policy.drop_profile('pgpp_t_profile')",
    )
    .await;

    let out = run_json(
        &url,
        &[
            "profile",
            "create",
            "pgpp_t_profile",
            "--set",
            "min_length=16",
            "--set",
            "max_age=30 days",
            "--set",
            "max_failures=3",
            "--set",
            "reject_username=false",
        ],
    );
    assert_eq!(out["profile"], "pgpp_t_profile");
    assert!(out["profile_id"].is_number());

    let shown = run_json(&url, &["profile", "show", "pgpp_t_profile"]);
    assert_eq!(shown["min_length"], 16);
    assert_eq!(shown["max_age"], "30 days");
    assert_eq!(shown["max_failures"], 3);
    assert_eq!(shown["reject_username"], false);

    run_ok(
        &url,
        &[
            "profile",
            "alter",
            "pgpp_t_profile",
            "--set",
            "min_length=20",
            "--set",
            "lock_duration=null",
        ],
    );
    let shown = run_json(&url, &["profile", "show", "pgpp_t_profile"]);
    assert_eq!(shown["min_length"], 20);
    assert!(shown["lock_duration"].is_null());

    let list = run_json(&url, &["profile", "list"]);
    assert!(list
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "pgpp_t_profile"));

    run_ok(
        &url,
        &["profile", "assign", "pgpp_t_prof", "pgpp_t_profile"],
    );
    let st = run_json(&url, &["status", "--role", "pgpp_t_prof"]);
    assert_eq!(st[0]["profile"], "pgpp_t_profile");

    // profile in use cannot be dropped
    let busy = run(&url, &["profile", "drop", "pgpp_t_profile"]);
    assert_eq!(busy.status.code(), Some(1));

    run_ok(&url, &["profile", "unassign", "pgpp_t_prof"]);
    let st = run_json(&url, &["status", "--role", "pgpp_t_prof"]);
    assert_eq!(st[0]["profile"], "default");
    run_ok(&url, &["profile", "drop", "pgpp_t_profile"]);

    let bad = run(
        &url,
        &["profile", "create", "pgpp_t_bad", "--set", "nope=1"],
    );
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("unknown profile setting"));
    let usage = run(&url, &["profile", "create", "pgpp_t_bad", "--set", "nokv"]);
    assert_eq!(usage.status.code(), Some(2));
    let dup = run(
        &url,
        &[
            "profile",
            "create",
            "pgpp_t_bad",
            "--set",
            "min_length=1",
            "--set",
            "min_length=2",
        ],
    );
    assert_eq!(
        dup.status.code(),
        Some(2),
        "a repeated key is a usage error"
    );
    assert!(String::from_utf8_lossy(&dup.stderr).contains("given twice"));
}

fn check_with_stdin(url: &str, role: &str, password: &str, json: bool) -> (i32, String) {
    let (code, stdout, _) = check_with_stdin_full(url, role, password, json);
    (code, stdout)
}

fn check_with_stdin_full(
    url: &str,
    role: &str,
    password: &str,
    json: bool,
) -> (i32, String, String) {
    let mut c = pgpp(url);
    if json {
        c.args(["-f", "json"]);
    }
    let mut child = c
        .args(["check", role])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{password}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn check_reads_password_from_stdin() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_chk").await;

    let (code, out) = check_with_stdin(&url, "pgpp_t_chk", "short", false);
    assert_eq!(code, 3);
    assert!(out.contains("REFUSED") && out.contains("PPP-010"), "{out}");

    let (code, out) = check_with_stdin(&url, "pgpp_t_chk", "pgpp_t_chk-Zq7!vLm2", true);
    assert_eq!(code, 3);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], false);
    assert!(
        v["reason"].as_str().unwrap().starts_with("PPP-017"),
        "{out}"
    );

    // the log warning is printed only when pgpp cannot set
    // log_parameter_max_length and the value in force is not already 0
    // has_parameter_privilege() exists from PostgreSQL 15 on; before, only a
    // superuser may set log_parameter_max_length
    let (masked, version, superuser): (String, i32, bool) = sqlx::query_as(
        "SELECT current_setting('log_parameter_max_length'), \
                current_setting('server_version_num')::int, rolsuper \
           FROM pg_catalog.pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    let may_set = superuser
        || (version >= 150000
            && sqlx::query_scalar::<_, bool>(
                "SELECT has_parameter_privilege('log_parameter_max_length', 'SET')",
            )
            .fetch_one(&mut conn)
            .await
            .unwrap());
    let (code, out, err) = check_with_stdin_full(&url, "pgpp_t_chk", "Zq7!vLm2#pRw9xKt", true);
    assert_eq!(code, 0, "{out}");
    let expect_warning = !may_set && masked != "0";
    assert_eq!(
        err.contains("log_parameter_max_length"),
        expect_warning,
        "setting={masked} may_set={may_set}: {err}"
    );
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["reason"].is_null());

    // only the first line is read: a writer that keeps the pipe open, as in
    // `(echo "$PW"; sleep 300) | pgpp check`, must not block pgpp
    let mut child = pgpp(&url)
        .args(["-f", "json", "check", "pgpp_t_chk"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"Zq7!vLm2#pRw9xKt\r\n").unwrap();
    stdin.flush().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break Some(st);
        }
        if std::time::Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    drop(stdin);
    if status.is_none() {
        let _ = child.kill();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        status.is_some(),
        "pgpp check blocked waiting for EOF on stdin"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "CRLF stripped: {v}");

    let (code, _) = check_with_stdin(&url, "pgpp_t_chk", "", false);
    assert_eq!(code, 2, "an empty password is a usage error, not a refusal");
    let (code, _) = check_with_stdin("postgres://u@127.0.0.1:9/db", "pgpp_t_chk", "x", false);
    assert_eq!(code, 1, "a connection failure is an error, not a refusal");
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn switch_pair_rotates_the_inactive_role() {
    let url = db_url!();
    let mut conn = admin().await;
    exec_lenient(&mut conn, "CREATE ROLE pgpp_t_grp").await;
    exec_lenient(
        &mut conn,
        "SELECT pass_policy.create_rotation_pair('pgpp_t_pair', 'pgpp_t_pa', 'pgpp_t_pb', 'pgpp_t_grp')",
    )
    .await;

    let first = run_json(&url, &["switch-pair", "pgpp_t_pair", "--show"]);
    let active = first["role"].as_str().unwrap().to_string();
    assert!(active == "pgpp_t_pa" || active == "pgpp_t_pb", "{first}");
    assert_eq!(first["pair"], "pgpp_t_pair");
    let pw = first["password"].as_str().unwrap();
    assert!(can_login(&active, pw).await, "new active role must log in");

    let second = run_json(
        &url,
        &["switch-pair", "pgpp_t_pair", "--show", "--length", "28"],
    );
    assert_ne!(second["role"], active);
    assert_eq!(second["previous_role"], active);
    assert!(second["previous_valid_until"].is_string(), "{second}");
    assert_eq!(second["password"].as_str().unwrap().chars().count(), 28);

    // table output, with --exec receiving the pair variables
    let out = run_ok(
        &url,
        &[
            "switch-pair", "pgpp_t_pair",
            "--exec", "read -r pw; test -n \"$pw\" && test \"$PGPP_PAIR\" = pgpp_t_pair && test -n \"$PGPP_PREVIOUS_ROLE\"",
        ],
    );
    assert!(
        out.contains("pair: pgpp_t_pair") && out.contains("delivered_to: exec"),
        "{out}"
    );

    let audit = run_json(
        &url,
        &[
            "audit",
            "--type",
            "pair_switched",
            "--since",
            "10m",
            "--limit",
            "5",
        ],
    );
    assert!(audit
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["details"]["pair"] == "pgpp_t_pair"));
}

/// `expiring` sorts by the timestamp, not by its text.  sqlx forces
/// `DateStyle = ISO` and `TimeZone = UTC` in the startup packet (they win
/// over PGOPTIONS), so the text order differs from the time order only from
/// year 10000 on: "10026-..." sorts before "2026-..." as text.  A huge
/// `warn_before` puts both roles in the `warning` state.
#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn expiring_sorts_by_time_not_by_text() {
    let url = db_url!();
    let mut conn = admin().await;
    let roles = [("pgpp_t_exp_a", "1 day"), ("pgpp_t_exp_b", "8000 years")];
    for (role, max_age) in roles {
        let profile = format!("{role}_p");
        fresh_login_role(&mut conn, role).await;
        exec_lenient(
            &mut conn,
            &format!("SELECT pass_policy.drop_profile('{profile}')"),
        )
        .await;
        let max_age = format!("max_age={max_age}");
        run_ok(
            &url,
            &[
                "profile",
                "create",
                &profile,
                "--set",
                &max_age,
                "--set",
                "warn_before=9000 years",
            ],
        );
        run_ok(&url, &["profile", "assign", role, &profile]);
        run_ok(&url, &["rotate", role, "--exec", "cat >/dev/null"]);
    }

    let v = run_json(&url, &["expiring"]);
    let ours: Vec<&Value> = v
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["role_name"]
                .as_str()
                .is_some_and(|n| n.starts_with("pgpp_t_exp_"))
        })
        .collect();
    let names: Vec<&str> = ours
        .iter()
        .map(|r| r["role_name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["pgpp_t_exp_a", "pgpp_t_exp_b"], "{v}");
    let a = ours[0]["expires_at"].as_str().unwrap();
    let b = ours[1]["expires_at"].as_str().unwrap();
    assert!(
        a > b,
        "the fixture must sort the other way as text: {a} / {b}"
    );

    for (role, _) in roles {
        run_ok(&url, &["profile", "unassign", role]);
        run_ok(&url, &["profile", "drop", &format!("{role}_p")]);
        exec_lenient(&mut conn, &format!("DROP ROLE IF EXISTS {role}")).await;
    }
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn audit_filters() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_audit").await;
    run_ok(
        &url,
        &["rotate", "pgpp_t_audit", "--exec", "cat >/dev/null"],
    );
    run_ok(&url, &["expire", "pgpp_t_audit"]);

    let rows = run_json(&url, &["audit", "--since", "1h", "--role", "pgpp_t_audit"]);
    let rows = rows.as_array().unwrap();
    assert!(rows.iter().any(|r| r["event_type"] == "password_rotated"));
    assert!(rows.iter().any(|r| r["event_type"] == "password_expired"));
    assert!(rows.iter().all(|r| r["role_name"] == "pgpp_t_audit"));
    assert!(rows
        .iter()
        .all(|r| r["actor"].is_string() && r["event_time"].is_string()));
    for r in rows {
        let text = r.to_string();
        assert!(
            !text.contains("\"password\":"),
            "no password in audit: {text}"
        );
    }

    let typed = run_json(
        &url,
        &[
            "audit",
            "--type",
            "password_expired",
            "--role",
            "pgpp_t_audit",
            "--limit",
            "1",
        ],
    );
    assert_eq!(typed.as_array().unwrap().len(), 1);
    assert_eq!(typed[0]["event_type"], "password_expired");

    let exp = run_json(&url, &["expiring"]);
    assert!(exp
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["role_name"] == "pgpp_t_audit" && r["status"] == "expired"));
    let within = run_json(&url, &["expiring", "--within", "365d"]);
    assert!(within.as_array().unwrap().len() >= exp.as_array().unwrap().len());

    let bad = run(&url, &["audit", "--limit", "0"]);
    assert_eq!(bad.status.code(), Some(2));
}

/// application_name: "pgpp" by default, the value of DATABASE_URL
/// (`?application_name=`) or of PGAPPNAME otherwise; the audit log records it.
#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn application_name_of_the_url_is_kept() {
    let url = db_url!();
    let mut conn = admin().await;
    fresh_login_role(&mut conn, "pgpp_t_app").await;
    let sep = if url.contains('?') { '&' } else { '?' };
    let with_name = format!("{url}{sep}application_name=pgpp_t_from_url");
    let last_app = |u: &str| {
        let rows = run_json(u, &["audit", "--role", "pgpp_t_app", "--limit", "1"]);
        rows[0]["application_name"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    run_ok(&url, &["expire", "pgpp_t_app"]);
    assert_eq!(last_app(&url), "pgpp");
    run_ok(&with_name, &["expire", "pgpp_t_app"]);
    assert_eq!(last_app(&url), "pgpp_t_from_url");
    let out = pgpp(&url)
        .args(["expire", "pgpp_t_app"])
        .env("PGAPPNAME", "pgpp_t_from_env")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(last_app(&url), "pgpp_t_from_env");
}

#[tokio::test]
#[ignore = "needs PGPP_TEST_URL (cargo test -- --include-ignored)"]
async fn maintenance_worker_status_and_failed_attempts() {
    let url = db_url!();
    let out = run(&url, &["maintenance"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = run_json(&url, &["maintenance"]);
    assert!(json.is_array());

    let ws = run_json(&url, &["worker-status"]);
    assert!(ws["pid"].is_number() || ws["pid"].is_null(), "{ws}");
    assert!(ws.get("tracked_roles").is_some());

    let fa = run_json(&url, &["failed-attempts"]);
    assert!(fa.is_array());
    assert!(!run_ok(&url, &["failed-attempts"]).is_empty());
}

#[test]
fn usage_errors_exit_with_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_pgpp"))
        .arg("bogus")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(env!("CARGO_BIN_EXE_pgpp"))
        .args(["lock", "x", "--for", "soon"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    for args in [
        vec!["lock", "x", "--for", "0s"],
        vec!["expiring", "--within", "0d"],
        vec!["audit", "--since", "0m0s"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_pgpp"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("greater than zero"),
            "{args:?}"
        );
    }
    for args in [
        vec!["rotate", "x"],
        vec!["switch-pair", "x", "--length", "20"],
        vec!["audit", "--limit", "0"],
        vec!["profile", "create", "p", "--set", "nokv"],
        vec!["profile", "alter", "p"],
        // a repeated key is refused before the connection
        vec![
            "profile",
            "create",
            "p",
            "--set",
            "min_length=1",
            "--set",
            "min_length=2",
        ],
        vec![
            "profile",
            "alter",
            "p",
            "--set",
            "max_age=null",
            "--set",
            "max_age=1 day",
        ],
        // empty password for check (stdin is /dev/null)
        vec!["check", "x"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_pgpp"))
            .args(&args)
            .env("DATABASE_URL", "postgres://u@127.0.0.1:9/db")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("cannot connect"), "{args:?}: {stderr}");
    }
    // check: an empty first line (or invalid UTF-8) is refused before the
    // connection too
    for input in [&b"\n"[..], b"\r\nrest\n", b"\xff\xfe\n"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pgpp"))
            .args(["check", "x"])
            .env("DATABASE_URL", "postgres://u@127.0.0.1:9/db")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{input:?}: {stderr}");
        assert!(!stderr.contains("cannot connect"), "{input:?}: {stderr}");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_pgpp"))
        .args(["rotate", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("choose at least one"));
    let out = Command::new(env!("CARGO_BIN_EXE_pgpp"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

/// Delivery options are validated before the connection, so a bad Vault
/// setup never reaches the server (nor rotates anything).
#[test]
fn bad_vault_setup_is_refused_before_connecting() {
    let unreachable = "postgres://u@127.0.0.1:9/db";
    type Case = (
        Vec<&'static str>,
        Vec<(&'static str, &'static str)>,
        &'static str,
    );
    let cases: Vec<Case> = vec![
        (
            vec!["rotate", "x", "--vault-kv", "secret/app"],
            vec![("VAULT_TOKEN", "t")],
            "VAULT_ADDR is not set",
        ),
        (
            vec!["rotate", "x", "--vault-kv", "secret/app"],
            vec![("VAULT_ADDR", "https://127.0.0.1:9")],
            "VAULT_TOKEN is not set",
        ),
        (
            vec!["switch-pair", "x", "--vault-kv", "secret/app"],
            vec![
                ("VAULT_ADDR", "http://vault.example.invalid:8200"),
                ("VAULT_TOKEN", "t"),
            ],
            "loopback",
        ),
        (
            vec!["rotate", "x", "--vault-kv", "secret/../app"],
            vec![("VAULT_ADDR", "https://127.0.0.1:9"), ("VAULT_TOKEN", "t")],
            "invalid path segment",
        ),
        (
            vec!["rotate", "x", "--vault-kv", "secret/app"],
            vec![
                ("VAULT_ADDR", "https://127.0.0.1:9"),
                ("VAULT_TOKEN", "t"),
                ("VAULT_CAPATH", "/nonexistent-dir"),
            ],
            "VAULT_CAPATH",
        ),
        (
            vec!["rotate", "x", "--vault-kv", "secret/app"],
            vec![
                ("VAULT_ADDR", "https://127.0.0.1:9"),
                ("VAULT_TOKEN", "t\nx"),
            ],
            "VAULT_TOKEN contains a character",
        ),
        (
            vec!["rotate", "x", "--vault-kv", "secret/app"],
            vec![
                (
                    "VAULT_ADDR",
                    "https://user:pw-in-addr@vault.example.net:99999",
                ),
                ("VAULT_TOKEN", "t"),
            ],
            "VAULT_ADDR is not a valid URL",
        ),
    ];
    for (args, env, expected) in cases {
        let mut c = Command::new(env!("CARGO_BIN_EXE_pgpp"));
        c.args(&args)
            .env("DATABASE_URL", unreachable)
            .env_remove("VAULT_ADDR")
            .env_remove("VAULT_TOKEN")
            .env_remove("VAULT_NAMESPACE")
            .env_remove("VAULT_CACERT")
            .env_remove("VAULT_CAPATH");
        for (k, v) in &env {
            c.env(k, v);
        }
        let out = c.output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
        assert!(!stderr.contains("cannot connect"), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("\"t\"") && !stderr.contains("t\nx"),
            "token must not be echoed: {stderr}"
        );
        assert!(!stderr.contains("pw-in-addr"), "{stderr}");
    }
}

fn rotate_against_vault(server: &MockServer) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pgpp"))
        .args(["rotate", "x", "--vault-kv", "secret/app"])
        .env("DATABASE_URL", "postgres://u@127.0.0.1:9/db")
        .env("VAULT_ADDR", server.base_url())
        .env("VAULT_TOKEN", "t-refused")
        .env_remove("VAULT_NAMESPACE")
        .env_remove("VAULT_CACERT")
        .env_remove("VAULT_CAPATH")
        .env_remove("PGPP_VAULT_SKIP_PREFLIGHT")
        .output()
        .unwrap()
}

/// `--vault-mount kv --vault-kv kv/app` writes kv/data/kv/app: a warning
/// is printed, before the preflight and the connection.
#[tokio::test]
async fn repeated_vault_mount_is_warned_about() {
    let server = MockServer::start_async().await;
    let lookup = server
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(403);
        })
        .await;
    let run = |kv: &str| {
        Command::new(env!("CARGO_BIN_EXE_pgpp"))
            .args(["rotate", "x", "--vault-mount", "kv", "--vault-kv", kv])
            .env("DATABASE_URL", "postgres://u@127.0.0.1:9/db")
            .env("VAULT_ADDR", server.base_url())
            .env("VAULT_TOKEN", "t-refused")
            .env_remove("VAULT_NAMESPACE")
            .env_remove("VAULT_CACERT")
            .env_remove("VAULT_CAPATH")
            .env_remove("PGPP_VAULT_SKIP_PREFLIGHT")
            .output()
            .unwrap()
    };
    let out = run("kv/app");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("warning") && stderr.contains("kv/data/kv/app"),
        "{stderr}"
    );
    let out = run("app");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("starts with the mount"), "{stderr}");
    assert_eq!(lookup.hits_async().await, 2);
}

/// The Vault token preflight also runs before the PostgreSQL connection.  A
/// failed preflight request is not a usage error: exit code 1.
#[tokio::test]
async fn vault_token_refused_before_connecting() {
    let server = MockServer::start_async().await;
    let lookup = server
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(401);
        })
        .await;
    let out = rotate_against_vault(&server);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("401") && stderr.contains("VAULT_TOKEN"),
        "{stderr}"
    );
    assert!(!stderr.contains("cannot connect"), "{stderr}");
    assert!(!stderr.contains("t-refused"), "{stderr}");
    lookup.assert_async().await;

    // 403 on lookup-self (expired, revoked or unknown token, or a token
    // without the default policy): refused too, before the connection
    let server = MockServer::start_async().await;
    let lookup = server
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(403);
        })
        .await;
    let caps = server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/sys/capabilities-self");
            then.status(200)
                .json_body(serde_json::json!({"capabilities": ["create", "update"]}));
        })
        .await;
    let out = rotate_against_vault(&server);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("403") && stderr.contains("VAULT_TOKEN"),
        "{stderr}"
    );
    assert!(!stderr.contains("cannot connect"), "{stderr}");
    lookup.assert_async().await;
    assert_eq!(caps.hits_async().await, 0);
}

/// A Vault that cannot be reached, or that answers 5xx, during the preflight
/// exits with 1 (not a usage error), before the PostgreSQL connection.
#[tokio::test]
async fn failed_vault_preflight_request_exits_with_1() {
    let run = |addr: &str| {
        Command::new(env!("CARGO_BIN_EXE_pgpp"))
            .args(["rotate", "x", "--vault-kv", "secret/app"])
            .env("DATABASE_URL", "postgres://u@127.0.0.1:9/db")
            .env("VAULT_ADDR", addr)
            .env("VAULT_TOKEN", "t-preflight")
            .env_remove("VAULT_NAMESPACE")
            .env_remove("VAULT_CACERT")
            .env_remove("VAULT_CAPATH")
            .env_remove("PGPP_VAULT_SKIP_PREFLIGHT")
            .output()
            .unwrap()
    };
    // nothing listens on port 9: network error
    let out = run("http://127.0.0.1:9");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("preflight request"), "{stderr}");
    assert!(!stderr.contains("cannot connect"), "{stderr}");
    // 503 on lookup-self
    let server = MockServer::start_async().await;
    let lookup = server
        .mock_async(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(503);
        })
        .await;
    let out = run(&server.base_url());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("503"), "{stderr}");
    assert!(!stderr.contains("cannot connect"), "{stderr}");
    assert!(!stderr.contains("t-preflight"), "{stderr}");
    lookup.assert_async().await;
}

#[test]
fn connection_failure_exits_with_1_without_leaking_the_url() {
    let out = Command::new(env!("CARGO_BIN_EXE_pgpp"))
        .env("DATABASE_URL", "postgres://u:hidden-secret@127.0.0.1:9/db")
        .env_remove("PGPASSWORD")
        .arg("locked")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot connect"), "{stderr}");
    assert!(!stderr.contains("hidden-secret"), "{stderr}");
}
