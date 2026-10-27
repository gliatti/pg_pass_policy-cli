//! Implementation of every sub-command against the `pass_policy` SQL API.
//!
//! Every identifier and value is sent as a bound parameter; the queries never
//! interpolate user input.  Timestamps and intervals are cast to text on the
//! server so that special values (`infinity`) render faithfully.

use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sqlx::{Connection, Executor, PgConnection, Row};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::RotateOpts;
use crate::duration::to_pg_interval;
use crate::kv::parse_settings;
use crate::output::{print_message, print_record, Format, ResultSet};
use crate::secret::{check_shell, run_exec, Secret};
use crate::vault::{self, build_payload, write_secret, VaultConfig, VaultTarget};
use crate::{EXIT_OK, EXIT_REFUSED};

const STATUS_COLUMNS: &str = "role_name, profile, password_changed_at::text, expires_at::text, \
     grace_until::text, days_left, locked_until::text, failed_count, status";

pub async fn status(conn: &mut PgConnection, role: Option<&str>, fmt: Format) -> Result<()> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM pass_policy.v_role_status \
         WHERE $1::text IS NULL OR role_name = $1 ORDER BY role_name"
    );
    let rows = sqlx::query(&sql).bind(role).fetch_all(conn).await?;
    if rows.is_empty() {
        if let Some(r) = role {
            bail!("role \"{r}\" not found among login roles");
        }
    }
    ResultSet::from_rows(&rows)?.print(fmt, "no login role");
    Ok(())
}

pub async fn expiring(
    conn: &mut PgConnection,
    within: Option<Duration>,
    fmt: Format,
) -> Result<()> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM pass_policy.v_role_status \
         WHERE status IN ('warning', 'grace', 'expired') \
            OR ($1::interval IS NOT NULL AND expires_at IS NOT NULL AND expires_at <= now() + $1) \
         ORDER BY expires_at NULLS LAST, role_name"
    );
    let rows = sqlx::query(&sql)
        .bind(within.map(to_pg_interval).transpose()?)
        .fetch_all(conn)
        .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no expiring role");
    Ok(())
}

pub async fn locked(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let rows = sqlx::query(
        "SELECT role_name, locked_until::text, locked_by, lock_reason, failed_count \
         FROM pass_policy.v_locked ORDER BY role_name",
    )
    .fetch_all(conn)
    .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no locked role");
    Ok(())
}

/// `rolvaliduntil` of a role, as text (NULL when unbounded).
async fn valid_until(conn: &mut PgConnection, role: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT rolvaliduntil::text FROM pg_catalog.pg_roles WHERE rolname = $1")
        .bind(role)
        .fetch_optional(conn)
        .await?;
    Ok(row.and_then(|r| r.get::<Option<String>, _>(0)))
}

/// Reads `rolvaliduntil` after a rotation; never fatal, since the password is
/// already committed server-side and must reach `deliver()` whatever happens.
async fn valid_until_after_rotation(conn: &mut PgConnection, role: &str) -> Option<String> {
    match valid_until(conn, role).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pgpp: warning: password rotated but rolvaliduntil could not be read: {e:#}");
            None
        }
    }
}

/// Delivery channels of a rotation, resolved and validated before the
/// password is rotated: the Vault environment (`VAULT_ADDR`, `VAULT_TOKEN`,
/// certificates), the `--vault-kv` path, the availability of `sh`, and
/// finally the Vault token itself (preflight request).
pub struct Delivery {
    pub length: Option<i32>,
    pub show: bool,
    pub exec: Option<String>,
    pub vault: Option<(VaultConfig, VaultTarget)>,
}

impl Delivery {
    /// Validates `--exec` and `--vault-kv` / `--vault-mount`, then checks
    /// that Vault accepts the token (`lookup-self`); an error here is a usage
    /// error, reported before any connection to PostgreSQL.
    pub async fn prepare(opts: &RotateOpts) -> Result<Self> {
        let vault = match &opts.vault_kv {
            Some(kv) => {
                let target = VaultTarget::parse(kv, opts.vault_mount.as_deref())?;
                let cfg = VaultConfig::from_env()?;
                Some((cfg, target))
            }
            None => None,
        };
        if opts.exec.is_some() {
            check_shell()?;
        }
        if let Some((cfg, _)) = &vault {
            vault::preflight(cfg).await?;
        }
        Ok(Delivery {
            length: opts.length,
            show: opts.show,
            exec: opts.exec.clone(),
            vault,
        })
    }
}

/// What a rotation produced, without the password.
#[derive(Debug, Default, Serialize)]
struct Rotation {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pair: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_valid_until: Option<String>,
    valid_until: Option<String>,
}

#[derive(Serialize)]
struct RotationOutput<'a> {
    #[serde(flatten)]
    rotation: &'a Rotation,
    delivered_to: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
}

/// Delivers a new password according to `--show`, `--exec` and `--vault-kv`.
///
/// Policy: the password is printed only with `--show`; clap refuses a
/// rotation without any of the three options before anything is rotated.  If
/// a delivery (`--exec`, Vault) fails after the rotation, the password is NOT
/// printed unless `--show` was given: the caller must rotate again.
async fn deliver(rot: &Rotation, password: Secret, opts: &Delivery, fmt: Format) -> Result<()> {
    let mut delivered: Vec<&str> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    if let Some((cfg, target)) = &opts.vault {
        let result = async {
            let rotated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
            let mut payload = build_payload(&rot.role, &password, &rotated_at);
            let res = write_secret(cfg, target, &payload).await;
            // wipe the copy of the password held by the JSON payload
            if let Some(Value::String(s)) = payload.pointer_mut("/data/password") {
                s.zeroize();
            }
            res
        }
        .await;
        match result {
            Ok(()) => delivered.push("vault"),
            Err(e) => failures.push(format!("Vault delivery failed: {e:#}")),
        }
    }

    if let Some(cmd) = &opts.exec {
        let mut extra: Vec<(&str, &str)> = Vec::new();
        if let Some(p) = &rot.pair {
            extra.push(("PGPP_PAIR", p.as_str()));
        }
        if let Some(p) = &rot.previous_role {
            extra.push(("PGPP_PREVIOUS_ROLE", p.as_str()));
        }
        match run_exec(
            cmd,
            &password,
            &rot.role,
            rot.valid_until.as_deref(),
            &extra,
        )
        .await
        {
            Ok(()) => delivered.push("exec"),
            Err(e) => failures.push(format!("--exec delivery failed: {e:#}")),
        }
    }

    for f in &failures {
        eprintln!("pgpp: {f}");
    }
    let show = opts.show;

    match fmt {
        Format::Json => {
            let out = RotationOutput {
                rotation: rot,
                delivered_to: &delivered,
                password: show.then_some(password.as_str()),
            };
            let mut text = serde_json::to_string(&out)?;
            println!("{text}");
            text.zeroize();
        }
        Format::Table => {
            if let Some(p) = &rot.pair {
                println!("pair: {p}");
                println!("active_role: {}", rot.role);
            } else {
                println!("role: {}", rot.role);
            }
            if let Some(p) = &rot.previous_role {
                println!("previous_role: {p}");
                println!(
                    "previous_valid_until: {}",
                    rot.previous_valid_until.as_deref().unwrap_or("")
                );
            }
            println!("valid_until: {}", rot.valid_until.as_deref().unwrap_or(""));
            if !delivered.is_empty() {
                println!("delivered_to: {}", delivered.join(", "));
            }
            if show {
                println!("password: {}", password.as_str());
            } else if failures.is_empty() {
                println!("password: (not shown; use --show to print it)");
            } else {
                println!("password: (not shown and delivery failed: rotate again)");
            }
        }
    }
    drop(password);
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "password rotated but {} delivery error(s) occurred",
            failures.len()
        )
    }
}

pub async fn rotate(
    conn: &mut PgConnection,
    role: &str,
    opts: Delivery,
    fmt: Format,
) -> Result<()> {
    let row = sqlx::query("SELECT pass_policy.rotate_password($1::name, $2::int)")
        .bind(role)
        .bind(opts.length)
        .fetch_one(&mut *conn)
        .await?;
    let password: Secret = Zeroizing::new(row.get::<String, _>(0));
    drop(row);
    let rot = Rotation {
        role: role.to_string(),
        valid_until: valid_until_after_rotation(conn, role).await,
        ..Rotation::default()
    };
    deliver(&rot, password, &opts, fmt).await
}

pub async fn switch_pair(
    conn: &mut PgConnection,
    pair: &str,
    opts: Delivery,
    fmt: Format,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT active_role, password, previous_role, previous_valid_until::text \
         FROM pass_policy.switch_rotation_pair($1::text, $2::int)",
    )
    .bind(pair)
    .bind(opts.length)
    .fetch_one(&mut *conn)
    .await?;
    let active: String = row.get(0);
    let password: Secret = Zeroizing::new(row.get::<String, _>(1));
    let previous_role: Option<String> = row.get(2);
    let previous_valid_until: Option<String> = row.get(3);
    drop(row);
    let rot = Rotation {
        valid_until: valid_until_after_rotation(conn, &active).await,
        role: active,
        pair: Some(pair.to_string()),
        previous_role,
        previous_valid_until,
    };
    deliver(&rot, password, &opts, fmt).await
}

pub async fn lock(
    conn: &mut PgConnection,
    role: &str,
    duration: Option<Duration>,
    reason: Option<&str>,
    fmt: Format,
) -> Result<()> {
    sqlx::query("SELECT pass_policy.lock_role($1::name, $2::interval, $3::text)")
        .bind(role)
        .bind(duration.map(to_pg_interval).transpose()?)
        .bind(reason)
        .execute(&mut *conn)
        .await?;
    // role_state.role_name is refreshed by the maintenance only: after an
    // ALTER ROLE ... RENAME it still holds the old name, so look the row up
    // by OID through pg_roles.
    let until: Option<String> = sqlx::query(
        "SELECT s.locked_until::text FROM pass_policy.role_state s \
           JOIN pg_catalog.pg_roles r ON r.oid = s.role_oid \
          WHERE r.rolname = $1",
    )
    .bind(role)
    .fetch_optional(conn)
    .await?
    .and_then(|r| r.get(0));
    let text = match &until {
        Some(u) if u != "infinity" => format!("role \"{role}\" locked until {u}"),
        _ => format!("role \"{role}\" locked until manual unlock"),
    };
    print_message(
        fmt,
        &text,
        json!({"ok": true, "role": role, "locked_until": until, "reason": reason}),
    );
    Ok(())
}

pub async fn unlock(conn: &mut PgConnection, role: &str, fmt: Format) -> Result<()> {
    sqlx::query("SELECT pass_policy.unlock_role($1::name)")
        .bind(role)
        .execute(conn)
        .await?;
    print_message(
        fmt,
        &format!("role \"{role}\" unlocked"),
        json!({"ok": true, "role": role}),
    );
    Ok(())
}

pub async fn expire(conn: &mut PgConnection, role: &str, fmt: Format) -> Result<()> {
    sqlx::query("SELECT pass_policy.expire_password($1::name)")
        .bind(role)
        .execute(conn)
        .await?;
    print_message(
        fmt,
        &format!("password of role \"{role}\" expired (must change)"),
        json!({"ok": true, "role": role}),
    );
    Ok(())
}

pub async fn profile_list(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let rows = sqlx::query(
        "SELECT p.name, p.min_length, p.max_length, p.min_classes, p.history_count, \
                p.max_age::text, p.grace_period::text, p.warn_before::text, \
                p.max_failures, p.failure_window::text, p.lock_duration::text, \
                (SELECT count(*) FROM pass_policy.role_profile rp \
                  WHERE rp.profile_id = p.profile_id) AS roles \
         FROM pass_policy.profile p ORDER BY (p.name <> 'default'), p.name",
    )
    .fetch_all(conn)
    .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no profile");
    Ok(())
}

pub async fn profile_show(conn: &mut PgConnection, name: &str, fmt: Format) -> Result<()> {
    let row = sqlx::query("SELECT to_jsonb(p) FROM pass_policy.profile p WHERE p.name = $1")
        .bind(name)
        .fetch_optional(conn)
        .await?;
    let Some(row) = row else {
        bail!("profile \"{name}\" does not exist");
    };
    let value: Value = row.get(0);
    let Value::Object(record) = value else {
        bail!("internal error: unexpected profile representation");
    };
    print_record(&record, fmt);
    Ok(())
}

pub async fn profile_create(
    conn: &mut PgConnection,
    name: &str,
    set: &[(String, Value)],
    fmt: Format,
) -> Result<()> {
    let settings = Value::Object(parse_settings(set)?);
    let id: i32 = sqlx::query("SELECT pass_policy.create_profile($1::text, $2::jsonb)")
        .bind(name)
        .bind(&settings)
        .fetch_one(conn)
        .await?
        .get(0);
    print_message(
        fmt,
        &format!("profile \"{name}\" created (id {id})"),
        json!({"ok": true, "profile": name, "profile_id": id, "settings": settings}),
    );
    Ok(())
}

pub async fn profile_alter(
    conn: &mut PgConnection,
    name: &str,
    set: &[(String, Value)],
    fmt: Format,
) -> Result<()> {
    let settings = Value::Object(parse_settings(set)?);
    sqlx::query("SELECT pass_policy.alter_profile($1::text, $2::jsonb)")
        .bind(name)
        .bind(&settings)
        .execute(conn)
        .await?;
    print_message(
        fmt,
        &format!("profile \"{name}\" altered"),
        json!({"ok": true, "profile": name, "settings": settings}),
    );
    Ok(())
}

pub async fn profile_drop(conn: &mut PgConnection, name: &str, fmt: Format) -> Result<()> {
    sqlx::query("SELECT pass_policy.drop_profile($1::text)")
        .bind(name)
        .execute(conn)
        .await?;
    print_message(
        fmt,
        &format!("profile \"{name}\" dropped"),
        json!({"ok": true, "profile": name}),
    );
    Ok(())
}

pub async fn profile_assign(
    conn: &mut PgConnection,
    role: &str,
    profile: &str,
    fmt: Format,
) -> Result<()> {
    sqlx::query("SELECT pass_policy.assign_profile($1::name, $2::text)")
        .bind(role)
        .bind(profile)
        .execute(conn)
        .await?;
    print_message(
        fmt,
        &format!("profile \"{profile}\" assigned to role \"{role}\""),
        json!({"ok": true, "role": role, "profile": profile}),
    );
    Ok(())
}

pub async fn profile_unassign(conn: &mut PgConnection, role: &str, fmt: Format) -> Result<()> {
    sqlx::query("SELECT pass_policy.unassign_profile($1::name)")
        .bind(role)
        .execute(conn)
        .await?;
    print_message(
        fmt,
        &format!("role \"{role}\" now uses profile \"default\""),
        json!({"ok": true, "role": role, "profile": "default"}),
    );
    Ok(())
}

pub async fn audit(
    conn: &mut PgConnection,
    since: Option<Duration>,
    role: Option<&str>,
    event_type: Option<&str>,
    limit: i64,
    fmt: Format,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT id, event_time::text, event_type, role_name, actor, database, \
                client_addr::text, application_name, details \
         FROM pass_policy.audit_log \
         WHERE ($1::interval IS NULL OR event_time >= now() - $1) \
           AND ($2::text IS NULL OR role_name = $2) \
           AND ($3::text IS NULL OR event_type = $3) \
         ORDER BY id DESC LIMIT $4::bigint",
    )
    .bind(since.map(to_pg_interval).transpose()?)
    .bind(role)
    .bind(event_type)
    .bind(limit)
    .fetch_all(conn)
    .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no audit event");
    Ok(())
}

/// Reads the candidate password: prompted without echo on a terminal,
/// otherwise the first line of stdin.
fn read_password() -> Result<Secret> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("Password to check: ");
        std::io::stderr().flush().ok();
        let pw = rpassword::read_password().context("cannot read the password")?;
        return Ok(Zeroizing::new(pw));
    }
    read_first_line(&mut stdin.lock()).context("cannot read the password from stdin")
}

/// Reads one line (the rest of the input is left unread, so that a writer
/// that keeps its end of the pipe open does not block pgpp) and strips the
/// final `\n` / `\r\n`.
fn read_first_line(input: &mut impl BufRead) -> std::io::Result<Secret> {
    // pre-allocated so that a usual password never makes the buffer grow
    // (a reallocation would leave an unwiped copy behind)
    let mut line = Zeroizing::new(String::with_capacity(1024));
    input.read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// Keeps the candidate password out of the server log.  A bound parameter is
/// written in the DETAIL line of `log_statement = 'all'` /
/// `log_min_duration_statement` unless `log_parameter_max_length` is 0; that
/// setting is superuser-only by default, so a refusal (42501) is downgraded
/// to a warning.  The SET LOCAL runs under a savepoint so that the transaction
/// stays usable after a refusal.
async fn mask_parameters(tx: &mut PgConnection) -> Result<()> {
    tx.execute("SAVEPOINT pgpp_mask").await?;
    match tx.execute("SET LOCAL log_parameter_max_length = 0").await {
        Ok(_) => {
            tx.execute("RELEASE SAVEPOINT pgpp_mask").await?;
            Ok(())
        }
        Err(e) if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("42501") => {
            tx.execute("ROLLBACK TO SAVEPOINT pgpp_mask").await?;
            eprintln!(
                "pgpp: warning: cannot disable parameter logging (log_parameter_max_length); \
                 the candidate password may appear in the server log if log_statement or \
                 log_min_duration_statement are enabled. Ask a superuser for \
                 \"ALTER ROLE <admin> SET log_parameter_max_length = 0\" or \
                 \"GRANT SET ON PARAMETER log_parameter_max_length TO <admin>\""
            );
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Returns the exit code: 0 when the password complies, 3 when refused
/// (1 is left to real errors so that scripts can tell them apart).
pub async fn check(conn: &mut PgConnection, role: &str, fmt: Format) -> Result<i32> {
    let password = read_password()?;
    if password.is_empty() {
        bail!("empty password");
    }
    let mut tx = conn.begin().await?;
    mask_parameters(&mut tx).await?;
    let row = sqlx::query("SELECT pass_policy.check_password($1::text, $2::text)")
        .bind(role)
        .bind(password.as_str())
        .fetch_one(&mut *tx)
        .await?;
    let reason: Option<String> = row.get(0);
    drop(password);
    tx.commit().await?;
    let (code, text) = match &reason {
        None => (
            EXIT_OK,
            format!("OK: password complies with the policy of role \"{role}\""),
        ),
        Some(r) => (EXIT_REFUSED, format!("REFUSED: {r}")),
    };
    print_message(
        fmt,
        &text,
        json!({"ok": reason.is_none(), "role": role, "reason": reason}),
    );
    Ok(code)
}

pub async fn maintenance(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let rows = sqlx::query("SELECT action, role_name, details FROM pass_policy.run_maintenance()")
        .fetch_all(conn)
        .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "maintenance run: nothing to do");
    Ok(())
}

pub async fn failed_attempts(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let rows = sqlx::query(
        "SELECT role_name, failed_count, first_failure_at::text, last_failure_at::text, \
                locked_until::text \
         FROM pass_policy.failed_attempts() ORDER BY role_name",
    )
    .fetch_all(conn)
    .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no tracked authentication failure");
    Ok(())
}

pub async fn worker_status(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let row = sqlx::query(
        "SELECT pid, last_run::text, last_reload::text, tracked_roles FROM pass_policy.worker_status()",
    )
    .fetch_one(conn)
    .await?;
    let rs = ResultSet::from_rows(std::slice::from_ref(&row))?;
    let mut record = Map::new();
    if let Some(values) = rs.rows.first() {
        for (k, v) in rs.columns.iter().zip(values) {
            record.insert(k.clone(), v.clone());
        }
    }
    print_record(&record, fmt);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_the_first_line() {
        let mut input: &[u8] = b"first\r\nsecond\n";
        assert_eq!(read_first_line(&mut input).unwrap().as_str(), "first");
        assert_eq!(input, b"second\n", "the rest is left unread");
        let mut input: &[u8] = b"pw\n";
        assert_eq!(read_first_line(&mut input).unwrap().as_str(), "pw");
        let mut input: &[u8] = b"no-newline";
        assert_eq!(read_first_line(&mut input).unwrap().as_str(), "no-newline");
        let mut input: &[u8] = b"  spaces kept \t\n";
        assert_eq!(
            read_first_line(&mut input).unwrap().as_str(),
            "  spaces kept \t"
        );
        let mut input: &[u8] = b"";
        assert_eq!(read_first_line(&mut input).unwrap().as_str(), "");
        let mut input: &[u8] = b"\nnext";
        assert_eq!(read_first_line(&mut input).unwrap().as_str(), "");
    }
}
