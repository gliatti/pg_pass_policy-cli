//! Implementation of every sub-command against the `pass_policy` SQL API.
//!
//! Every identifier and value is sent as a bound parameter; the queries never
//! interpolate user input.  Timestamps and intervals are cast to text on the
//! server so that special values (`infinity`) render faithfully.

use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sqlx::postgres::{PgRow, PgTypeInfo};
use sqlx::{Connection, Executor, PgConnection, Row, TypeInfo, ValueRef};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::RotateOpts;
use crate::duration::to_pg_interval;
use crate::output::{is_broken_pipe, print_message, print_record, write_line, Format, ResultSet};
use crate::secret::{check_shell, run_exec, Interrupt, Secret};
use crate::vault::{self, build_payload, write_secret, VaultConfig, VaultTarget};
use crate::{EXIT_OK, EXIT_REFUSED};

/// Columns of `v_role_status`, read through the alias `v`.  The ORDER BY
/// clauses must name `v.<column>`: an unqualified `expires_at` would resolve
/// to the output column `expires_at::text` and sort as text.
const STATUS_COLUMNS: &str = "v.role_name, v.profile, v.password_changed_at::text, \
     v.expires_at::text, v.grace_until::text, v.days_left, v.locked_until::text, \
     v.failed_count, v.status";

pub async fn status(conn: &mut PgConnection, role: Option<&str>, fmt: Format) -> Result<()> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM pass_policy.v_role_status v \
         WHERE $1::text IS NULL OR v.role_name = $1 ORDER BY v.role_name"
    );
    let rows = sqlx::query(&sql).bind(role).fetch_all(conn).await?;
    if rows.is_empty() {
        if let Some(r) = role {
            bail!("role \"{r}\" not found among login roles");
        }
    }
    ResultSet::from_rows(&rows)?.print(fmt, "no login role")
}

pub async fn expiring(
    conn: &mut PgConnection,
    within: Option<Duration>,
    fmt: Format,
) -> Result<()> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM pass_policy.v_role_status v \
         WHERE v.status IN ('warning', 'grace', 'expired') \
            OR ($1::interval IS NOT NULL AND v.expires_at IS NOT NULL \
                AND v.expires_at <= now() + $1) \
         ORDER BY v.expires_at NULLS LAST, v.role_name"
    );
    let rows = sqlx::query(&sql)
        .bind(within.map(to_pg_interval).transpose()?)
        .fetch_all(conn)
        .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no expiring role")
}

/// Rows of the view `v_locked`.  The view joins `role_state` by OID (it
/// used to join on `role_name`, which the maintenance refreshes only, so
/// that `locked_by` / `lock_reason` were empty after an
/// `ALTER ROLE ... RENAME`); an older extension still shows that gap.
pub async fn locked(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let rows = sqlx::query(
        "SELECT role_name, locked_until::text, locked_by, lock_reason, failed_count \
           FROM pass_policy.v_locked ORDER BY role_name",
    )
    .fetch_all(conn)
    .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no locked role")
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
/// `None` when the read failed or was interrupted (Ctrl-C), `Some(None)`
/// when the role is unbounded.
async fn valid_until_after_rotation(
    conn: &mut PgConnection,
    role: &str,
    interrupt: &mut Interrupt,
) -> Option<Option<String>> {
    let read = tokio::select! {
        biased;
        () = interrupt.wait() => Err(anyhow::anyhow!("interrupted (Ctrl-C)")),
        r = valid_until(conn, role) => r,
    };
    match read {
        Ok(v) => Some(v),
        Err(e) => {
            crate::report(
                crate::Report::Warning,
                &e.context("password rotated but rolvaliduntil could not be read"),
            );
            None
        }
    }
}

/// Delivery channels of a rotation, resolved and validated before the
/// password is rotated: the Vault environment (`VAULT_ADDR`, `VAULT_TOKEN`,
/// certificates), the `--vault-kv` path, the availability of `sh`, and
/// finally the Vault token itself and its permission on the target path
/// (preflight requests).
pub struct Delivery {
    pub length: Option<i32>,
    pub show: bool,
    pub exec: Option<String>,
    /// `--exec-timeout` (`None`: no limit).
    pub exec_timeout: Option<Duration>,
    pub vault: Option<(VaultConfig, VaultTarget)>,
}

/// Why [`Delivery::prepare`] refused the delivery options.  Both are
/// reported before any connection to PostgreSQL; they differ by exit code.
#[derive(Debug)]
pub enum PrepareError {
    /// Local validation: `--vault-kv` path, Vault environment and
    /// certificates, `sh` for `--exec` (usage error, exit code 2).
    Invalid(anyhow::Error),
    /// A preflight request to Vault failed: network, TLS, redirect, refused
    /// token, HTTP status, missing write permission (exit code 1).
    Preflight(anyhow::Error),
}

impl PrepareError {
    pub fn error(&self) -> &anyhow::Error {
        match self {
            PrepareError::Invalid(e) | PrepareError::Preflight(e) => e,
        }
    }
}

impl Delivery {
    /// Validates `--exec` and `--vault-kv` / `--vault-mount`, then checks
    /// that Vault accepts the token and lets it write the target
    /// ([`vault::preflight`]), before any connection to PostgreSQL.
    pub async fn prepare(opts: &RotateOpts) -> std::result::Result<Self, PrepareError> {
        let vault = match &opts.vault_kv {
            Some(kv) => {
                let target = VaultTarget::parse(kv, opts.vault_mount.as_deref())
                    .map_err(PrepareError::Invalid)?;
                if opts.vault_mount.is_some() {
                    if let Some(w) = target.repeated_mount_warning() {
                        eprintln!("pgpp: warning: {w}");
                    }
                }
                let cfg = VaultConfig::from_env().map_err(PrepareError::Invalid)?;
                Some((cfg, target))
            }
            None => None,
        };
        if opts.exec.is_some() {
            check_shell().map_err(PrepareError::Invalid)?;
        }
        if let Some((cfg, target)) = &vault {
            if opts.vault_skip_preflight {
                eprintln!(
                    "pgpp: warning: Vault preflight skipped (--vault-skip-preflight): \
                     VAULT_TOKEN and its permission on the path are only checked by the \
                     write, after the rotation"
                );
            } else {
                let warnings = vault::preflight(cfg, target)
                    .await
                    .map_err(PrepareError::Preflight)?;
                for w in warnings {
                    eprintln!("pgpp: warning: {w}");
                }
            }
        }
        Ok(Delivery {
            length: opts.length,
            show: opts.show,
            exec: opts.exec.clone(),
            exec_timeout: opts.exec_timeout.0,
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
    /// `rolvaliduntil` after the rotation; `None` (JSON null) for an
    /// unbounded role, or when the value is unknown (see `valid_until_known`)
    valid_until: Option<String>,
    /// false when `rolvaliduntil` could not be read after the rotation
    /// (`valid_until` is then null although the role may be bounded)
    valid_until_known: bool,
}

impl Rotation {
    fn set_valid_until(&mut self, read: Option<Option<String>>) {
        self.valid_until_known = read.is_some();
        self.valid_until = read.flatten();
    }

    /// `valid_until` in table format: empty for an unbounded role,
    /// `(unknown)` when the value could not be read after the rotation.
    fn valid_until_display(&self) -> &str {
        if self.valid_until_known {
            self.valid_until.as_deref().unwrap_or("")
        } else {
            "(unknown)"
        }
    }

    /// Value of `PGPP_VALID_UNTIL`: empty for an unbounded role, unset when
    /// the value could not be read.
    fn valid_until_env(&self) -> Option<&str> {
        self.valid_until_known
            .then(|| self.valid_until.as_deref().unwrap_or(""))
    }
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
///
/// A Ctrl-C ([`Interrupt`]) received before or during a delivery makes it
/// fail (the Vault write or the `--exec` command in progress is abandoned,
/// a delivery still to come is not attempted): it ends like any other
/// failed delivery, with exit code 1 and « rotate again ».
async fn deliver(
    rot: &Rotation,
    password: Secret,
    opts: &Delivery,
    fmt: Format,
    interrupt: &mut Interrupt,
) -> Result<()> {
    let mut delivered: Vec<&str> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    if let Some((cfg, target)) = &opts.vault {
        let rotated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut payload = build_payload(&rot.role, &password, &rotated_at);
        // biased: a Ctrl-C already received wins before the request starts
        let result = tokio::select! {
            biased;
            () = interrupt.wait() => Err(anyhow::anyhow!(
                "interrupted (Ctrl-C); the secret may or may not have been written"
            )),
            r = write_secret(cfg, target, &payload) => r,
        };
        // wipe the copy of the password held by the JSON payload
        if let Some(Value::String(s)) = payload.pointer_mut("/data/password") {
            s.zeroize();
        }
        match result {
            Ok(()) => delivered.push("vault"),
            Err(e) => failures.push(format!("Vault delivery failed: {e:#}")),
        }
    }

    if let Some(cmd) = opts.exec.as_ref().filter(|_| interrupt.received()) {
        failures.push(format!(
            "--exec delivery not attempted: interrupted (Ctrl-C); command: {cmd}"
        ));
    } else if let Some(cmd) = &opts.exec {
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
            rot.valid_until_env(),
            &extra,
            opts.exec_timeout,
            interrupt,
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
    let printed = print_rotation(rot, &password, &delivered, failures.is_empty(), show, fmt);
    drop(password);
    if !failures.is_empty() {
        bail!(
            "password rotated but {} delivery error(s) occurred",
            failures.len()
        )
    }
    // with --show alone the standard output is the only delivery: a closed
    // pipe loses the password and is reported (not silenced)
    let lost = show && delivered.is_empty();
    match printed {
        Err(e) if lost && is_broken_pipe(&e) => bail!(
            "password rotated but it could not be printed (the standard output was \
             closed): rotate again"
        ),
        Err(e) if lost => {
            Err(e.context("password rotated but it could not be printed: rotate again"))
        }
        other => other,
    }
}

/// Prints the outcome of a rotation (and the password with `--show`).
fn print_rotation(
    rot: &Rotation,
    password: &Secret,
    delivered: &[&str],
    succeeded: bool,
    show: bool,
    fmt: Format,
) -> Result<()> {
    match fmt {
        Format::Json => {
            let out = RotationOutput {
                rotation: rot,
                delivered_to: delivered,
                password: show.then_some(password.as_str()),
            };
            // exact-size, wiped buffer, newline included (no reallocation
            // copies of the password with --show), written past the stdout
            // buffer
            let text = vault::zeroizing_json_line(&out)?;
            write_stdout_unbuffered(&text)
        }
        Format::Table => {
            if let Some(p) = &rot.pair {
                write_line(format_args!("pair: {p}"))?;
                write_line(format_args!("active_role: {}", rot.role))?;
            } else {
                write_line(format_args!("role: {}", rot.role))?;
            }
            if let Some(p) = &rot.previous_role {
                write_line(format_args!("previous_role: {p}"))?;
                write_line(format_args!(
                    "previous_valid_until: {}",
                    rot.previous_valid_until.as_deref().unwrap_or("")
                ))?;
            }
            write_line(format_args!("valid_until: {}", rot.valid_until_display()))?;
            if !delivered.is_empty() {
                write_line(format_args!("delivered_to: {}", delivered.join(", ")))?;
            }
            if show {
                let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 11));
                line.extend_from_slice(b"password: ");
                line.extend_from_slice(password.as_bytes());
                line.push(b'\n');
                write_stdout_unbuffered(&line)
            } else if succeeded {
                write_line("password: (not shown; use --show to print it)")
            } else {
                write_line("password: (not shown and delivery failed: rotate again)")
            }
        }
    }
}

/// `check` keeps its exit code (0 / 3) when the reader of the standard
/// output is gone.
fn ignore_broken_pipe(e: anyhow::Error) -> Result<()> {
    if is_broken_pipe(&e) {
        Ok(())
    } else {
        Err(e)
    }
}

/// Writes `bytes` to the standard output without going through the buffer of
/// `std::io::stdout()` (which would keep an unwiped copy of a password): the
/// buffer is flushed first, then the bytes go to a duplicate of descriptor 1.
fn write_stdout_unbuffered(bytes: &[u8]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let written = lock.flush().and_then(|()| {
        let fd = lock.as_fd().try_clone_to_owned()?;
        std::fs::File::from(fd).write_all(bytes)
    });
    written.map_err(|e| {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            anyhow::Error::new(crate::output::BrokenPipe)
        } else {
            anyhow::Error::new(e).context("cannot write to the standard output")
        }
    })
}

/// Copies a text column holding a password straight from the raw value of
/// the row into a [`Secret`] allocated at its exact size; a NULL is an
/// error.  The row itself (and the receive buffer of sqlx it was cut from)
/// is not wiped: see the README, « Limite de cet effacement ».
fn secret_column(row: &PgRow, index: usize) -> Result<Secret> {
    let raw = row
        .try_get_raw(index)
        .context("cannot read the generated password")?;
    if raw.is_null() {
        bail!("the server returned no password");
    }
    check_text_type(&raw.type_info())?;
    let text = raw
        .as_str()
        .map_err(|e| anyhow::anyhow!("cannot read the generated password: {e}"))?;
    let mut secret = Zeroizing::new(String::with_capacity(text.len()));
    secret.push_str(text);
    Ok(secret)
}

/// Decodes an optional text column of the result of a rotation, with the
/// wording of [`secret_column`] (`cannot read <what>`): a type mismatch is
/// an error, not a panic.
fn text_column(row: &PgRow, index: usize, what: &str) -> Result<Option<String>> {
    row.try_get::<Option<String>, _>(index)
        .with_context(|| format!("cannot read {what}"))
}

/// `as_str()` reads any value as UTF-8 text, whatever its type: the binary
/// form of an `int4` or a `bytea` would be taken for a password.  Only the
/// text types decoded by sqlx as `&str` (text, varchar, name, bpchar,
/// citext) are accepted.
fn check_text_type(ty: &PgTypeInfo) -> Result<()> {
    if <str as sqlx::Type<sqlx::Postgres>>::compatible(ty) {
        Ok(())
    } else {
        bail!(
            "cannot read the generated password: the server returned a value of type {}, \
             text expected (incompatible version of pg_pass_policy?)",
            ty.name()
        )
    }
}

/// Runs the SQL call that rotates the password, Ctrl-C handler already
/// installed: a Ctrl-C during the call abandons it (the connection is
/// dropped) and is reported, since the server may have committed the new
/// password all the same.
async fn rotation_call(
    query: impl std::future::Future<Output = std::result::Result<PgRow, sqlx::Error>>,
    interrupt: &mut Interrupt,
) -> Result<PgRow> {
    tokio::select! {
        biased;
        () = interrupt.wait() => bail!(
            "interrupted (Ctrl-C) during the rotation: the password may have been changed \
             on the server and is not delivered: rotate again"
        ),
        r = query => Ok(r?),
    }
}

pub async fn rotate(
    conn: &mut PgConnection,
    role: &str,
    opts: Delivery,
    fmt: Format,
) -> Result<()> {
    // installed before the SQL call: from the rotation on, a Ctrl-C must
    // not kill pgpp before the password is delivered
    let mut interrupt = Interrupt::install();
    let row = rotation_call(
        sqlx::query("SELECT pass_policy.rotate_password($1::name, $2::int)")
            .bind(role)
            .bind(opts.length)
            .fetch_one(&mut *conn),
        &mut interrupt,
    )
    .await?;
    let password = secret_column(&row, 0)?;
    drop(row);
    let mut rot = Rotation {
        role: role.to_string(),
        ..Rotation::default()
    };
    rot.set_valid_until(valid_until_after_rotation(conn, role, &mut interrupt).await);
    deliver(&rot, password, &opts, fmt, &mut interrupt).await
}

pub async fn switch_pair(
    conn: &mut PgConnection,
    pair: &str,
    opts: Delivery,
    fmt: Format,
) -> Result<()> {
    let mut interrupt = Interrupt::install();
    let row = rotation_call(
        sqlx::query(
            "SELECT active_role, password, previous_role, previous_valid_until::text \
             FROM pass_policy.switch_rotation_pair($1::text, $2::int)",
        )
        .bind(pair)
        .bind(opts.length)
        .fetch_one(&mut *conn),
        &mut interrupt,
    )
    .await?;
    let password = secret_column(&row, 1)?;
    let active = text_column(&row, 0, "the active role")?
        .ok_or_else(|| anyhow::anyhow!("the server returned no active role"))?;
    let previous_role = text_column(&row, 2, "the previous role")?;
    let previous_valid_until = text_column(&row, 3, "the end of validity of the previous role")?;
    drop(row);
    let read = valid_until_after_rotation(conn, &active, &mut interrupt).await;
    let mut rot = Rotation {
        role: active,
        pair: Some(pair.to_string()),
        previous_role,
        previous_valid_until,
        ..Rotation::default()
    };
    rot.set_valid_until(read);
    deliver(&rot, password, &opts, fmt, &mut interrupt).await
}

pub async fn lock(
    conn: &mut PgConnection,
    role: &str,
    duration: Option<Duration>,
    reason: Option<&str>,
    fmt: Format,
) -> Result<()> {
    // lock_role() returns the end of the lock (infinity for a manual lock)
    let until: Option<String> =
        sqlx::query_scalar("SELECT pass_policy.lock_role($1::name, $2::interval, $3::text)::text")
            .bind(role)
            .bind(duration.map(to_pg_interval).transpose()?)
            .bind(reason)
            .fetch_one(conn)
            .await?;
    let text = match until.as_deref() {
        Some("infinity") => format!("role \"{role}\" locked until manual unlock"),
        Some(u) => format!("role \"{role}\" locked until {u}"),
        None => format!("role \"{role}\" locked"),
    };
    print_message(
        fmt,
        &text,
        json!({"ok": true, "role": role, "locked_until": until, "reason": reason}),
    )
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
    )
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
    )
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
    ResultSet::from_rows(&rows)?.print(fmt, "no profile")
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
    print_record(&record, fmt)
}

pub async fn profile_create(
    conn: &mut PgConnection,
    name: &str,
    settings: Map<String, Value>,
    fmt: Format,
) -> Result<()> {
    let settings = Value::Object(settings);
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
    )
}

pub async fn profile_alter(
    conn: &mut PgConnection,
    name: &str,
    settings: Map<String, Value>,
    fmt: Format,
) -> Result<()> {
    let settings = Value::Object(settings);
    sqlx::query("SELECT pass_policy.alter_profile($1::text, $2::jsonb)")
        .bind(name)
        .bind(&settings)
        .execute(conn)
        .await?;
    print_message(
        fmt,
        &format!("profile \"{name}\" altered"),
        json!({"ok": true, "profile": name, "settings": settings}),
    )
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
    )
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
    )
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
    )
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
    ResultSet::from_rows(&rows)?.print(fmt, "no audit event")
}

/// Reads the candidate password of `check` (before the connection): prompted
/// without echo on a terminal, otherwise the first line of stdin.  An empty
/// password is an error.
pub fn read_candidate_password() -> Result<Secret> {
    let password = read_password()?;
    if password.is_empty() {
        bail!("empty password");
    }
    Ok(password)
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
    // Read on a duplicate of descriptor 0, unbuffered: `StdinLock` would keep
    // a copy of the password in the internal buffer of `std::io::stdin()`,
    // which is never wiped.
    let fd = stdin
        .as_fd()
        .try_clone_to_owned()
        .context("cannot read the password from stdin")?;
    let mut file = std::fs::File::from(fd);
    let regular = file.metadata().is_ok_and(|m| m.file_type().is_file());
    let line = if regular {
        read_first_line_seekable(&mut file)
    } else {
        read_first_line(&mut file)
    };
    line.context("cannot read the password from stdin")
}

/// Line being read, in a zeroised buffer that is replaced (old one wiped)
/// instead of being reallocated in place, so that no unwiped copy is left
/// behind whatever the length.
struct LineBuf(Zeroizing<Vec<u8>>);

impl LineBuf {
    fn new() -> Self {
        LineBuf(Zeroizing::new(Vec::with_capacity(256)))
    }

    fn extend(&mut self, bytes: &[u8]) {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let mut capacity = self.0.capacity().max(1);
            while capacity < needed {
                capacity *= 2;
            }
            let mut bigger = Zeroizing::new(Vec::with_capacity(capacity));
            bigger.extend_from_slice(&self.0);
            self.0 = bigger;
        }
        self.0.extend_from_slice(bytes);
    }

    /// Strips a final `\r` and converts to a [`Secret`].
    fn finish(mut self) -> std::io::Result<Secret> {
        if self.0.last() == Some(&b'\r') {
            self.0.pop();
        }
        match String::from_utf8(std::mem::take(&mut *self.0)) {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) => {
                e.into_bytes().zeroize();
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the password is not valid UTF-8",
                ))
            }
        }
    }
}

/// Reads one line byte by byte (nothing after the `\n` is consumed, so that a
/// writer that keeps its end of the pipe open does not block pgpp) and strips
/// the final `\n` / `\r\n`.  `input` must be unbuffered, or its own buffer
/// keeps a copy.  Used for pipes and terminals, which cannot seek.
fn read_first_line(input: &mut impl Read) -> std::io::Result<Secret> {
    let mut line = LineBuf::new();
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match input.read(&mut byte[..]) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.extend(&byte[..]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    line.finish()
}

/// Same as [`read_first_line`] for a regular file (`pgpp check < file`):
/// reads by blocks into a zeroised buffer, then seeks back to just after the
/// `\n`, so that the rest of the file is left unread for whoever shares the
/// descriptor, as with the byte-by-byte loop.
fn read_first_line_seekable(input: &mut (impl Read + Seek)) -> std::io::Result<Secret> {
    let mut line = LineBuf::new();
    let mut block = Zeroizing::new([0u8; 4096]);
    loop {
        let n = match input.read(&mut block[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if let Some(pos) = block[..n].iter().position(|&b| b == b'\n') {
            line.extend(&block[..pos]);
            let unread = (n - pos - 1) as i64;
            if unread > 0 {
                input.seek(SeekFrom::Current(-unread))?;
            }
            break;
        }
        line.extend(&block[..n]);
    }
    line.finish()
}

/// Keeps the candidate password out of the server log.  A bound parameter is
/// written in the DETAIL line of `log_statement = 'all'` /
/// `log_min_duration_statement` unless `log_parameter_max_length` is 0; that
/// setting is superuser-only by default, so a refusal (42501) is downgraded
/// to a warning, printed only when the value in force for the session
/// (`ALTER ROLE ... SET`, for instance) is not already 0.  The SET LOCAL runs
/// under a savepoint so that the transaction stays usable after a refusal.
/// `log_parameter_max_length_on_error` (any user may set it) is also set to
/// 0, for the case where `check_password` raises an error.
async fn mask_parameters(tx: &mut PgConnection) -> Result<()> {
    tx.execute("SET LOCAL log_parameter_max_length_on_error = 0")
        .await?;
    tx.execute("SAVEPOINT pgpp_mask").await?;
    match tx.execute("SET LOCAL log_parameter_max_length = 0").await {
        Ok(_) => {
            tx.execute("RELEASE SAVEPOINT pgpp_mask").await?;
            Ok(())
        }
        Err(e) if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("42501") => {
            tx.execute("ROLLBACK TO SAVEPOINT pgpp_mask").await?;
            let current: String =
                sqlx::query_scalar("SELECT current_setting('log_parameter_max_length')")
                    .fetch_one(&mut *tx)
                    .await?;
            if current.trim() != "0" {
                eprintln!(
                    "pgpp: warning: cannot disable parameter logging (log_parameter_max_length \
                     = {current}); the candidate password may appear in the server log if \
                     log_statement or log_min_duration_statement are enabled. Ask a superuser \
                     for \"ALTER ROLE <admin> SET log_parameter_max_length = 0\" or \
                     \"GRANT SET ON PARAMETER log_parameter_max_length TO <admin>\""
                );
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Returns the exit code: 0 when the password complies, 3 when refused
/// (1 is left to real errors so that scripts can tell them apart).
/// `password` comes from [`read_candidate_password`].
pub async fn check(
    conn: &mut PgConnection,
    role: &str,
    password: Secret,
    fmt: Format,
) -> Result<i32> {
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
    )
    .or_else(ignore_broken_pipe)?;
    Ok(code)
}

pub async fn maintenance(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let rows = sqlx::query("SELECT action, role_name, details FROM pass_policy.run_maintenance()")
        .fetch_all(conn)
        .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "maintenance run: nothing to do")
}

pub async fn failed_attempts(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let rows = sqlx::query(
        "SELECT role_name, failed_count, first_failure_at::text, last_failure_at::text, \
                locked_until::text \
         FROM pass_policy.failed_attempts() ORDER BY role_name",
    )
    .fetch_all(conn)
    .await?;
    ResultSet::from_rows(&rows)?.print(fmt, "no tracked authentication failure")
}

pub async fn worker_status(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let row = sqlx::query(
        "SELECT pid, last_run::text, last_reload::text, tracked_roles FROM pass_policy.worker_status()",
    )
    .fetch_one(conn)
    .await?;
    let record = ResultSet::from_rows(std::slice::from_ref(&row))?
        .first_record()
        .unwrap_or_default();
    print_record(&record, fmt)
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
        let mut input: &[u8] = b"\xff\xfe\n";
        assert!(read_first_line(&mut input).is_err(), "invalid UTF-8");
        // longer than the initial capacity: the buffer is replaced, not grown
        let long = "é".repeat(700);
        let data = format!("{long}\nrest");
        let mut input: &[u8] = data.as_bytes();
        assert_eq!(read_first_line(&mut input).unwrap().as_str(), long);
        assert_eq!(input, b"rest");
    }

    #[test]
    fn reads_only_the_first_line_of_a_seekable_input() {
        use std::io::Cursor;
        let read = |data: &[u8]| {
            let mut c = Cursor::new(data.to_vec());
            let line = read_first_line_seekable(&mut c).ok().map(|s| s.to_string());
            (line, c.position() as usize)
        };
        assert_eq!(read(b"first\r\nsecond\n"), (Some("first".into()), 7));
        assert_eq!(read(b"pw\n").0.unwrap(), "pw");
        assert_eq!(read(b"no-newline"), (Some("no-newline".into()), 10));
        assert_eq!(read(b"").0.unwrap(), "");
        assert_eq!(read(b"\nnext"), (Some(String::new()), 1));
        assert!(read(b"\xff\xfe\n").0.is_none(), "invalid UTF-8");
        // longer than a block and than the initial capacity
        let long = "é".repeat(3000);
        let data = format!("{long}\nrest");
        let (line, pos) = read(data.as_bytes());
        assert_eq!(line.unwrap(), long);
        assert_eq!(
            &data.as_bytes()[pos..],
            b"rest",
            "seeks back after the newline"
        );
    }

    #[test]
    fn regular_file_on_stdin_is_left_after_the_first_line() {
        let path = std::env::temp_dir().join(format!("pgpp-stdin-{}.txt", std::process::id()));
        std::fs::write(&path, "pw-line\nsecond line\n").unwrap();
        let mut f = std::fs::File::open(&path).unwrap();
        assert_eq!(
            read_first_line_seekable(&mut f).unwrap().as_str(),
            "pw-line"
        );
        let mut rest = String::new();
        f.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "second line\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_tells_an_unknown_valid_until_from_an_unbounded_one() {
        let json_of = |read: Option<Option<String>>| {
            let mut rot = Rotation {
                role: "app".into(),
                ..Rotation::default()
            };
            rot.set_valid_until(read);
            let out = RotationOutput {
                rotation: &rot,
                delivered_to: &["exec"],
                password: None,
            };
            (
                serde_json::to_value(&out).unwrap(),
                rot.valid_until_env().map(str::to_string),
            )
        };
        let (bounded, env) = json_of(Some(Some("2027-01-01 00:00:00+00".into())));
        assert_eq!(bounded["valid_until"], "2027-01-01 00:00:00+00");
        assert_eq!(bounded["valid_until_known"], true);
        assert_eq!(env.as_deref(), Some("2027-01-01 00:00:00+00"));
        let (unbounded, env) = json_of(Some(None));
        assert!(unbounded["valid_until"].is_null());
        assert_eq!(unbounded["valid_until_known"], true);
        assert_eq!(env.as_deref(), Some(""));
        let (unknown, env) = json_of(None);
        assert!(unknown["valid_until"].is_null());
        assert_eq!(unknown["valid_until_known"], false);
        assert_eq!(env, None);
        assert!(unknown.get("password").is_none());
    }

    #[test]
    fn table_shows_an_unknown_valid_until() {
        let display = |read: Option<Option<String>>| {
            let mut rot = Rotation::default();
            rot.set_valid_until(read);
            rot.valid_until_display().to_string()
        };
        assert_eq!(display(Some(Some("infinity".into()))), "infinity");
        assert_eq!(display(Some(None)), "", "unbounded");
        assert_eq!(display(None), "(unknown)", "read failed");
    }

    #[test]
    fn only_text_columns_are_read_as_a_password() {
        use sqlx::{Postgres, Type};
        // (`with_oid` cannot be used here: sqlx matches it with any type
        // declared by name, citext included)
        check_text_type(&<String as Type<Postgres>>::type_info()).unwrap();
        for name in ["varchar", "name", "bpchar"] {
            check_text_type(&PgTypeInfo::with_name(name))
                .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        }
        for ty in [
            <i32 as Type<Postgres>>::type_info(),
            <Vec<u8> as Type<Postgres>>::type_info(),
            <Value as Type<Postgres>>::type_info(),
        ] {
            let err = check_text_type(&ty).unwrap_err();
            assert!(
                format!("{err:#}").contains("text expected"),
                "{ty}: {err:#}"
            );
        }
    }

    /// Same check on values sent by a real server (PGPP_TEST_URL).
    #[tokio::test]
    #[ignore = "needs PGPP_TEST_URL"]
    async fn secret_column_checks_the_type_sent_by_the_server() {
        use sqlx::Connection;
        let url = std::env::var("PGPP_TEST_URL").expect("PGPP_TEST_URL must be set");
        let mut conn = PgConnection::connect(&url).await.unwrap();
        let row = sqlx::query("SELECT 'pw'::text, 'pw'::varchar, 'pw'::name, 42, '\\x7077'::bytea")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        for i in 0..3 {
            assert_eq!(secret_column(&row, i).unwrap().as_str(), "pw", "column {i}");
        }
        for i in 3..5 {
            let err = secret_column(&row, i).unwrap_err();
            assert!(
                format!("{err:#}").contains("text expected"),
                "column {i}: {err:#}"
            );
        }
    }

    /// The columns of `switch_rotation_pair` are decoded without panicking
    /// (PGPP_TEST_URL): NULL, text, and a type that is not text.
    #[tokio::test]
    #[ignore = "needs PGPP_TEST_URL"]
    async fn text_columns_are_decoded_without_panicking() {
        use sqlx::Connection;
        let url = std::env::var("PGPP_TEST_URL").expect("PGPP_TEST_URL must be set");
        let mut conn = PgConnection::connect(&url).await.unwrap();
        let row = sqlx::query("SELECT NULL::text, 'r'::text, 42")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(text_column(&row, 0, "the active role").unwrap(), None);
        assert_eq!(
            text_column(&row, 1, "the active role").unwrap().as_deref(),
            Some("r")
        );
        let err = text_column(&row, 2, "the previous role").unwrap_err();
        assert!(
            format!("{err:#}").starts_with("cannot read the previous role: "),
            "{err:#}"
        );
        let err = text_column(&row, 9, "the previous role").unwrap_err();
        assert!(format!("{err:#}").starts_with("cannot read the previous role"));
    }

    #[test]
    fn json_output_with_the_password_is_serialised_at_its_exact_size() {
        let mut rot = Rotation {
            role: "app".into(),
            ..Rotation::default()
        };
        rot.set_valid_until(None);
        let password = "pw-é\"x".repeat(100);
        let out = RotationOutput {
            rotation: &rot,
            delivered_to: &["exec", "vault"],
            password: Some(&password),
        };
        // the line actually printed: JSON text and newline in one exact-size
        // allocation (a push after the fact would reallocate)
        let text = vault::zeroizing_json_line(&out).unwrap();
        assert_eq!(text.capacity(), text.len(), "no reallocation");
        let mut expected = serde_json::to_vec(&out).unwrap();
        expected.push(b'\n');
        assert_eq!(text.as_slice(), expected.as_slice());
        let v: Value = serde_json::from_slice(&text).unwrap();
        assert_eq!(v["password"], password.as_str());
        assert_eq!(v["valid_until_known"], false);
    }
}
