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
use crate::output::{
    is_broken_pipe, map_stdout_error, print_message, print_record, write_line, Format, ResultSet,
};
use crate::secret::{check_shell, run_exec, Interrupt, Secret, SigintGuard};
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
    let Some(row) = row else {
        return Ok(None);
    };
    row.try_get::<Option<String>, _>(0)
        .context("cannot read rolvaliduntil")
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
                // PGPP_VAULT_SKIP_PREFLIGHT is only validated when it matters
                let skip_preflight = opts
                    .vault_skip_preflight
                    .get()
                    .map_err(|e| PrepareError::Invalid(anyhow::anyhow!(e)))?;
                let target = VaultTarget::parse(kv, opts.vault_mount.as_deref())
                    .map_err(PrepareError::Invalid)?;
                if opts.vault_mount.is_some() {
                    if let Some(w) = target.repeated_mount_warning() {
                        crate::warn(&w);
                    }
                }
                let cfg = VaultConfig::from_env().map_err(PrepareError::Invalid)?;
                Some((cfg, target, skip_preflight))
            }
            None => None,
        };
        if opts.exec.is_some() {
            check_shell().map_err(PrepareError::Invalid)?;
        }
        if let Some((cfg, target, skip_preflight)) = &vault {
            if *skip_preflight {
                crate::warn(
                    "Vault preflight skipped (--vault-skip-preflight): \
                     VAULT_TOKEN and its permission on the path are only checked by the \
                     write, after the rotation",
                );
            } else {
                let warnings = vault::preflight(cfg, target)
                    .await
                    .map_err(PrepareError::Preflight)?;
                for w in warnings {
                    crate::warn(&w);
                }
            }
        }
        Ok(Delivery {
            length: opts.length,
            show: opts.show,
            exec: opts.exec.clone(),
            exec_timeout: opts.exec_timeout.0,
            vault: vault.map(|(cfg, target, _)| (cfg, target)),
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
    /// failed deliveries (`exec`, `vault`), empty when everything went well
    failed: &'a [&'a str],
    /// what to do after a failed delivery (text of [`retry_advice`]), null
    /// when nothing failed or when the password is printed (`--show`) and
    /// not in Vault: see [`advice`]
    advice: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
}

/// Delivers a new password according to `--show`, `--exec` and `--vault-kv`.
///
/// Policy: the password is printed only with `--show`; clap refuses a
/// rotation without any of the three options before anything is rotated.  If
/// a delivery (`--exec`, Vault) fails after the rotation, the password is NOT
/// printed unless `--show` was given: the caller must rotate again, unless
/// the password reached Vault (see [`retry_advice`]).
///
/// A Ctrl-C ([`Interrupt`]) received before or during a delivery makes it
/// fail (the Vault write or the `--exec` command in progress is abandoned,
/// a delivery still to come is not attempted): it ends like any other
/// failed delivery, with exit code 1 and the advice of [`retry_advice`].
async fn deliver(
    rot: &Rotation,
    password: Secret,
    opts: &Delivery,
    fmt: Format,
    interrupt: &mut Interrupt,
) -> Result<()> {
    let mut delivered: Vec<&str> = Vec::new();
    let mut failed: Vec<&str> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    // failed Vault write that may have reached Vault all the same
    let mut vault_unknown = false;

    if let Some((cfg, target)) = &opts.vault {
        match vault_delivery(cfg, target, &rot.role, &password, interrupt).await {
            Ok(()) => delivered.push("vault"),
            Err(f) => {
                failed.push("vault");
                vault_unknown = f.unknown;
                failures.push(f.message);
            }
        }
    }

    if let Some(cmd) = &opts.exec {
        // a Ctrl-C delivered since the Vault write ended (no wait was in
        // progress) is taken here, before the command is started
        if interrupt.poll_received().await {
            failed.push("exec");
            failures.push(format!(
                "--exec delivery not attempted: interrupted (Ctrl-C); command: {cmd}"
            ));
        } else {
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
                Err(e) => {
                    failed.push("exec");
                    failures.push(format!("--exec delivery failed: {e:#}"));
                }
            }
        }
    }

    for f in &failures {
        crate::report_text(crate::Report::Error, f);
    }
    let outcome = Outcome {
        delivered: &delivered,
        failed: &failed,
        vault_unknown,
    };
    let printed = print_rotation(rot, &password, &outcome, opts.show, fmt);
    drop(password);
    delivery_outcome(&outcome, opts.show, printed)
}

/// Deliveries of a rotation: those that succeeded, those that failed, and
/// whether a failed Vault write may have been received by Vault all the
/// same (`vault_unknown`: no answer, connection lost while waiting for it,
/// Ctrl-C during the request).
#[derive(Clone, Copy)]
struct Outcome<'a> {
    delivered: &'a [&'a str],
    failed: &'a [&'a str],
    vault_unknown: bool,
}

/// What to do after a failed delivery (`failed` not empty), for a
/// password that is not shown.  Once in Vault, the password is not lost:
/// rotating again would only replace a delivered secret (and run the
/// failed `--exec` again with another password); the failed delivery is to
/// be completed from Vault.  When the Vault write failed after the request
/// was sent (`vault_unknown`), the password may be in Vault: check it before
/// rotating again.  Otherwise the password is lost (or only held by the
/// `--exec` command): rotate again.
fn retry_advice(o: &Outcome) -> String {
    let unknown = "the secret may or may not have been written: check Vault before rotating \
                   again";
    if o.delivered.is_empty() {
        return if o.vault_unknown {
            unknown.to_string()
        } else {
            "nothing delivered: rotate again".to_string()
        };
    }
    let what = format!(
        "delivered to {}, {} failed",
        o.delivered.join(", "),
        o.failed.join(", ")
    );
    if o.delivered.contains(&"vault") {
        format!("{what}: the password is in Vault, do not rotate again")
    } else if o.vault_unknown {
        format!("{what}: {unknown}")
    } else {
        format!("{what}: rotate again")
    }
}

/// Advice printed with the outcome of a rotation ([`retry_advice`]): none
/// when nothing failed, nor when the password is printed (`--show`) without
/// being in Vault (the printed password is then the one to deliver by hand).
fn advice(o: &Outcome, show: bool) -> Option<String> {
    (!o.failed.is_empty() && (!show || o.delivered.contains(&"vault"))).then(|| retry_advice(o))
}

/// Failed Vault delivery: message, and whether the secret may have been
/// written all the same.
#[derive(Debug, PartialEq)]
struct VaultFailure {
    message: String,
    unknown: bool,
}

/// Writes the secret to Vault, the failure otherwise.  A Ctrl-C received
/// before the request is polled for the first time means the request was
/// never sent (« not attempted »); one received while it runs abandons it,
/// and the secret may or may not have been written, as after an error
/// raised once the request was sent (no answer within the timeout,
/// connection lost while waiting for it: [`vault::may_have_been_received`]).
/// An error before the request was sent (DNS, connection refused) or an
/// answer of Vault (HTTP status) means nothing was written.
async fn vault_delivery(
    cfg: &VaultConfig,
    target: &VaultTarget,
    role: &str,
    password: &Secret,
    interrupt: &mut Interrupt,
) -> std::result::Result<(), VaultFailure> {
    let rotated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut payload = build_payload(role, password, &rotated_at);
    let started = std::cell::Cell::new(false);
    let result = {
        let write = async {
            started.set(true);
            write_secret(cfg, target, &payload).await
        };
        // biased: a Ctrl-C already received wins before the request starts
        tokio::select! {
            biased;
            () = interrupt.wait() => None,
            r = write => Some(r),
        }
    };
    // wipe the copy of the password held by the JSON payload
    if let Some(Value::String(s)) = payload.pointer_mut("/data/password") {
        s.zeroize();
    }
    let unknown = "the secret may or may not have been written";
    match result {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) if vault::may_have_been_received(&e) => Err(VaultFailure {
            message: format!("Vault delivery failed: {e:#}; {unknown}"),
            unknown: true,
        }),
        Some(Err(e)) => Err(VaultFailure {
            message: format!("Vault delivery failed: {e:#}"),
            unknown: false,
        }),
        None if !started.get() => Err(VaultFailure {
            message: "Vault delivery not attempted: interrupted (Ctrl-C)".to_string(),
            unknown: false,
        }),
        None => Err(VaultFailure {
            message: format!("Vault delivery failed: interrupted (Ctrl-C); {unknown}"),
            unknown: true,
        }),
    }
}

/// Result of a rotation once the deliveries are done (to the channels of
/// `delivered`, not to those of `failed`) and the outcome printed
/// (`printed`).  A failed delivery ends with the advice of
/// [`retry_advice`] (« do not rotate again » once the password is in
/// Vault, « rotate again » otherwise) unless the password was printed.  With `--show` the standard output is a delivery too: its
/// failure is reported (never silenced as a closed pipe, which would exit
/// with 0) when it was the only delivery or when another one failed.
/// Without `--show`, a print failure other than a closed pipe after a
/// failed delivery is added to the error (a full disk must not go unseen).
/// After successful deliveries, such a failure says that the password was
/// rotated and where it was delivered.
fn delivery_outcome(o: &Outcome, show: bool, printed: Result<()>) -> Result<()> {
    let Outcome {
        delivered, failed, ..
    } = *o;
    let failures = failed.len();
    if failures > 0 {
        let advice = retry_advice(o);
        match printed {
            Err(e) if show => {
                let cause = if is_broken_pipe(&e) {
                    "the standard output was closed".to_string()
                } else {
                    format!("{e:#}")
                };
                bail!(
                    "password rotated but {failures} delivery error(s) occurred and the \
                     password could not be printed ({cause}); {advice}"
                )
            }
            Err(e) if !is_broken_pipe(&e) => bail!(
                "password rotated but {failures} delivery error(s) occurred (and the \
                 outcome could not be printed: {e:#}); {advice}"
            ),
            // printed with --show: the password is on the standard output
            _ if show && !delivered.contains(&"vault") => {
                bail!("password rotated but {failures} delivery error(s) occurred")
            }
            _ => bail!("password rotated but {failures} delivery error(s) occurred; {advice}"),
        }
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
        // delivered elsewhere: a closed pipe stays quiet (exit 0), another
        // print failure says that the password is not lost and where it is
        Err(e) if !is_broken_pipe(&e) => Err(e.context(format!(
            "password rotated and delivered to {}; the result could not be printed",
            delivered.join(", ")
        ))),
        other => other,
    }
}

/// Prints the outcome of a rotation (and the password with `--show`).
fn print_rotation(
    rot: &Rotation,
    password: &Secret,
    o: &Outcome,
    show: bool,
    fmt: Format,
) -> Result<()> {
    let Outcome {
        delivered, failed, ..
    } = *o;
    match fmt {
        Format::Json => {
            let out = RotationOutput {
                rotation: rot,
                delivered_to: delivered,
                failed,
                advice: advice(o, show),
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
            } else if failed.is_empty() {
                write_line("password: (not shown; use --show to print it)")
            } else {
                write_line(format_args!("password: (not shown; {})", retry_advice(o)))
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
    written.map_err(map_stdout_error)
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

/// Error reading the row returned by a rotation: the new password is
/// already committed on the server but pgpp does not have it (or not the
/// role it belongs to), so it is lost.
fn read_after_rotation<T>(read: Result<T>) -> Result<T> {
    read.map_err(|e| {
        anyhow::anyhow!(
            "the password was changed on the server but the result of the rotation could \
             not be read ({}): the new password is lost, rotate again",
            crate::format_error(&e)
        )
    })
}

/// Decodes column `index` of a row returned by a function of the
/// extension: a missing column or a type other than expected (another
/// version of pg_pass_policy) is an error, not a panic of `Row::get`.
fn column<'r, T>(row: &'r PgRow, index: usize, what: &str) -> Result<T>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get::<T, _>(index)
        .with_context(|| format!("cannot read {what} (incompatible extension version?)"))
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
    let password = read_after_rotation(secret_column(&row, 0))?;
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
    let (password, active, previous_role, previous_valid_until) = read_after_rotation((|| {
        let password = secret_column(&row, 1)?;
        let active = column::<Option<String>>(&row, 0, "the active role")?
            .ok_or_else(|| anyhow::anyhow!("the server returned no active role"))?;
        let previous_role = column::<Option<String>>(&row, 2, "the previous role")?;
        let previous_valid_until =
            column::<Option<String>>(&row, 3, "the end of validity of the previous role")?;
        Ok((password, active, previous_role, previous_valid_until))
    })())?;
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
    let value: Value = column(&row, 0, "the profile")?;
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
    let row = sqlx::query("SELECT pass_policy.create_profile($1::text, $2::jsonb)")
        .bind(name)
        .bind(&settings)
        .fetch_one(conn)
        .await?;
    let id: i32 = column(&row, 0, "the id of the new profile")?;
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
        crate::output::write_stderr("Password to check: ", false);
        // rpassword puts the terminal in raw mode (no echo, no ISIG) and
        // turns a typed Ctrl-C into `raise(SIGINT)` before restoring the
        // terminal settings (in a Drop): with the default action, pgpp
        // would die with the echo still off.  The guard catches SIGINT for
        // the duration of the prompt, so that rpassword returns and
        // restores the terminal; the Ctrl-C is then replayed below with the
        // previous disposition.
        //
        // The terminal read is the one of descriptor 0 (the one tested
        // above), reopened through /dev/stdin, not /dev/tty (the default of
        // rpassword): the controlling terminal may be missing (`setsid`,
        // some schedulers or containers: ENXIO) or be another terminal than
        // the standard input.  The end of line echoed after the password
        // (and after a Ctrl-C) goes to the standard error, like the prompt.
        let guard = SigintGuard::install();
        let config = rpassword::ConfigBuilder::new()
            .input_file_path(STDIN_TERMINAL_PATH)
            .output_writer(std::io::stderr())
            .build();
        let read = rpassword::read_password_with_config(config).map(Zeroizing::new);
        let interrupted = guard.received()
            || matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::Interrupted);
        drop(guard);
        if interrupted {
            drop(read);
            // SAFETY: plain system call; the previous disposition of SIGINT
            // (default: terminate) is back in force.
            unsafe {
                libc::raise(libc::SIGINT);
            }
            bail!("interrupted (Ctrl-C)");
        }
        let pw = read.context("cannot read the password")?;
        if pw.len() > MAX_CANDIDATE_BYTES {
            return Err(too_long().into());
        }
        return Ok(pw);
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

/// Path through which the terminal of descriptor 0 is reopened for the
/// prompt of `check` (rpassword only switches off the echo of a terminal it
/// opens by path).
const STDIN_TERMINAL_PATH: &str = "/dev/stdin";

/// Longest candidate password accepted by `check` (the server refuses
/// passwords longer than 1024 characters anyway): past it, the input is a
/// usage error instead of an unbounded read into memory.
const MAX_CANDIDATE_BYTES: usize = 4096;

fn too_long() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("the password is longer than {MAX_CANDIDATE_BYTES} bytes"),
    )
}

/// Line being read, in a zeroised buffer that is replaced (old one wiped)
/// instead of being reallocated in place, so that no unwiped copy is left
/// behind whatever the length.
struct LineBuf(Zeroizing<Vec<u8>>);

impl LineBuf {
    fn new() -> Self {
        LineBuf(Zeroizing::new(Vec::with_capacity(256)))
    }

    /// Appends `bytes`; refuses a line longer than [`MAX_CANDIDATE_BYTES`]
    /// (one more byte is allowed for a final `\r`, checked by
    /// [`LineBuf::finish`]).  The bytes already read are wiped when the
    /// buffer is dropped.
    fn extend(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let needed = self.0.len() + bytes.len();
        if needed > MAX_CANDIDATE_BYTES + 1 {
            return Err(too_long());
        }
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
        Ok(())
    }

    /// Strips a final `\r` and converts to a [`Secret`].
    fn finish(mut self) -> std::io::Result<Secret> {
        if self.0.last() == Some(&b'\r') {
            self.0.pop();
        }
        if self.0.len() > MAX_CANDIDATE_BYTES {
            return Err(too_long());
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
            Ok(_) => line.extend(&byte[..])?,
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
            line.extend(&block[..pos])?;
            let unread = (n - pos - 1) as i64;
            if unread > 0 {
                input.seek(SeekFrom::Current(-unread))?;
            }
            break;
        }
        line.extend(&block[..n])?;
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
            let (current, version): (String, i32) = sqlx::query_as(
                "SELECT current_setting('log_parameter_max_length'), \
                        current_setting('server_version_num')::int",
            )
            .fetch_one(&mut *tx)
            .await?;
            if let Some(w) = unmasked_parameters_warning(&current, version) {
                crate::warn(&w);
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Warning of [`mask_parameters`] when `log_parameter_max_length` could not
/// be set and the value in force (`current`) is not 0.  `GRANT SET ON
/// PARAMETER` exists from PostgreSQL 15 on (`server_version_num` 150000):
/// it is only suggested from that version on.
fn unmasked_parameters_warning(current: &str, server_version_num: i32) -> Option<String> {
    if current.trim() == "0" {
        return None;
    }
    let grant = if server_version_num >= 150_000 {
        " or \"GRANT SET ON PARAMETER log_parameter_max_length TO <admin>\""
    } else {
        ""
    };
    Some(format!(
        "cannot disable parameter logging (log_parameter_max_length = {current}); the \
         candidate password may appear in the server log if log_statement or \
         log_min_duration_statement are enabled. Ask a superuser for \
         \"ALTER ROLE <admin> SET log_parameter_max_length = 0\"{grant}"
    ))
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
    let reason: Option<String> = column(&row, 0, "the result of check_password")?;
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

/// `worker_status()`, columns read by name.  `locks_loaded` (start-up
/// window closed, the locks are loaded) is read through `to_jsonb(w)`: an
/// extension that does not return it yet gives NULL instead of an error.
pub async fn worker_status(conn: &mut PgConnection, fmt: Format) -> Result<()> {
    let row = sqlx::query(
        "SELECT w.pid, w.last_run::text AS last_run, w.last_reload::text AS last_reload, \
                w.tracked_roles, to_jsonb(w) -> 'locks_loaded' AS locks_loaded \
           FROM pass_policy.worker_status() w",
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

    /// Deliveries without a Vault write of unknown outcome.
    fn o<'a>(delivered: &'a [&'a str], failed: &'a [&'a str]) -> Outcome<'a> {
        Outcome {
            delivered,
            failed,
            vault_unknown: false,
        }
    }

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
        // longer than a block and than the initial capacity, and exactly
        // at the limit (4096 bytes)
        let long = "é".repeat(2048);
        let data = format!("{long}\nrest");
        let (line, pos) = read(data.as_bytes());
        assert_eq!(line.unwrap(), long);
        assert_eq!(
            &data.as_bytes()[pos..],
            b"rest",
            "seeks back after the newline"
        );
    }

    /// A candidate longer than 4 KiB is refused (usage error of `check`)
    /// instead of being read without bound, by both readers; 4096 bytes
    /// (plus a final `\r`) are accepted.
    #[test]
    fn a_candidate_longer_than_4_kib_is_refused() {
        use std::io::Cursor;
        let at_limit = "a".repeat(MAX_CANDIDATE_BYTES);
        let over = "a".repeat(MAX_CANDIDATE_BYTES + 1);
        for (data, ok) in [
            (format!("{at_limit}\n"), true),
            (format!("{at_limit}\r\n"), true),
            (at_limit.clone(), true),
            (format!("{over}\n"), false),
            (format!("{at_limit}a\r\n"), false),
            ("a".repeat(1 << 20), false),
        ] {
            let mut input: &[u8] = data.as_bytes();
            let r = read_first_line(&mut input);
            let mut c = Cursor::new(data.as_bytes().to_vec());
            let s = read_first_line_seekable(&mut c);
            for (kind, r) in [("pipe", r), ("file", s)] {
                match r {
                    Ok(pw) => {
                        assert!(ok, "{kind}: accepted {} bytes", data.len());
                        assert_eq!(pw.as_str(), at_limit, "{kind}");
                    }
                    Err(e) => {
                        assert!(!ok, "{kind}: {e}");
                        assert!(e.to_string().contains("longer than 4096 bytes"), "{e}");
                    }
                }
            }
        }
        // the pipe reader stops at the limit: the rest is not consumed
        let data = "a".repeat(10_000);
        let mut input: &[u8] = data.as_bytes();
        assert!(read_first_line(&mut input).is_err());
        assert_eq!(input.len(), 10_000 - MAX_CANDIDATE_BYTES - 2);
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
                failed: &[],
                advice: None,
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
            let err = read_after_rotation(secret_column(&row, i)).unwrap_err();
            let m = format!("{err:#}");
            assert!(m.contains("changed on the server"), "column {i}: {m}");
            assert!(m.contains("text expected"), "column {i}: {m}");
            assert!(m.ends_with("is lost, rotate again"), "column {i}: {m}");
        }
    }

    /// A Ctrl-C received before the Vault write: the request is never sent
    /// (no server listens on the address), the message says so.
    #[tokio::test]
    async fn a_vault_write_after_a_ctrl_c_is_not_attempted() {
        let cfg = VaultConfig::new("http://127.0.0.1:9", "t", None).unwrap();
        let target = VaultTarget::parse("secret/db/app", None).unwrap();
        let mut interrupt = Interrupt::already_received();
        let password = Zeroizing::new("pw".to_string());
        let err = vault_delivery(&cfg, &target, "app", &password, &mut interrupt)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            VaultFailure {
                message: "Vault delivery not attempted: interrupted (Ctrl-C)".to_string(),
                unknown: false,
            }
        );
    }

    /// A Vault write that fails before the request is sent (connection
    /// refused) wrote nothing; one that fails after (no answer within the
    /// timeout: the server got the request) may have written the secret,
    /// and the advice asks to check Vault rather than to rotate again.
    #[tokio::test]
    async fn a_vault_failure_after_the_request_was_sent_asks_to_check_vault() {
        let target = VaultTarget::parse("secret/db/app", None).unwrap();
        let password = Zeroizing::new("pw".to_string());
        let mut interrupt = Interrupt::never();
        let refused = VaultConfig::new("http://127.0.0.1:9", "t", None).unwrap();
        let err = vault_delivery(&refused, &target, "app", &password, &mut interrupt)
            .await
            .unwrap_err();
        assert!(!err.unknown, "{err:?}");
        assert!(
            err.message.starts_with("Vault delivery failed: "),
            "{err:?}"
        );
        assert!(!err.message.contains("may or may not"), "{err:?}");

        let server = httpmock::MockServer::start_async().await;
        let slow = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST)
                    .path("/v1/secret/data/db/app");
                then.status(200)
                    .delay(Duration::from_secs(3))
                    .json_body(json!({"data": {"version": 1}}));
            })
            .await;
        let cfg = VaultConfig::new(server.base_url(), "t", None)
            .unwrap()
            .with_timeout(Duration::from_millis(300));
        let err = vault_delivery(&cfg, &target, "app", &password, &mut interrupt)
            .await
            .unwrap_err();
        assert_eq!(slow.hits_async().await, 1);
        assert!(err.unknown, "{err:?}");
        assert!(
            err.message
                .ends_with("; the secret may or may not have been written"),
            "{err:?}"
        );
        let uncertain = |delivered| Outcome {
            delivered,
            failed: &["vault"],
            vault_unknown: true,
        };
        let check =
            "the secret may or may not have been written: check Vault before rotating again";
        assert_eq!(retry_advice(&uncertain(&[])), check);
        assert_eq!(
            retry_advice(&uncertain(&["exec"])),
            format!("delivered to exec, vault failed: {check}")
        );
        let m = format!(
            "{:#}",
            delivery_outcome(&uncertain(&[]), false, Ok(())).unwrap_err()
        );
        assert_eq!(
            m,
            format!("password rotated but 1 delivery error(s) occurred; {check}")
        );
    }

    #[test]
    fn grant_set_on_parameter_is_suggested_from_postgresql_15_on() {
        assert_eq!(unmasked_parameters_warning("0", 160004), None);
        assert_eq!(unmasked_parameters_warning(" 0 ", 140010), None);
        let alter = "\"ALTER ROLE <admin> SET log_parameter_max_length = 0\"";
        let grant = "GRANT SET ON PARAMETER";
        for version in [150000, 160004, 170000] {
            let w = unmasked_parameters_warning("-1", version).unwrap();
            assert!(w.contains("log_parameter_max_length = -1"), "{w}");
            assert!(w.contains(alter) && w.contains(grant), "{version}: {w}");
        }
        for version in [140010, 149999, 130000] {
            let w = unmasked_parameters_warning("64", version).unwrap();
            assert!(w.ends_with(alter), "{version}: {w}");
            assert!(!w.contains(grant), "{version}: {w}");
        }
    }

    #[test]
    fn a_print_failure_after_a_failed_delivery_is_reported() {
        let closed = || Err(anyhow::Error::new(crate::output::BrokenPipe));
        let other = || Err(anyhow::anyhow!("disk full"));
        let msg = |r: Result<()>| {
            let e = r.unwrap_err();
            assert!(!is_broken_pipe(&e), "must not exit quietly with 0: {e:#}");
            format!("{e:#}")
        };
        let none: &[&str] = &[];
        // --show, a delivery failed and the password could not be printed
        let m = msg(delivery_outcome(&o(none, &["exec"]), true, closed()));
        assert!(m.contains("1 delivery error(s)"), "{m}");
        assert!(
            m.contains("password could not be printed (the standard output was closed)"),
            "{m}"
        );
        assert!(m.ends_with("nothing delivered: rotate again"), "{m}");
        let m = msg(delivery_outcome(&o(&["vault"], &["exec"]), true, other()));
        assert!(m.contains("could not be printed (disk full)"), "{m}");
        assert!(m.ends_with("do not rotate again"), "{m}");
        // printed with --show: the delivery error alone
        let m = msg(delivery_outcome(&o(&["exec"], &["vault"]), true, Ok(())));
        assert_eq!(m, "password rotated but 1 delivery error(s) occurred");
        let m = msg(delivery_outcome(&o(none, &["vault", "exec"]), true, Ok(())));
        assert_eq!(m, "password rotated but 2 delivery error(s) occurred");
        // not shown: the advice says whether to rotate again
        let m = msg(delivery_outcome(&o(none, &["exec"]), false, closed()));
        assert_eq!(
            m,
            "password rotated but 1 delivery error(s) occurred; nothing delivered: rotate again"
        );
        let m = msg(delivery_outcome(&o(&["exec"], &["vault"]), false, Ok(())));
        assert_eq!(
            m,
            "password rotated but 1 delivery error(s) occurred; delivered to exec, vault \
             failed: rotate again"
        );
        // in Vault, the password is not lost: shown or not, no new rotation
        for show in [false, true] {
            let m = msg(delivery_outcome(&o(&["vault"], &["exec"]), show, Ok(())));
            assert_eq!(
                m,
                "password rotated but 1 delivery error(s) occurred; delivered to vault, exec \
                 failed: the password is in Vault, do not rotate again"
            );
        }
        // not shown: another print failure is kept in the message
        let m = msg(delivery_outcome(&o(none, &["exec"]), false, other()));
        assert_eq!(
            m,
            "password rotated but 1 delivery error(s) occurred (and the outcome could not \
             be printed: disk full); nothing delivered: rotate again"
        );
        // no delivery error
        assert!(delivery_outcome(&o(&["exec"], none), true, Ok(())).is_ok());
        let m = msg(delivery_outcome(&o(none, none), true, closed()));
        assert!(m.contains("could not be printed"), "{m}");
        // delivered elsewhere: a closed stdout stays a quiet broken pipe
        let e = delivery_outcome(&o(&["exec"], none), true, closed()).unwrap_err();
        assert!(is_broken_pipe(&e));
        let e = delivery_outcome(&o(&["vault"], none), false, closed()).unwrap_err();
        assert!(is_broken_pipe(&e));
    }

    /// Deliveries done but the outcome not printed (other than a closed
    /// pipe): the message says that the password was rotated and where it
    /// is, shown or not.
    #[test]
    fn a_print_failure_after_successful_deliveries_says_where_the_password_is() {
        let none: &[&str] = &[];
        let other = || Err(anyhow::anyhow!("disk full"));
        for show in [false, true] {
            let e = delivery_outcome(&o(&["vault"], none), show, other()).unwrap_err();
            assert!(!is_broken_pipe(&e));
            assert_eq!(
                crate::format_error(&e),
                "password rotated and delivered to vault; the result could not be printed: \
                 disk full"
            );
        }
        let e = delivery_outcome(&o(&["vault", "exec"], none), false, other()).unwrap_err();
        assert_eq!(
            crate::format_error(&e),
            "password rotated and delivered to vault, exec; the result could not be printed: \
             disk full"
        );
    }

    /// A failure to read the row of a rotation says that the password was
    /// changed on the server and is lost.
    #[test]
    fn a_failed_read_after_the_rotation_says_the_password_is_lost() {
        let e = read_after_rotation::<()>(Err(
            anyhow::anyhow!("text expected").context("cannot read the generated password")
        ))
        .unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "the password was changed on the server but the result of the rotation could not \
             be read (cannot read the generated password: text expected): the new password \
             is lost, rotate again"
        );
        assert_eq!(read_after_rotation(Ok(7)).unwrap(), 7);
    }

    /// JSON output: `failed` lists the failed deliveries and `advice` holds
    /// the text of `retry_advice` (null when nothing failed, or when the
    /// printed password is not in Vault).
    #[test]
    fn json_lists_failed_deliveries_with_the_advice() {
        let rot = Rotation {
            role: "app".into(),
            ..Rotation::default()
        };
        let json_of = |delivered: &[&str], failed: &[&str], show: bool| {
            let out = RotationOutput {
                rotation: &rot,
                delivered_to: delivered,
                failed,
                advice: advice(&o(delivered, failed), show),
                password: show.then_some("pw"),
            };
            serde_json::to_value(&out).unwrap()
        };
        let none: &[&str] = &[];
        let ok = json_of(&["vault"], none, false);
        assert_eq!(ok["failed"], json!([]));
        assert!(ok["advice"].is_null(), "{ok}");
        let v = json_of(&["vault"], &["exec"], false);
        assert_eq!(v["delivered_to"], json!(["vault"]));
        assert_eq!(v["failed"], json!(["exec"]));
        assert_eq!(v["advice"], retry_advice(&o(&["vault"], &["exec"])));
        assert_eq!(
            v["advice"],
            "delivered to vault, exec failed: the password is in Vault, do not rotate again"
        );
        let v = json_of(none, &["vault", "exec"], false);
        assert_eq!(v["failed"], json!(["vault", "exec"]));
        assert_eq!(v["advice"], "nothing delivered: rotate again");
        // with --show: the advice only when the password is in Vault
        let v = json_of(&["vault"], &["exec"], true);
        assert_eq!(v["advice"], retry_advice(&o(&["vault"], &["exec"])));
        let v = json_of(&["exec"], &["vault"], true);
        assert_eq!(v["failed"], json!(["vault"]));
        assert!(v["advice"].is_null(), "{v}");
        assert_eq!(v["password"], "pw");
    }

    /// Columns read with [`column`] (profile show / create, check, the
    /// optional text columns of switch-pair) are decoded without panicking
    /// (PGPP_TEST_URL).
    #[tokio::test]
    #[ignore = "needs PGPP_TEST_URL"]
    async fn extension_columns_are_decoded_without_panicking() {
        use sqlx::Connection;
        let url = std::env::var("PGPP_TEST_URL").expect("PGPP_TEST_URL must be set");
        let mut conn = PgConnection::connect(&url).await.unwrap();
        let row = sqlx::query("SELECT 42, 'x'::text, '{\"a\": 1}'::jsonb, NULL::text")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(column::<i32>(&row, 0, "the id").unwrap(), 42);
        assert_eq!(
            column::<Value>(&row, 2, "the profile").unwrap(),
            json!({"a": 1})
        );
        assert_eq!(
            column::<Option<String>>(&row, 3, "the reason").unwrap(),
            None
        );
        assert_eq!(
            column::<Option<String>>(&row, 1, "the active role")
                .unwrap()
                .as_deref(),
            Some("x")
        );
        for err in [
            column::<i32>(&row, 1, "the id of the new profile").unwrap_err(),
            column::<i64>(&row, 0, "the id of the new profile").unwrap_err(),
            column::<Value>(&row, 1, "the id of the new profile").unwrap_err(),
            column::<Option<String>>(&row, 0, "the id of the new profile").unwrap_err(),
            column::<i32>(&row, 9, "the id of the new profile").unwrap_err(),
        ] {
            assert!(
                format!("{err:#}").starts_with(
                    "cannot read the id of the new profile (incompatible extension version?): "
                ),
                "{err:#}"
            );
        }
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
            failed: &[],
            advice: None,
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
