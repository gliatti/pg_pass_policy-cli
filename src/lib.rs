//! `pgpp`: command-line client for the pg_pass_policy PostgreSQL extension.
//!
//! The binary (`src/main.rs`) only parses the arguments and maps the result of
//! [`run`] to an exit code; everything else lives here so that it can be
//! exercised by the integration tests.

pub mod cli;
pub mod commands;
pub mod db;
pub mod duration;
pub mod kv;
pub mod output;
pub mod secret;
pub mod vault;

use anyhow::Result;
use sqlx::postgres::PgDatabaseError;

use cli::{Cli, Command, ProfileCommand, RotateOpts};
use commands::{Delivery, PrepareError};

/// Exit code of a successful run.
pub const EXIT_OK: i32 = 0;
/// Exit code of a failed run (database, network, policy refusal, ...).
pub const EXIT_ERROR: i32 = 1;
/// Exit code of a usage error (clap uses it on its own; `run` uses it for a
/// delivery configuration refused by the local validation, before any
/// rotation; a failed Vault preflight request exits with [`EXIT_ERROR`]).
pub const EXIT_USAGE: i32 = 2;
/// Exit code of `check` when the candidate password is refused by the policy.
pub const EXIT_REFUSED: i32 = 3;

/// Renders an error chain for the user.  A PostgreSQL error is shown once,
/// with its DETAIL and HINT; redundant links of the chain (sqlx repeats the
/// database message in its own wrapper) are dropped.
pub fn format_error(err: &anyhow::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in err.chain() {
        if let Some(sqlx::Error::Database(db)) = cause.downcast_ref::<sqlx::Error>() {
            let mut text = db.message().to_string();
            if let Some(pg) = db.try_downcast_ref::<PgDatabaseError>() {
                if let Some(d) = pg.detail() {
                    text.push_str(&format!(" (detail: {d})"));
                }
                if let Some(h) = pg.hint() {
                    text.push_str(&format!(" (hint: {h})"));
                }
            }
            parts.push(text);
            break;
        }
        let m = cause.to_string();
        if !parts.last().is_some_and(|p| p.ends_with(&m)) {
            parts.push(m);
        }
    }
    parts.join(": ")
}

/// Kind of a message printed on the standard error by [`report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// `pgpp: error: ...`
    Error,
    /// `pgpp: warning: ...`
    Warning,
}

/// Line printed by [`report`], [`warn`] and [`report_text`]: the one place
/// where the `pgpp: error:` / `pgpp: warning:` prefix is written.
fn message_line(kind: Report, text: &str) -> String {
    let label = match kind {
        Report::Error => "error",
        Report::Warning => "warning",
    };
    format!("pgpp: {label}: {text}")
}

/// Line printed by [`report`].
fn report_line(kind: Report, err: &anyhow::Error) -> String {
    message_line(kind, &format_error(err))
}

/// Prints an error chain on the standard error, as `pgpp: error: ...` or
/// `pgpp: warning: ...` (see [`format_error`]).
pub fn report(kind: Report, err: &anyhow::Error) {
    output::write_stderr(report_line(kind, err), true);
}

/// Prints a message (not an error chain) on the standard error, with the
/// prefix of [`report`].
pub fn report_text(kind: Report, text: &str) {
    output::write_stderr(message_line(kind, text), true);
}

/// Prints `pgpp: warning: <text>` on the standard error.
pub fn warn(text: &str) {
    report_text(Report::Warning, text);
}

/// Exit code of a run that failed with `err`, reported on the standard
/// error.  A standard output closed by its reader (`pgpp audit | head -1`,
/// [`output::BrokenPipe`]) is not a failure of pgpp: nothing is printed and
/// the exit code is [`EXIT_OK`].
pub fn failure_code(err: &anyhow::Error) -> i32 {
    if output::is_broken_pipe(err) {
        return EXIT_OK;
    }
    report(Report::Error, err);
    EXIT_ERROR
}

/// Validates the delivery options of `rotate` / `switch-pair` before any
/// connection: a bad Vault configuration or path, a token refused by Vault,
/// an unreachable Vault or a missing shell must not be discovered after the
/// password has been rotated.  On a refusal the error is printed and the
/// exit code returned: [`EXIT_USAGE`] for the local validation (path,
/// environment, certificates, `sh`), [`EXIT_ERROR`] for a failed preflight
/// request (network, TLS, HTTP status, refused token or permission).
async fn prepare_delivery(opts: &RotateOpts) -> std::result::Result<Delivery, i32> {
    Delivery::prepare(opts).await.map_err(|e| {
        report(Report::Error, e.error());
        match e {
            PrepareError::Invalid(_) => EXIT_USAGE,
            PrepareError::Preflight(_) => EXIT_ERROR,
        }
    })
}

/// Prints a usage error detected before the connection and returns its exit
/// code.
fn usage_error(err: &anyhow::Error) -> i32 {
    report(Report::Error, err);
    EXIT_USAGE
}

/// Executes the parsed command and returns the process exit code.
pub async fn run(cli: Cli) -> Result<i32> {
    let fmt = cli.format;
    // Inputs that do not depend on the server are validated before the
    // connection: a repeated `--set` key, the connection options, the
    // candidate password of `check`
    // (read first, so that an empty or unreadable input is a usage error and
    // the password is never awaited with an idle connection open).
    let settings = match &cli.command {
        Command::Profile {
            action: ProfileCommand::Create { set, .. } | ProfileCommand::Alter { set, .. },
        } => match kv::parse_settings(set) {
            Ok(m) => Some(m),
            Err(e) => return Ok(usage_error(&e)),
        },
        _ => None,
    };
    // the connection options (DATABASE_URL / PG*) are checked before the
    // candidate password is prompted for or read: an invalid DATABASE_URL
    // must not be discovered once the password has been typed
    let connect_options = db::connect_options()?;
    let password = match &cli.command {
        Command::Check { .. } => match commands::read_candidate_password() {
            Ok(p) => Some(p),
            Err(e) => return Ok(usage_error(&e)),
        },
        _ => None,
    };
    let delivery = match &cli.command {
        Command::Rotate { opts, .. } | Command::SwitchPair { opts, .. } => {
            match prepare_delivery(opts).await {
                Ok(d) => Some(d),
                Err(code) => return Ok(code),
            }
        }
        _ => None,
    };
    let mut conn = db::connect(&connect_options).await?;
    let result = dispatch(&mut conn, cli.command, fmt, settings, password, delivery).await;
    db::close(conn).await;
    result
}

/// Runs the command on the open connection; [`run`] closes it afterwards,
/// whatever the result.
async fn dispatch(
    conn: &mut sqlx::PgConnection,
    command: Command,
    fmt: output::Format,
    settings: Option<serde_json::Map<String, serde_json::Value>>,
    password: Option<secret::Secret>,
    delivery: Option<Delivery>,
) -> Result<i32> {
    match command {
        Command::Status { role } => commands::status(conn, role.as_deref(), fmt).await?,
        Command::Expiring { within } => commands::expiring(conn, within, fmt).await?,
        Command::Locked => commands::locked(conn, fmt).await?,
        Command::Rotate { role, .. } => {
            let delivery = delivery.expect("delivery prepared above");
            commands::rotate(conn, &role, delivery, fmt).await?
        }
        Command::SwitchPair { pair, .. } => {
            let delivery = delivery.expect("delivery prepared above");
            commands::switch_pair(conn, &pair, delivery, fmt).await?
        }
        Command::Lock {
            role,
            duration,
            reason,
        } => commands::lock(conn, &role, duration, reason.as_deref(), fmt).await?,
        Command::Unlock { role } => commands::unlock(conn, &role, fmt).await?,
        Command::Expire { role } => commands::expire(conn, &role, fmt).await?,
        Command::Profile { action } => match action {
            ProfileCommand::List => commands::profile_list(conn, fmt).await?,
            ProfileCommand::Show { name } => commands::profile_show(conn, &name, fmt).await?,
            ProfileCommand::Create { name, .. } => {
                let settings = settings.expect("settings validated above");
                commands::profile_create(conn, &name, settings, fmt).await?
            }
            ProfileCommand::Alter { name, .. } => {
                let settings = settings.expect("settings validated above");
                commands::profile_alter(conn, &name, settings, fmt).await?
            }
            ProfileCommand::Drop { name } => commands::profile_drop(conn, &name, fmt).await?,
            ProfileCommand::Assign { role, profile } => {
                commands::profile_assign(conn, &role, &profile, fmt).await?
            }
            ProfileCommand::Unassign { role } => {
                commands::profile_unassign(conn, &role, fmt).await?
            }
        },
        Command::Audit {
            since,
            role,
            event_type,
            limit,
        } => {
            commands::audit(
                conn,
                since,
                role.as_deref(),
                event_type.as_deref(),
                limit,
                fmt,
            )
            .await?
        }
        Command::Check { role } => {
            let password = password.expect("password read above");
            return commands::check(conn, &role, password, fmt).await;
        }
        Command::Maintenance => commands::maintenance(conn, fmt).await?,
        Command::FailedAttempts => commands::failed_attempts(conn, fmt).await?,
        Command::WorkerStatus => commands::worker_status(conn, fmt).await?,
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_error_drops_redundant_links() {
        let err = anyhow::anyhow!("inner").context("outer: inner");
        assert_eq!(format_error(&err), "outer: inner");
        let err = anyhow::anyhow!("inner").context("outer");
        assert_eq!(format_error(&err), "outer: inner");
    }

    #[test]
    fn reports_share_one_prefix() {
        let err = anyhow::anyhow!("inner").context("outer");
        assert_eq!(
            report_line(Report::Error, &err),
            "pgpp: error: outer: inner"
        );
        assert_eq!(
            report_line(Report::Warning, &err),
            "pgpp: warning: outer: inner"
        );
        // the lines of `warn` / `report_text` (Vault preflight warnings,
        // failed deliveries, parameter logging) use the same prefix
        assert_eq!(
            message_line(Report::Warning, "preflight skipped"),
            "pgpp: warning: preflight skipped"
        );
        assert_eq!(
            message_line(Report::Error, "Vault delivery failed: x"),
            "pgpp: error: Vault delivery failed: x"
        );
    }

    #[test]
    fn a_closed_stdout_exits_quietly_with_0() {
        let pipe = anyhow::Error::new(output::BrokenPipe);
        assert_eq!(failure_code(&pipe), EXIT_OK);
        assert_eq!(failure_code(&pipe.context("printing")), EXIT_OK);
        assert_eq!(failure_code(&anyhow::anyhow!("boom")), EXIT_ERROR);
    }
}
