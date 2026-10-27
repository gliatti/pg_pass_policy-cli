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
use commands::Delivery;

/// Exit code of a successful run.
pub const EXIT_OK: i32 = 0;
/// Exit code of a failed run (database, network, policy refusal, ...).
pub const EXIT_ERROR: i32 = 1;
/// Exit code of a usage error (clap uses it on its own; `run` uses it for a
/// delivery configuration refused before any rotation).
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

/// Validates the delivery options of `rotate` / `switch-pair` before any
/// connection: a bad Vault configuration or path, a token refused by Vault,
/// an unreachable Vault or a missing shell must not be discovered after the
/// password has been rotated.  Returns `None`
/// (usage error, already printed) when they are refused.
async fn prepare_delivery(opts: &RotateOpts) -> Option<Delivery> {
    match Delivery::prepare(opts).await {
        Ok(d) => Some(d),
        Err(e) => {
            eprintln!("pgpp: error: {}", format_error(&e));
            None
        }
    }
}

/// Executes the parsed command and returns the process exit code.
pub async fn run(cli: Cli) -> Result<i32> {
    let fmt = cli.format;
    let delivery = match &cli.command {
        Command::Rotate { opts, .. } | Command::SwitchPair { opts, .. } => {
            match prepare_delivery(opts).await {
                Some(d) => Some(d),
                None => return Ok(EXIT_USAGE),
            }
        }
        _ => None,
    };
    let mut conn = db::connect().await?;
    match cli.command {
        Command::Status { role } => commands::status(&mut conn, role.as_deref(), fmt).await?,
        Command::Expiring { within } => commands::expiring(&mut conn, within, fmt).await?,
        Command::Locked => commands::locked(&mut conn, fmt).await?,
        Command::Rotate { role, .. } => {
            let delivery = delivery.expect("delivery prepared above");
            commands::rotate(&mut conn, &role, delivery, fmt).await?
        }
        Command::SwitchPair { pair, .. } => {
            let delivery = delivery.expect("delivery prepared above");
            commands::switch_pair(&mut conn, &pair, delivery, fmt).await?
        }
        Command::Lock {
            role,
            duration,
            reason,
        } => commands::lock(&mut conn, &role, duration, reason.as_deref(), fmt).await?,
        Command::Unlock { role } => commands::unlock(&mut conn, &role, fmt).await?,
        Command::Expire { role } => commands::expire(&mut conn, &role, fmt).await?,
        Command::Profile { action } => match action {
            ProfileCommand::List => commands::profile_list(&mut conn, fmt).await?,
            ProfileCommand::Show { name } => commands::profile_show(&mut conn, &name, fmt).await?,
            ProfileCommand::Create { name, set } => {
                commands::profile_create(&mut conn, &name, &set, fmt).await?
            }
            ProfileCommand::Alter { name, set } => {
                commands::profile_alter(&mut conn, &name, &set, fmt).await?
            }
            ProfileCommand::Drop { name } => commands::profile_drop(&mut conn, &name, fmt).await?,
            ProfileCommand::Assign { role, profile } => {
                commands::profile_assign(&mut conn, &role, &profile, fmt).await?
            }
            ProfileCommand::Unassign { role } => {
                commands::profile_unassign(&mut conn, &role, fmt).await?
            }
        },
        Command::Audit {
            since,
            role,
            event_type,
            limit,
        } => {
            commands::audit(
                &mut conn,
                since,
                role.as_deref(),
                event_type.as_deref(),
                limit,
                fmt,
            )
            .await?
        }
        Command::Check { role } => return commands::check(&mut conn, &role, fmt).await,
        Command::Maintenance => commands::maintenance(&mut conn, fmt).await?,
        Command::FailedAttempts => commands::failed_attempts(&mut conn, fmt).await?,
        Command::WorkerStatus => commands::worker_status(&mut conn, fmt).await?,
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
}
