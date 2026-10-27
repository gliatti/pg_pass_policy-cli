//! Database connection.

use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::postgres::PgConnectOptions;
use sqlx::{ConnectOptions, Connection, PgConnection};

/// Opens a connection from `DATABASE_URL` or, when it is unset, from the
/// standard `PG*` environment variables (`PGPASSFILE` / `~/.pgpass` are read
/// by sqlx when no password is given).  Statement logging is disabled so that
/// no bound parameter (passwords of `check`) can reach a log.
pub async fn connect() -> Result<PgConnection> {
    let mut opts = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => PgConnectOptions::from_str(&url)
            .context("invalid DATABASE_URL (the value itself is not shown)")?,
        _ => PgConnectOptions::new(),
    };
    if std::env::var("PGAPPNAME").is_err() {
        opts = opts.application_name("pgpp");
    }
    opts = opts.disable_statement_logging();
    PgConnection::connect_with(&opts)
        .await
        .context("cannot connect to PostgreSQL (check DATABASE_URL / PG* variables / PGPASSFILE)")
}
