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
    // keep an application_name given by DATABASE_URL (?application_name=)
    // or by PGAPPNAME (read by sqlx), default to "pgpp" otherwise
    if opts.get_application_name().is_none() {
        opts = opts.application_name("pgpp");
    }
    opts = opts.disable_statement_logging();
    PgConnection::connect_with(&opts)
        .await
        .context("cannot connect to PostgreSQL (check DATABASE_URL / PG* variables / PGPASSFILE)")
}

/// Longest wait of [`close`]: an unresponsive server must not hold pgpp.
const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Ends the session cleanly before the process exits, on success and on
/// error alike: without it the server sees the socket close without a
/// Terminate message (« unexpected EOF on client connection », « with an
/// open transaction » after an error inside a transaction).  A transaction
/// still open is rolled back explicitly; the ROLLBACK queued by a dropped
/// sqlx `Transaction` (error inside `check`) goes out ahead of the Terminate
/// message, which `close` sends without waiting for the results of a query
/// abandoned by a Ctrl-C.  Errors are ignored (the outcome of the command is
/// already known) and the whole is bounded by [`CLOSE_TIMEOUT`].
pub async fn close(mut conn: PgConnection) {
    let graceful = async move {
        if conn.is_in_transaction() {
            let _ = sqlx::Executor::execute(&mut conn, "ROLLBACK").await;
        }
        let _ = conn.close().await;
    };
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, graceful).await;
}
