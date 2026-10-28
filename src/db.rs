//! Database connection.

use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::postgres::PgConnectOptions;
use sqlx::{ConnectOptions, Connection, PgConnection};

/// Connection options from `DATABASE_URL` or, when it is unset, from the
/// standard `PG*` environment variables (`PGPASSFILE` / `~/.pgpass` are read
/// by sqlx when no password is given).  Nothing is opened: [`run`] calls it
/// before any input is read (the candidate password of `check`), so that an
/// invalid `DATABASE_URL` is reported first.  Statement logging is disabled
/// so that no bound parameter (passwords of `check`) can reach a log.
///
/// [`run`]: crate::run
pub fn connect_options() -> Result<PgConnectOptions> {
    let opts = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => PgConnectOptions::from_str(&url)
            .context("invalid DATABASE_URL (the value itself is not shown)")?,
        _ => PgConnectOptions::new(),
    };
    Ok(with_defaults(opts))
}

/// Keeps an application_name given by `DATABASE_URL` (`?application_name=`)
/// or by `PGAPPNAME` (read by sqlx), defaults to "pgpp" otherwise; disables
/// statement logging.
fn with_defaults(mut opts: PgConnectOptions) -> PgConnectOptions {
    if opts.get_application_name().is_none() {
        opts = opts.application_name("pgpp");
    }
    opts.disable_statement_logging()
}

/// Opens a connection with the options of [`connect_options`].
pub async fn connect(opts: &PgConnectOptions) -> Result<PgConnection> {
    PgConnection::connect_with(opts)
        .await
        .context("cannot connect to PostgreSQL (check DATABASE_URL / PG* variables / PGPASSFILE)")
}

/// Longest wait of [`close`] (and of the check of `commands::diagnose`):
/// an unresponsive server must not hold pgpp.
pub(crate) const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

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
        let _ = rollback_open(&mut conn).await;
        let _ = conn.close().await;
    };
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, graceful).await;
}

/// Rolls back the transactions sqlx still counts as open on `conn`
/// (`is_in_transaction`), through its transaction manager: each level is
/// ended by the statement sqlx would send itself (`ROLLBACK`, or
/// `ROLLBACK TO SAVEPOINT` for a nested level) and its depth is decreased,
/// so that the count of sqlx stays in step with the server (a raw
/// `ROLLBACK` would leave it at one and make the next `begin` a
/// savepoint).  Without an open transaction, nothing is sent.  Used by
/// [`close`] and by the check of `commands::diagnose`.
pub(crate) async fn rollback_open(conn: &mut PgConnection) -> Result<()> {
    while conn.is_in_transaction() {
        <sqlx::postgres::PgTransactionManager as sqlx::TransactionManager>::rollback(conn).await?;
    }
    Ok(())
}
