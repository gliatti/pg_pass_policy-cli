//! Handling of a freshly generated password: zeroised buffer, delivery to a
//! child process on its stdin.

use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

/// A password that is wiped from memory when dropped.
pub type Secret = Zeroizing<String>;

/// Checks that `sh` can be started, so that a missing shell is reported
/// before the password is rotated.
pub fn check_shell() -> Result<()> {
    let status = std::process::Command::new("sh")
        .args(["-c", ":"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("cannot run sh (required by --exec)")?;
    if !status.success() {
        bail!("sh -c ':' failed with {status}");
    }
    Ok(())
}

/// Runs `cmd` through `sh -c` with the password written on its stdin (followed
/// by a newline).  The password is never put in an argument or in an
/// environment variable.  The child inherits the whole environment of pgpp
/// (hence VAULT_ADDR / VAULT_TOKEN, DATABASE_URL, PG*...) and receives in
/// addition `PGPP_ROLE`, `PGPP_VALID_UNTIL` and the extra variables given.
/// A non-zero exit status is an error.
pub async fn run_exec(
    cmd: &str,
    password: &Secret,
    role: &str,
    valid_until: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Result<()> {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .env("PGPP_ROLE", role)
        .env("PGPP_VALID_UNTIL", valid_until.unwrap_or(""))
        .stdin(Stdio::piped());
    for (k, v) in extra_env {
        command.env(k, v);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot run --exec command: {cmd}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .context("cannot open stdin of the --exec command")?;
        let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        line.extend_from_slice(password.as_bytes());
        line.push(b'\n');
        // The child may legitimately exit without reading stdin: ignore EPIPE.
        let _ = stdin.write_all(&line).await;
        let _ = stdin.shutdown().await;
    }
    let status = child.wait().await.context("--exec command failed")?;
    if !status.success() {
        bail!("--exec command exited with {status}");
    }
    Ok(())
}
