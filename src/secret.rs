//! Handling of a freshly generated password: zeroised buffer, delivery to a
//! child process on its stdin.

use std::io::Read;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::unix::pipe;
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
/// `valid_until` is `Some("")` for an unbounded role and `None` when the
/// value is unknown (read failed after the rotation): `PGPP_VALID_UNTIL` is
/// then left unset, even if pgpp itself inherited one.  `--` ends the options
/// of `sh`, so that a command starting with `-` is not taken for one.
/// Its standard output is sent to the standard error of pgpp, so that it
/// never mixes with the result printed by pgpp (JSON with `-f json`).
///
/// The delivery fails when the command exits with a non-zero status, when the
/// password cannot be written to the pipe, or when the command exits without
/// having read the whole password line: pgpp keeps its own copy of the read
/// end of the pipe and checks, once the command has exited, that no byte is
/// left in it.  A command that ignores its stdin would otherwise be reported
/// as a successful delivery while the password is lost.
pub async fn run_exec(
    cmd: &str,
    password: &Secret,
    role: &str,
    valid_until: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Result<()> {
    let (tx, rx) = pipe::pipe().context("cannot create the pipe for --exec")?;
    // The child gets a blocking descriptor; pgpp keeps another one on the
    // same pipe to check afterwards that the password was consumed.
    let probe = rx
        .into_blocking_fd()
        .context("cannot create the pipe for --exec")?;
    let child_stdin = probe
        .try_clone()
        .context("cannot create the pipe for --exec")?;

    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("--")
        .arg(cmd)
        .env("PGPP_ROLE", role)
        .stdin(Stdio::from(child_stdin))
        .stdout(Stdio::from(std::io::stderr()));
    match valid_until {
        Some(v) => command.env("PGPP_VALID_UNTIL", v),
        None => command.env_remove("PGPP_VALID_UNTIL"),
    };
    for (k, v) in extra_env {
        command.env(k, v);
    }
    let spawned = command.spawn();
    // drop the parent's copy of the child's stdin descriptor
    drop(command);
    let mut child = spawned.with_context(|| format!("cannot run --exec command: {cmd}"))?;

    let write_result = {
        let mut tx = tx;
        let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        line.extend_from_slice(password.as_bytes());
        line.push(b'\n');
        let r = tx.write_all(&line).await;
        // closing the write end gives EOF to the child
        drop(tx);
        r
    };
    let status = child.wait().await.context("--exec command failed")?;
    if let Err(e) = write_result {
        bail!("cannot write the password to the stdin of the --exec command: {e}");
    }
    if !status.success() {
        bail!("--exec command exited with {status}");
    }
    let unread = unread_bytes(probe).context("cannot check the stdin of the --exec command")?;
    if unread > 0 {
        bail!(
            "--exec command exited without reading the password from its stdin \
             ({unread} byte(s) left unread)"
        );
    }
    Ok(())
}

/// Number of bytes still buffered in the pipe (drained and wiped).  Called
/// once the child has exited and the write end is closed: every write end is
/// gone, so a blocking read returns at once (data, or 0 at end of file).
fn unread_bytes(probe: std::os::fd::OwnedFd) -> Result<usize> {
    let mut file = std::fs::File::from(probe);
    let mut buf = Zeroizing::new([0u8; 512]);
    let mut total = 0;
    loop {
        match file.read(&mut buf[..]) {
            Ok(0) => return Ok(total),
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Secret {
        Zeroizing::new(s.to_string())
    }

    async fn exec(cmd: &str) -> Result<()> {
        run_exec(cmd, &secret("pw-Test-123"), "app", None, &[]).await
    }

    #[tokio::test]
    async fn consuming_commands_succeed() {
        for cmd in [
            "cat >/dev/null",
            "read -r pw; test \"$pw\" = pw-Test-123",
            "test \"$PGPP_ROLE\" = app && cat >/dev/null",
        ] {
            exec(cmd).await.unwrap_or_else(|e| panic!("{cmd}: {e:#}"));
        }
    }

    #[tokio::test]
    async fn a_command_that_ignores_stdin_is_a_failed_delivery() {
        for cmd in [
            "true",
            "exec 0<&-",
            "exec 0<&-; sleep 0.2",
            "head -c 3 >/dev/null",
        ] {
            let err = exec(cmd).await.unwrap_err();
            let text = format!("{err:#}");
            assert!(
                text.contains("without reading the password"),
                "{cmd}: {text}"
            );
            assert!(!text.contains("pw-Test-123"), "{cmd}: {text}");
        }
    }

    #[tokio::test]
    async fn a_command_starting_with_a_dash_is_not_an_option_of_sh() {
        // without `--`, sh would reject "-pgpp..." as an invalid option
        exec("-pgpp-no-such-command 2>/dev/null; cat >/dev/null")
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
    }

    #[tokio::test]
    async fn valid_until_is_unset_when_unknown() {
        let pw = secret("pw-Test-123");
        let set = "cat >/dev/null; test \"${PGPP_VALID_UNTIL+set}\" = set";
        let unset = "cat >/dev/null; test -z \"${PGPP_VALID_UNTIL+set}\"";
        // unbounded role: set and empty
        run_exec(
            &format!("{set} && test -z \"$PGPP_VALID_UNTIL\""),
            &pw,
            "app",
            Some(""),
            &[],
        )
        .await
        .unwrap();
        run_exec(
            &format!("{set} && test \"$PGPP_VALID_UNTIL\" = infinity"),
            &pw,
            "app",
            Some("infinity"),
            &[],
        )
        .await
        .unwrap();
        // unknown: unset
        run_exec(unset, &pw, "app", None, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_reported_first() {
        let err = exec("exit 4").await.unwrap_err();
        assert!(format!("{err:#}").contains("exit status: 4"), "{err:#}");
    }
}
