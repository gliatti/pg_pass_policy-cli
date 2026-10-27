//! Handling of a freshly generated password: zeroised buffer, delivery to a
//! child process on its stdin.

use std::io::Read;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::unix::pipe;
use tokio::process::Command;
use zeroize::Zeroizing;

/// A password that is wiped from memory when dropped.
pub type Secret = Zeroizing<String>;

/// Longest wait for the password to be written into the pipe of `--exec`.
/// The write only blocks when the line exceeds the capacity of the pipe
/// (64 KiB on Linux) and the command does not read it.
pub const EXEC_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of the write of the password line into the pipe.
enum Written {
    /// Every byte is in the pipe (or already read).
    Complete,
    /// The command exited before the line was entirely written.
    Incomplete,
    /// The write did not end within the delay; the command was killed.
    TimedOut,
    Failed(std::io::Error),
}

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
///
/// The write and the wait for the command run concurrently: a line larger
/// than the pipe, sent to a command that exits without reading it, cannot
/// block pgpp.  The write is bounded by [`EXEC_WRITE_TIMEOUT`]; past it the
/// command (still running, not reading) is killed and the delivery fails.
/// Once the line is written, the command may run as long as it needs.
///
/// `sh` runs in its own process group, so that the delay kills `sh` and every
/// sub-process it started (unless one moved to another group or session).
/// Whatever the outcome (success, delay, write error, non-zero exit), the
/// pipe is drained (and the bytes wiped) before returning: a sub-process
/// that inherited stdin and outlives `sh` cannot read the password left in
/// it.  Being in its own group, the command does not receive the `SIGINT`
/// of a Ctrl-C typed in the terminal of pgpp, and it cannot read that
/// terminal (`SIGTTIN`): its input is the pipe anyway.
pub async fn run_exec(
    cmd: &str,
    password: &Secret,
    role: &str,
    valid_until: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Result<()> {
    run_exec_with_timeout(
        cmd,
        password,
        role,
        valid_until,
        extra_env,
        EXEC_WRITE_TIMEOUT,
    )
    .await
}

async fn run_exec_with_timeout(
    cmd: &str,
    password: &Secret,
    role: &str,
    valid_until: Option<&str>,
    extra_env: &[(&str, &str)],
    write_timeout: Duration,
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
        .stdout(Stdio::from(std::io::stderr()))
        // own process group, killed as a whole when the write times out
        .process_group(0);
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

    let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    line.extend_from_slice(password.as_bytes());
    line.push(b'\n');
    let (written, exited) = {
        // the future owns the write end: dropping it gives EOF to the child
        let write = async move {
            let mut tx = tx;
            tx.write_all(&line).await
        };
        tokio::pin!(write);
        tokio::select! {
            r = tokio::time::timeout(write_timeout, &mut write) => match r {
                Ok(Ok(())) => (Written::Complete, None),
                Ok(Err(e)) => (Written::Failed(e), None),
                Err(_) => (Written::TimedOut, None),
            },
            status = child.wait() => {
                // The child exited first: take a write that ended at the
                // same time (a zero timeout still polls it once), give up
                // the rest, nobody will read it.
                let written = match tokio::time::timeout(Duration::ZERO, &mut write).await {
                    Ok(Ok(())) => Written::Complete,
                    Ok(Err(e)) => Written::Failed(e),
                    Err(_) => Written::Incomplete,
                };
                (written, Some(status))
            }
        }
    };
    // From here on the write end is closed (owned by the dropped future).
    // On a delay, kill the whole process group of `sh`: a sub-process it
    // started (still holding the read end) must not read the line later.
    if exited.is_none() && matches!(written, Written::TimedOut) {
        kill_group(&child);
    }
    let status = match exited {
        Some(status) => status,
        None => child.wait().await,
    };
    // Drain the pipe on every path, before any error is reported: a
    // sub-process that inherited stdin and outlives `sh` (or escaped the
    // process group) must not find the password there.
    let unread = unread_bytes(probe);
    let status = status.context("--exec command failed")?;
    match written {
        Written::Failed(e) => {
            bail!("cannot write the password to the stdin of the --exec command: {e}")
        }
        Written::TimedOut => bail!(
            "--exec command did not read the password from its stdin within {} s \
             (command killed)",
            write_timeout.as_secs_f32()
        ),
        Written::Complete | Written::Incomplete => {}
    }
    if !status.success() {
        bail!("--exec command exited with {status}");
    }
    let unread = unread.context("cannot check the stdin of the --exec command")?;
    if matches!(written, Written::Incomplete) {
        bail!(
            "--exec command exited without reading the password from its stdin \
             (line only partly written, {unread} byte(s) left unread in the pipe)"
        );
    }
    if unread > 0 {
        bail!(
            "--exec command exited without reading the password from its stdin \
             ({unread} byte(s) left unread)"
        );
    }
    Ok(())
}

/// Sends `SIGKILL` to the process group of `child` (its own group, see
/// `process_group(0)`); nothing when `child` was already reaped.
fn kill_group(child: &tokio::process::Child) {
    if let Some(pid) = child.id().and_then(|pid| libc::pid_t::try_from(pid).ok()) {
        // SAFETY: plain system call on the process group created for `sh`
        // (its id is the pid of `sh`, not reaped yet).
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
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

    /// A line larger than the pipe capacity (64 KiB on Linux) cannot be
    /// written at once: a command that exits without reading must not block
    /// the write (the server limits passwords to 1024 characters, hence a
    /// direct call).
    #[tokio::test]
    async fn a_line_larger_than_the_pipe_does_not_block() {
        let big = secret(&"p".repeat(256 * 1024));
        for cmd in ["true", "head -c 10 >/dev/null", "exec 0<&-; sleep 0.2"] {
            let started = std::time::Instant::now();
            let err = run_exec(cmd, &big, "app", None, &[]).await.unwrap_err();
            let text = format!("{err:#}");
            assert!(
                text.contains("without reading the password"),
                "{cmd}: {text}"
            );
            assert!(!text.contains("ppppp"), "{cmd}: {text}");
            assert!(started.elapsed() < Duration::from_secs(10), "{cmd}");
        }
        // a command that reads it all succeeds
        run_exec("cat >/dev/null", &big, "app", None, &[])
            .await
            .unwrap();
        run_exec("test \"$(wc -c)\" -eq 262145", &big, "app", None, &[])
            .await
            .unwrap();
    }

    /// A command that neither reads nor exits is killed once the write delay
    /// is over.
    #[tokio::test]
    async fn a_write_that_never_ends_is_bounded() {
        let big = secret(&"p".repeat(256 * 1024));
        let started = std::time::Instant::now();
        let err = run_exec_with_timeout(
            "exec sleep 30",
            &big,
            "app",
            None,
            &[],
            Duration::from_millis(300),
        )
        .await
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("within 0.3 s"), "{text}");
        assert!(started.elapsed() < Duration::from_secs(10));
        // a short line is written at once: the delay does not apply to the
        // run time of the command
        run_exec_with_timeout(
            "sleep 0.5; cat >/dev/null",
            &secret("pw"),
            "app",
            None,
            &[],
            Duration::from_millis(100),
        )
        .await
        .unwrap();
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pgpp-{tag}-{}", std::process::id()))
    }

    /// Waits (up to 10 s) for `path` to appear.
    async fn wait_for(path: &std::path::Path) -> bool {
        for _ in 0..200 {
            if path.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// A sub-process that inherited stdin and reads it after `sh` exited
    /// with an error finds the pipe empty: it was drained before the error.
    #[tokio::test]
    async fn the_pipe_is_drained_after_a_non_zero_exit() {
        let out = temp_path("drain-exit");
        let done = temp_path("drain-exit-done");
        let _ = std::fs::remove_file(&out);
        let _ = std::fs::remove_file(&done);
        // fd 3: an asynchronous list gets /dev/null on its fd 0
        let cmd = format!(
            "exec 3<&0; (sleep 0.5; cat <&3 > '{}'; touch '{}') & exit 4",
            out.display(),
            done.display()
        );
        let err = exec(&cmd).await.unwrap_err();
        assert!(format!("{err:#}").contains("exit status: 4"), "{err:#}");
        assert!(wait_for(&done).await, "the sub-process did not finish");
        let read = std::fs::read(&out).unwrap();
        let _ = std::fs::remove_file(&out);
        let _ = std::fs::remove_file(&done);
        assert!(read.is_empty(), "password left in the pipe: {read:?}");
    }

    /// Past the write delay the whole process group of `sh` is killed, not
    /// only `sh`; the pipe is drained as well.
    #[tokio::test]
    async fn the_process_group_is_killed_after_the_delay() {
        let pidfile = temp_path("group-pid");
        let _ = std::fs::remove_file(&pidfile);
        let big = secret(&"p".repeat(256 * 1024));
        let cmd = format!(
            "exec 3<&0; sleep 30 <&3 & echo $! > '{}'; exec sleep 30",
            pidfile.display()
        );
        let err = run_exec_with_timeout(&cmd, &big, "app", None, &[], Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("command killed"), "{err:#}");
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let _ = std::fs::remove_file(&pidfile);
        let stat = format!("/proc/{}/stat", pid.trim());
        let mut alive = true;
        for _ in 0..100 {
            // gone, or a zombie waiting for its new parent to reap it
            alive = std::fs::read_to_string(&stat)
                .ok()
                .and_then(|s| s.rsplit(')').next().map(|r| r.trim_start().to_string()))
                .is_some_and(|r| !r.starts_with('Z'));
            if !alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!alive, "sub-process {} survived the delay", pid.trim());
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_reported_first() {
        let err = exec("exit 4").await.unwrap_err();
        assert!(format!("{err:#}").contains("exit status: 4"), "{err:#}");
    }
}
