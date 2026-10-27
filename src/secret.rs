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

/// Default of `--exec-timeout`: longest run time of the `--exec` command.
pub const EXEC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Longest wait for the command once its process group was killed
/// (`SIGKILL`, normally immediate).
const KILL_WAIT: Duration = Duration::from_secs(5);

/// Outcome of the write of the password line into the pipe.
enum Written {
    /// Every byte is in the pipe (or already read).
    Complete,
    /// The command exited (or was killed) before the line was entirely
    /// written.
    Incomplete,
    /// The write did not end within the delay; the command was killed.
    TimedOut,
    /// The write failed; the command was killed.
    Failed(std::io::Error),
}

/// Why the command was killed while it was still running, besides a failed
/// or timed-out write.
#[derive(Clone, Copy, PartialEq)]
enum Stop {
    /// Ctrl-C (`SIGINT`) received by pgpp.
    Interrupted,
    /// `--exec-timeout` reached.
    TimedOut,
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
/// block pgpp.  The write is bounded by [`EXEC_WRITE_TIMEOUT`], the whole
/// run of the command by `timeout` (`--exec-timeout`, `None`: unbounded).
/// `sh` runs in its own process group: when the write fails or times out,
/// when `timeout` is reached, or when pgpp receives a Ctrl-C (`SIGINT`, which
/// the terminal sends to the foreground group of pgpp only), the whole group
/// (`sh` and every sub-process that stayed in it) is killed with `SIGKILL`,
/// waited for at most [`KILL_WAIT`], and the delivery fails.
///
/// Whatever the outcome, the pipe is drained (and the bytes wiped) before
/// returning: a sub-process that inherited stdin and outlives `sh` cannot
/// read the bytes still in the pipe afterwards.  The drain only removes what
/// is left in the pipe at that moment: it guarantees nothing against a
/// reader that left the group (`setsid`) and already read, or reads first.
///
/// Being in a background group of the terminal, the command is stopped by
/// `SIGTTIN` when it reads the terminal, and by `SIGTTOU` when it writes to
/// it under `stty tostop` or changes its settings; `timeout` and Ctrl-C then
/// still end the wait.
pub async fn run_exec(
    cmd: &str,
    password: &Secret,
    role: &str,
    valid_until: Option<&str>,
    extra_env: &[(&str, &str)],
    timeout: Option<Duration>,
) -> Result<()> {
    let interrupt = async {
        // without a handler (error), Ctrl-C keeps its default action
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    run_exec_with(
        cmd,
        password,
        Env {
            role,
            valid_until,
            extra: extra_env,
        },
        EXEC_WRITE_TIMEOUT,
        timeout,
        interrupt,
    )
    .await
}

/// Environment given to the command (see [`run_exec`]).
struct Env<'a> {
    role: &'a str,
    valid_until: Option<&'a str>,
    extra: &'a [(&'a str, &'a str)],
}

async fn run_exec_with(
    cmd: &str,
    password: &Secret,
    env: Env<'_>,
    write_timeout: Duration,
    timeout: Option<Duration>,
    interrupt: impl std::future::Future<Output = ()>,
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
        .env("PGPP_ROLE", env.role)
        .stdin(Stdio::from(child_stdin))
        .stdout(Stdio::from(std::io::stderr()))
        // own process group, killed as a whole (delays, Ctrl-C)
        .process_group(0);
    match env.valid_until {
        Some(v) => command.env("PGPP_VALID_UNTIL", v),
        None => command.env_remove("PGPP_VALID_UNTIL"),
    };
    for (k, v) in env.extra {
        command.env(k, v);
    }
    let spawned = command.spawn();
    // drop the parent's copy of the child's stdin descriptor
    drop(command);
    let mut child = spawned.with_context(|| format!("cannot run --exec command: {cmd}"))?;

    let deadline = async {
        match timeout {
            Some(t) => tokio::time::sleep(t).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);
    tokio::pin!(interrupt);

    let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    line.extend_from_slice(password.as_bytes());
    line.push(b'\n');
    let (written, mut exited, mut stop) = {
        // the future owns the write end: dropping it gives EOF to the child
        let write = async move {
            let mut tx = tx;
            tx.write_all(&line).await
        };
        tokio::pin!(write);
        tokio::select! {
            r = tokio::time::timeout(write_timeout, &mut write) => match r {
                Ok(Ok(())) => (Written::Complete, None, None),
                Ok(Err(e)) => (Written::Failed(e), None, None),
                Err(_) => (Written::TimedOut, None, None),
            },
            status = child.wait() => {
                // The child exited first: take a write that ended at the
                // same time (a zero timeout still polls it once), give up
                // the rest, nobody will read it.
                (poll_once(&mut write).await, Some(status), None)
            }
            () = &mut interrupt => (poll_once(&mut write).await, None, Some(Stop::Interrupted)),
            () = &mut deadline => (poll_once(&mut write).await, None, Some(Stop::TimedOut)),
        }
    };
    // From here on the write end is closed (owned by the dropped future).
    let write_failed = matches!(written, Written::Failed(_) | Written::TimedOut);
    if exited.is_none() && stop.is_none() && !write_failed {
        // line written: wait for the command, within the same bounds
        tokio::select! {
            status = child.wait() => exited = Some(status),
            () = &mut interrupt => stop = Some(Stop::Interrupted),
            () = &mut deadline => stop = Some(Stop::TimedOut),
        }
    }
    if exited.is_none() {
        // Write failure or delay, --exec-timeout, Ctrl-C: kill the whole
        // process group of `sh`, a sub-process it started (still holding
        // the read end) must not read the line later.  The wait for the
        // killed group is bounded as well.
        kill_group(&child);
        exited = tokio::time::timeout(KILL_WAIT, child.wait()).await.ok();
    }
    // Drain the pipe on every path, before any error is reported: a
    // sub-process that inherited stdin and outlives `sh` (or escaped the
    // process group) must not find the password left there.
    let unread = unread_bytes(probe);
    match stop {
        Some(Stop::Interrupted) => {
            bail!("interrupted (Ctrl-C) while the --exec command was running (command killed)")
        }
        Some(Stop::TimedOut) => bail!(
            "--exec command did not finish within {} (--exec-timeout; command killed)",
            seconds(timeout.unwrap_or_default())
        ),
        None => {}
    }
    match written {
        Written::Failed(e) => bail!(
            "cannot write the password to the stdin of the --exec command: {e} (command killed)"
        ),
        Written::TimedOut => bail!(
            "--exec command did not read the password from its stdin within {} \
             (command killed)",
            seconds(write_timeout)
        ),
        Written::Complete | Written::Incomplete => {}
    }
    let status = exited
        .context("--exec command did not exit")?
        .context("--exec command failed")?;
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

/// Result of a write that is given up: done if it ended at the same time
/// (a zero timeout still polls it once), incomplete otherwise.
async fn poll_once(
    write: &mut std::pin::Pin<&mut impl std::future::Future<Output = std::io::Result<()>>>,
) -> Written {
    match tokio::time::timeout(Duration::ZERO, write).await {
        Ok(Ok(())) => Written::Complete,
        Ok(Err(e)) => Written::Failed(e),
        Err(_) => Written::Incomplete,
    }
}

/// `0.3 s`, `300 s`.
fn seconds(d: Duration) -> String {
    format!("{} s", d.as_secs_f32())
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

    /// `run_exec` without the Ctrl-C handler (which would stay installed in
    /// the test process), with the given delays and interruption.
    async fn exec_with(
        cmd: &str,
        password: &Secret,
        write_timeout: Duration,
        timeout: Option<Duration>,
        interrupt: impl std::future::Future<Output = ()>,
    ) -> Result<()> {
        let env = Env {
            role: "app",
            valid_until: None,
            extra: &[],
        };
        run_exec_with(cmd, password, env, write_timeout, timeout, interrupt).await
    }

    async fn exec_pw(cmd: &str, password: &Secret) -> Result<()> {
        exec_with(
            cmd,
            password,
            EXEC_WRITE_TIMEOUT,
            Some(EXEC_DEFAULT_TIMEOUT),
            std::future::pending(),
        )
        .await
    }

    async fn exec(cmd: &str) -> Result<()> {
        exec_pw(cmd, &secret("pw-Test-123")).await
    }

    async fn exec_env(cmd: &str, valid_until: Option<&str>) -> Result<()> {
        let env = Env {
            role: "app",
            valid_until,
            extra: &[],
        };
        let pw = secret("pw-Test-123");
        run_exec_with(
            cmd,
            &pw,
            env,
            EXEC_WRITE_TIMEOUT,
            None,
            std::future::pending(),
        )
        .await
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
        let set = "cat >/dev/null; test \"${PGPP_VALID_UNTIL+set}\" = set";
        let unset = "cat >/dev/null; test -z \"${PGPP_VALID_UNTIL+set}\"";
        // unbounded role: set and empty
        exec_env(&format!("{set} && test -z \"$PGPP_VALID_UNTIL\""), Some(""))
            .await
            .unwrap();
        exec_env(
            &format!("{set} && test \"$PGPP_VALID_UNTIL\" = infinity"),
            Some("infinity"),
        )
        .await
        .unwrap();
        // unknown: unset
        exec_env(unset, None).await.unwrap();
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
            let err = exec_pw(cmd, &big).await.unwrap_err();
            let text = format!("{err:#}");
            assert!(
                text.contains("without reading the password"),
                "{cmd}: {text}"
            );
            assert!(!text.contains("ppppp"), "{cmd}: {text}");
            assert!(started.elapsed() < Duration::from_secs(10), "{cmd}");
        }
        // a command that reads it all succeeds
        exec_pw("cat >/dev/null", &big).await.unwrap();
        exec_pw("test \"$(wc -c)\" -eq 262145", &big).await.unwrap();
    }

    /// A command that neither reads nor exits is killed once the write delay
    /// is over.
    #[tokio::test]
    async fn a_write_that_never_ends_is_bounded() {
        let big = secret(&"p".repeat(256 * 1024));
        let started = std::time::Instant::now();
        let err = exec_with(
            "exec sleep 30",
            &big,
            Duration::from_millis(300),
            None,
            std::future::pending(),
        )
        .await
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("within 0.3 s"), "{text}");
        assert!(started.elapsed() < Duration::from_secs(10));
        // a short line is written at once: the write delay does not apply
        // to the run time of the command
        exec_with(
            "sleep 0.5; cat >/dev/null",
            &secret("pw"),
            Duration::from_millis(100),
            None,
            std::future::pending(),
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

    /// Zombie state, read from /proc (a killed process reparented to init
    /// may stay a zombie for a moment).
    #[cfg(target_os = "linux")]
    fn is_zombie(pid: libc::pid_t) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| s.rsplit(')').next().map(|r| r.trim_start().to_string()))
            .is_some_and(|r| r.starts_with('Z'))
    }

    #[cfg(not(target_os = "linux"))]
    fn is_zombie(_pid: libc::pid_t) -> bool {
        false
    }

    /// Asserts that the process whose pid is in `pidfile` ends within 5 s.
    /// The probe is `kill(pid, 0)`, available everywhere: `ESRCH` once the
    /// process is gone (a zombie still counts as gone).
    async fn assert_killed(pidfile: &std::path::Path) {
        assert!(wait_for(pidfile).await, "no pid file");
        // the file may exist before `echo` wrote into it
        let mut text = String::new();
        for _ in 0..100 {
            text = std::fs::read_to_string(pidfile).unwrap_or_default();
            if text.ends_with('\n') {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = std::fs::remove_file(pidfile);
        let pid: libc::pid_t = text.trim().parse().expect("pid file");
        assert!(pid > 1, "pid {pid}");
        let mut alive = true;
        for _ in 0..100 {
            // SAFETY: signal 0 only checks that the process exists.
            let exists = unsafe { libc::kill(pid, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
            alive = exists && !is_zombie(pid);
            if !alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if alive {
            // do not leave it behind
            // SAFETY: plain system call on a process started by the test.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(!alive, "sub-process {pid} survived");
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
    async fn the_process_group_is_killed_after_the_write_delay() {
        let pidfile = temp_path("group-pid");
        let _ = std::fs::remove_file(&pidfile);
        let big = secret(&"p".repeat(256 * 1024));
        let cmd = format!(
            "exec 3<&0; sleep 30 <&3 & echo $! > '{}'; exec sleep 30",
            pidfile.display()
        );
        let err = exec_with(
            &cmd,
            &big,
            Duration::from_millis(500),
            None,
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("command killed"), "{err:#}");
        assert_killed(&pidfile).await;
    }

    /// A command that closed its stdin but keeps running (the line is
    /// written, the pipe stays open on the side of pgpp) is bounded by
    /// `--exec-timeout`: its whole group is killed and the delivery fails.
    #[tokio::test]
    async fn the_run_time_is_bounded_by_the_exec_timeout() {
        let pidfile = temp_path("timeout-pid");
        let _ = std::fs::remove_file(&pidfile);
        let started = std::time::Instant::now();
        let cmd = format!(
            "sleep 100000 & echo $! > '{}'; exec 0<&-; sleep 100000",
            pidfile.display()
        );
        let err = exec_with(
            &cmd,
            &secret("pw-Test-123"),
            EXEC_WRITE_TIMEOUT,
            Some(Duration::from_millis(500)),
            std::future::pending(),
        )
        .await
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("within 0.5 s (--exec-timeout"), "{text}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_killed(&pidfile).await;
        // the same without the sub-process
        let err = exec_with(
            "exec 0<&-; sleep 100000",
            &secret("pw"),
            EXEC_WRITE_TIMEOUT,
            Some(Duration::from_millis(300)),
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("--exec-timeout"), "{err:#}");
        // a command that ends in time is not affected; None: no limit
        for timeout in [Some(Duration::from_secs(30)), None] {
            exec_with(
                "sleep 0.5; cat >/dev/null",
                &secret("pw"),
                EXEC_WRITE_TIMEOUT,
                timeout,
                std::future::pending(),
            )
            .await
            .unwrap();
        }
    }

    /// An interruption (Ctrl-C) while the command runs kills its group and
    /// fails the delivery, whether the line is written or not.
    #[tokio::test]
    async fn an_interruption_kills_the_process_group() {
        let big = secret(&"p".repeat(256 * 1024));
        for (tag, password) in [("short", secret("pw")), ("big", big)] {
            let pidfile = temp_path(&format!("intr-pid-{tag}"));
            let _ = std::fs::remove_file(&pidfile);
            let cmd = format!(
                "sleep 100000 & echo $! > '{}'; exec sleep 100000",
                pidfile.display()
            );
            let started = std::time::Instant::now();
            let err = exec_with(
                &cmd,
                &password,
                EXEC_WRITE_TIMEOUT,
                None,
                tokio::time::sleep(Duration::from_millis(500)),
            )
            .await
            .unwrap_err();
            let text = format!("{err:#}");
            assert!(text.contains("interrupted (Ctrl-C)"), "{tag}: {text}");
            assert!(!text.contains("ppppp"), "{tag}: {text}");
            assert!(started.elapsed() < Duration::from_secs(10), "{tag}");
            assert_killed(&pidfile).await;
        }
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_reported_first() {
        let err = exec("exit 4").await.unwrap_err();
        assert!(format!("{err:#}").contains("exit status: 4"), "{err:#}");
    }
}
