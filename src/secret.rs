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
#[derive(Clone, Copy, Debug, PartialEq)]
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
/// The check is only meaningful when `cmd` itself reads the line.  A hook
/// that leaves the reading to a background process (`cat > file &`) gives
/// a non-deterministic result: depending on whether that process has read
/// the line when `sh` exits, the delivery is reported as successful or as
/// failed (and the drain below may take the line from it).  Do not do that.
///
/// The write and the wait for the command run concurrently: a line larger
/// than the pipe, sent to a command that exits without reading it, cannot
/// block pgpp.  The write is bounded by [`EXEC_WRITE_TIMEOUT`], the whole
/// run of the command by `timeout` (`--exec-timeout`, `None`: unbounded).
/// `sh` runs in its own process group: when the write fails or times out,
/// when `timeout` is reached, or when `interrupt` reports a Ctrl-C (`SIGINT`,
/// which the terminal sends to the foreground group of pgpp only), the whole group
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
    interrupt: &mut Interrupt,
) -> Result<()> {
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
        interrupt.wait(),
    )
    .await
}

/// Ctrl-C (`SIGINT`) during a rotation.  [`Interrupt::install`] is called
/// before the SQL call that rotates the password: from then on a Ctrl-C no
/// longer kills pgpp (which would lose the new password without a word) but
/// is recorded, ends the step in progress (SQL call, Vault write, `--exec`
/// command) and makes every delivery still to come fail, so that pgpp
/// exits with code 1 and asks for a new rotation.  The handler stays
/// installed until the end of the process.
pub struct Interrupt {
    /// `None` when the handler could not be installed (Ctrl-C then keeps
    /// its default action).
    signal: Option<tokio::signal::unix::Signal>,
    received: bool,
}

impl Interrupt {
    /// Installs the handler at once (not on the first wait).
    pub fn install() -> Self {
        let signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        {
            Ok(s) => Some(s),
            Err(e) => {
                crate::report(
                    crate::Report::Warning,
                    &anyhow::Error::new(e).context("cannot catch Ctrl-C during the rotation"),
                );
                None
            }
        };
        Interrupt {
            signal,
            received: false,
        }
    }

    /// An `Interrupt` that has already received its Ctrl-C (tests).
    #[cfg(test)]
    pub(crate) fn already_received() -> Self {
        Interrupt {
            signal: None,
            received: true,
        }
    }

    /// An `Interrupt` that never receives anything (tests).
    #[cfg(test)]
    pub(crate) fn never() -> Self {
        Interrupt {
            signal: None,
            received: false,
        }
    }

    /// An `Interrupt` listening to another signal (tests: `SIGUSR1` here,
    /// `SIGUSR2` in the tests of `commands`, which nothing else in the test
    /// process uses, rather than `SIGINT`).
    #[cfg(test)]
    pub(crate) fn on(kind: tokio::signal::unix::SignalKind) -> Self {
        Interrupt {
            signal: Some(tokio::signal::unix::signal(kind).unwrap()),
            received: false,
        }
    }

    /// True once a Ctrl-C was received (as seen by a [`Interrupt::wait`]
    /// that ended).
    pub fn received(&self) -> bool {
        self.received
    }

    /// Same as [`Interrupt::received`], after taking without waiting a
    /// Ctrl-C delivered to the process but not yet seen by a wait (between
    /// two steps, when no wait is in progress).  The runtime first gets one
    /// turn (`yield_now`) so that a signal already delivered reaches the
    /// listener; the wait is then polled once (zero delay).
    pub async fn poll_received(&mut self) -> bool {
        if !self.received {
            tokio::task::yield_now().await;
            let _ = tokio::time::timeout(Duration::ZERO, self.wait()).await;
        }
        self.received
    }

    /// Ends when a Ctrl-C is received, at once if one already was.
    /// Cancel-safe: a dropped wait loses no signal.
    pub async fn wait(&mut self) {
        if self.received {
            return;
        }
        match &mut self.signal {
            Some(s) => {
                if s.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending::<()>().await,
        }
        self.received = true;
    }
}

/// Set by [`on_sigint`] while a [`SigintGuard`] is installed.
static SIGINT_RECEIVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    // async-signal-safe: a plain atomic store
    SIGINT_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Catches `SIGINT` for a synchronous step (the password prompt of
/// `check`): while the guard lives, a Ctrl-C only sets a flag (no
/// `SA_RESTART`: a read in progress returns `EINTR`), so that the code that
/// changed the terminal settings can restore them; the previous disposition
/// is put back on drop.  Unlike [`Interrupt`], nothing stays installed
/// afterwards: a Ctrl-C later on keeps its usual effect.
pub struct SigintGuard {
    /// `None` when the handler could not be installed.
    previous: Option<libc::sigaction>,
}

impl SigintGuard {
    pub fn install() -> Self {
        SIGINT_RECEIVED.store(false, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: `sigaction` structures fully initialised (zeroed, empty
        // mask); the handler only stores into an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            let mut previous: libc::sigaction = std::mem::zeroed();
            let ok = libc::sigaction(libc::SIGINT, &action, &mut previous) == 0;
            SigintGuard {
                previous: ok.then_some(previous),
            }
        }
    }

    /// True once a `SIGINT` was received while the guard is installed.
    pub fn received(&self) -> bool {
        SIGINT_RECEIVED.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for SigintGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            // SAFETY: restores the disposition saved by `install`.
            unsafe {
                libc::sigaction(libc::SIGINT, previous, std::ptr::null_mut());
            }
        }
    }
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
    let deadline = async {
        match timeout {
            Some(t) => tokio::time::sleep(t).await,
            None => std::future::pending().await,
        }
    };
    run_exec_until(
        cmd,
        password,
        env,
        write_timeout,
        timeout,
        deadline,
        interrupt,
    )
    .await
}

/// [`run_exec_with`] with the `--exec-timeout` given as a future
/// (`deadline`); `timeout` is only used in the message.
async fn run_exec_until(
    cmd: &str,
    password: &Secret,
    env: Env<'_>,
    write_timeout: Duration,
    timeout: Option<Duration>,
    deadline: impl std::future::Future<Output = ()>,
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
        let first = first_event(
            tokio::time::timeout(write_timeout, &mut write),
            child.wait(),
            &mut interrupt,
            &mut deadline,
        )
        .await;
        match first {
            First::Written(Ok(Ok(()))) => (Written::Complete, None, None),
            First::Written(Ok(Err(e))) => (Written::Failed(e), None, None),
            First::Written(Err(_)) => (Written::TimedOut, None, None),
            // The child exited first (or was stopped): take a write that
            // ended at the same time (a zero timeout still polls it once),
            // give up the rest, nobody will read it.
            First::Exited(status) => (poll_once(&mut write).await, Some(status), None),
            First::Stopped(s) => (poll_once(&mut write).await, None, Some(s)),
        }
    };
    // From here on the write end is closed (owned by the dropped future).
    let write_failed = matches!(written, Written::Failed(_) | Written::TimedOut);
    if exited.is_none() && stop.is_none() && !write_failed {
        // line written: wait for the command, within the same bounds
        match wait_or_stop(child.wait(), &mut interrupt, &mut deadline).await {
            Ok(status) => exited = Some(status),
            Err(s) => stop = Some(s),
        }
    }
    // The delay expired while the command was exiting: if it has already
    // exited (reaped right now, without waiting) after the line was
    // entirely written, it finished in time and is checked as usual (exit
    // status, unread bytes) rather than reported as killed.
    if stop == Some(Stop::TimedOut) && matches!(written, Written::Complete) {
        if let Ok(Some(status)) = child.try_wait() {
            exited = Some(Ok(status));
            stop = None;
        }
    }
    // the command was killed by pgpp, rather than exited by itself
    let killed = exited.is_none();
    if killed {
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
        Written::Failed(e) => bail!("{}", write_failure(&e)),
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

/// Message of a failed write of the password line.  The write cannot fail
/// with `EPIPE`: pgpp keeps a read end of the pipe (`probe`) until the
/// drain, so a command that exits or closes its stdin never makes the write
/// fail; only another I/O error of the pipe gets here.  It is reported in
/// the same terms whether the error interrupted a running command (killed
/// by pgpp right after) or came at the instant the command exited.
fn write_failure(e: &std::io::Error) -> String {
    format!(
        "cannot write the password to the stdin of the --exec command ({e}): the command \
         did not receive it (killed if it was still running)"
    )
}

/// First event of [`run_exec_with`], while the line is being written.
#[derive(Debug, PartialEq)]
enum First<W, S> {
    /// The write ended (or its delay expired).
    Written(W),
    /// The command exited before the end of the write.
    Exited(S),
    /// Ctrl-C or `--exec-timeout` before the end of the write and of the
    /// command.
    Stopped(Stop),
}

/// First wait of [`run_exec_with`]: the end of the write, of the command, a
/// Ctrl-C or `--exec-timeout`.  `biased`, in this order: the write may stay
/// first (a line entirely written is then checked by the second wait), but
/// a command that has exited must win over a Ctrl-C or a delay ready at the
/// same instant, as in [`wait_or_stop`].
async fn first_event<W, S>(
    write: impl std::future::Future<Output = W>,
    wait: impl std::future::Future<Output = S>,
    interrupt: impl std::future::Future<Output = ()>,
    deadline: impl std::future::Future<Output = ()>,
) -> First<W, S> {
    tokio::select! {
        biased;
        w = write => First::Written(w),
        status = wait => First::Exited(status),
        () = interrupt => First::Stopped(Stop::Interrupted),
        () = deadline => First::Stopped(Stop::TimedOut),
    }
}

/// Second wait of [`run_exec_with`], once the line is written: the end of
/// the command, a Ctrl-C or `--exec-timeout`.  `biased`, the end of the
/// command first: a command that exits at the instant the delay expires (or
/// a Ctrl-C arrives) has finished and must not be reported as killed; an
/// unbiased `select!` would pick one of the ready branches at random.
async fn wait_or_stop<T>(
    wait: impl std::future::Future<Output = T>,
    interrupt: impl std::future::Future<Output = ()>,
    deadline: impl std::future::Future<Output = ()>,
) -> std::result::Result<T, Stop> {
    tokio::select! {
        biased;
        status = wait => Ok(status),
        () = interrupt => Err(Stop::Interrupted),
        () = deadline => Err(Stop::TimedOut),
    }
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
/// once the child has exited and the write end of pgpp is closed.  The read
/// is non-blocking: a descendant that outlived `sh` may still hold a write
/// end (`exec 3>/proc/self/fd/0; sleep 100 &`), in which case an empty pipe
/// never reaches end of file; the drain then stops at once (`EAGAIN`)
/// instead of waiting for that descendant.  `O_NONBLOCK` is set on the open
/// file description shared with the stdin of the command: a reader that
/// outlived `sh` then gets `EAGAIN` too, which is fine, it must not read the
/// line anyway.
fn unread_bytes(probe: std::os::fd::OwnedFd) -> Result<usize> {
    use std::os::fd::AsRawFd;
    let fd = probe.as_raw_fd();
    // SAFETY: fcntl on a descriptor owned by `probe`.
    let nonblocking = unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0
    };
    if !nonblocking {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())
            .context("cannot make the pipe non-blocking"));
    }
    let mut file = std::fs::File::from(probe);
    let mut buf = Zeroizing::new([0u8; 512]);
    let mut total = 0;
    loop {
        match file.read(&mut buf[..]) {
            Ok(0) => return Ok(total),
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(total),
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

    /// A signal delivered while no wait is in progress is seen by
    /// `poll_received` (not by `received`), without blocking otherwise.
    #[tokio::test]
    async fn a_signal_between_two_steps_is_seen_without_waiting() {
        let mut interrupt = Interrupt::on(tokio::signal::unix::SignalKind::user_defined1());
        let started = std::time::Instant::now();
        assert!(!interrupt.poll_received().await);
        assert!(started.elapsed() < Duration::from_secs(1));
        // SAFETY: plain system call; SIGUSR1 is caught by the listener above.
        unsafe {
            libc::raise(libc::SIGUSR1);
        }
        assert!(!interrupt.received());
        assert!(interrupt.poll_received().await);
        assert!(interrupt.received());
        assert!(Interrupt::already_received().poll_received().await);
        assert!(!Interrupt::never().poll_received().await);
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

    /// The second wait prefers the end of the command to a delay or a
    /// Ctrl-C ready at the same instant (`biased`): with every branch ready,
    /// an unbiased `select!` would report « killed » about two times in
    /// three.
    #[tokio::test]
    async fn an_exit_at_the_deadline_is_not_reported_as_killed() {
        for _ in 0..200 {
            let r = wait_or_stop(
                std::future::ready(7),
                std::future::ready(()),
                std::future::ready(()),
            )
            .await;
            assert_eq!(r, Ok(7));
        }
        let pending = std::future::pending::<i32>;
        let r = wait_or_stop(pending(), std::future::ready(()), std::future::ready(())).await;
        assert_eq!(r, Err(Stop::Interrupted));
        let r = wait_or_stop(pending(), std::future::pending(), std::future::ready(())).await;
        assert_eq!(r, Err(Stop::TimedOut));
    }

    /// The first wait (write still running) is biased too: write, then the
    /// end of the command, then Ctrl-C, then the delay.
    #[tokio::test]
    async fn the_first_wait_prefers_the_exit_to_a_stop() {
        use std::future::{pending, ready};
        for _ in 0..200 {
            let r = first_event(ready('w'), ready(7), ready(()), ready(())).await;
            assert_eq!(r, First::Written('w'));
            let r = first_event(pending::<char>(), ready(7), ready(()), ready(())).await;
            assert_eq!(r, First::Exited(7));
        }
        let r = first_event(pending::<char>(), pending::<i32>(), ready(()), ready(())).await;
        assert_eq!(r, First::Stopped(Stop::Interrupted));
        let r = first_event(pending::<char>(), pending::<i32>(), pending(), ready(())).await;
        assert_eq!(r, First::Stopped(Stop::TimedOut));
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
    /// `--exec-timeout` expiring while the command exits: the deadline
    /// blocks the runtime until the command (which read the whole line) has
    /// exited, then fires before the exit is seen by the wait; the command is reaped right after the delay and
    /// the delivery succeeds instead of « killed ».  A command still running
    /// at the deadline, or one that exited without reading the line, still
    /// fails.
    #[tokio::test]
    async fn a_command_that_exits_just_before_the_deadline_succeeds() {
        let env = || Env {
            role: "app",
            valid_until: None,
            extra: &[],
        };
        // expires after 0.1 s (the line is written by then), but blocks the
        // (single-threaded) runtime for 0.8 s before firing
        let late_deadline = || async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            std::thread::sleep(Duration::from_millis(800));
        };
        let pw = secret("pw-Test-123");
        run_exec_until(
            "read l; sleep 0.2; exit 0",
            &pw,
            env(),
            EXEC_WRITE_TIMEOUT,
            Some(Duration::from_millis(800)),
            late_deadline(),
            std::future::pending(),
        )
        .await
        .unwrap();
        let err = run_exec_until(
            "sleep 0.2; exit 0",
            &pw,
            env(),
            EXEC_WRITE_TIMEOUT,
            Some(Duration::from_millis(800)),
            late_deadline(),
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("without reading"), "{err:#}");
        let err = run_exec_until(
            "read l; sleep 100000",
            &pw,
            env(),
            EXEC_WRITE_TIMEOUT,
            Some(Duration::from_millis(800)),
            late_deadline(),
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("within 0.8 s (--exec-timeout"),
            "{err:#}"
        );
    }

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

    /// One message for every write failure (an I/O error other than
    /// `EPIPE`, which the read end kept by pgpp rules out).
    #[test]
    fn a_write_failure_says_the_password_was_not_received() {
        let e = std::io::Error::from_raw_os_error(libc::EIO);
        let m = write_failure(&e);
        assert!(
            m.starts_with("cannot write the password to the stdin of the --exec command ("),
            "{m}"
        );
        assert!(m.contains(&e.to_string()), "{m}");
        assert!(
            m.ends_with("the command did not receive it (killed if it was still running)"),
            "{m}"
        );
    }

    /// A descendant that outlives `sh` and holds a write end of the pipe
    /// (opened through /proc) does not block the drain: the check returns
    /// as soon as `sh` exits.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_surviving_writer_does_not_block_the_drain() {
        let pidfile = temp_path("writer-pid");
        let _ = std::fs::remove_file(&pidfile);
        let cmd = format!(
            "read -r pw; exec 3>/proc/self/fd/0; sleep 30 & echo $! > '{}'",
            pidfile.display()
        );
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(10), exec(&cmd)).await;
        let elapsed = started.elapsed();
        // do not leave the sleep behind
        if wait_for(&pidfile).await {
            let text = std::fs::read_to_string(&pidfile).unwrap_or_default();
            if let Ok(pid) = text.trim().parse::<libc::pid_t>() {
                if pid > 1 {
                    // SAFETY: plain system call on a process started by the test.
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&pidfile);
        let r = r.expect("the drain blocked on the surviving writer");
        r.unwrap_or_else(|e| panic!("{e:#}"));
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    /// Current handler of SIGINT.
    fn sigint_handler() -> libc::sighandler_t {
        // SAFETY: query only (no new action).
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGINT, std::ptr::null(), &mut current),
                0
            );
            current.sa_sigaction
        }
    }

    /// While the guard lives, a SIGINT (as raised by rpassword on a typed
    /// Ctrl-C) is recorded instead of killing the process; the previous
    /// disposition is restored on drop.
    #[test]
    fn the_sigint_guard_catches_and_restores() {
        let before = sigint_handler();
        let guard = SigintGuard::install();
        assert!(!guard.received());
        assert_ne!(sigint_handler(), before);
        // SAFETY: the guard's handler is installed: the signal only sets a flag.
        unsafe {
            libc::raise(libc::SIGINT);
        }
        assert!(guard.received());
        drop(guard);
        assert_eq!(sigint_handler(), before);
        // a new guard starts without a received signal
        let guard = SigintGuard::install();
        assert!(!guard.received());
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_reported_first() {
        let err = exec("exit 4").await.unwrap_err();
        assert!(format!("{err:#}").contains("exit status: 4"), "{err:#}");
    }
}
