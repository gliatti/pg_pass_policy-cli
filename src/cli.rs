//! Command-line definitions (clap derive).

use std::time::Duration;

use clap::{ArgGroup, Args, Parser, Subcommand};
use serde_json::Value;

use crate::duration::{parse_duration, MAX_DURATION_SECS};
use crate::kv::parse_kv;
use crate::output::Format;
use crate::secret::EXEC_DEFAULT_TIMEOUT;

fn duration_arg(s: &str) -> Result<Duration, String> {
    parse_duration(s).map_err(|e| e.to_string())
}

/// `--exec-timeout`: a duration (`300s`, `5m`), a bare number of seconds,
/// or `0` for no limit.
fn exec_timeout_arg(s: &str) -> Result<ExecTimeout, String> {
    let t = s.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        let secs: u64 = t
            .parse()
            .map_err(|_| format!("invalid duration \"{s}\": number too large"))?;
        if secs == 0 {
            return Ok(ExecTimeout(None));
        }
        if secs > MAX_DURATION_SECS {
            return Err(format!(
                "invalid duration \"{s}\": at most 36500d (100 years)"
            ));
        }
        return Ok(ExecTimeout(Some(Duration::from_secs(secs))));
    }
    parse_duration(s)
        .map(|d| ExecTimeout(Some(d)))
        .map_err(|e| e.to_string())
}

/// Longest run time of the `--exec` command; `None`: unbounded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecTimeout(pub Option<Duration>);

/// Shown by `--help` as the default and parsed back by clap
/// ([`exec_timeout_arg`]): `300s`, or `0` for no limit.  Sub-second parts
/// are not rendered (the default is a whole number of seconds).
impl std::fmt::Display for ExecTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(d) => write!(f, "{}s", d.as_secs()),
            None => f.write_str("0"),
        }
    }
}

/// `--vault-skip-preflight` / `PGPP_VAULT_SKIP_PREFLIGHT`: the boolean
/// values of clap (`1`, `true`, `yes`, `on`, `0`, `false`, `no`, `off`...);
/// an empty value (`export PGPP_VAULT_SKIP_PREFLIGHT=`) counts as absent,
/// so that it does not turn every rotation into a usage error.
fn skip_preflight_arg(s: &str) -> Result<bool, String> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(false);
    }
    match t.to_ascii_lowercase().as_str() {
        "y" | "yes" | "t" | "true" | "on" | "1" => Ok(true),
        "n" | "no" | "f" | "false" | "off" | "0" => Ok(false),
        _ => Err(format!("value was not a boolean: \"{s}\"")),
    }
}

fn kv_arg(s: &str) -> Result<(String, Value), String> {
    parse_kv(s).map_err(|e| e.to_string())
}

/// Command-line client for the pg_pass_policy PostgreSQL extension.
///
/// Connection: DATABASE_URL, or the standard PGHOST / PGPORT / PGUSER /
/// PGPASSWORD / PGDATABASE variables, plus PGPASSFILE (default ~/.pgpass).
/// The connecting role must be a member of pass_policy_admin (or a superuser)
/// for the administration commands.
#[derive(Debug, Parser)]
#[command(name = "pgpp", version, about, long_about = None)]
pub struct Cli {
    /// Output format
    #[arg(short, long, global = true, value_enum, default_value_t = Format::Table)]
    pub format: Format,

    #[command(subcommand)]
    pub command: Command,
}

/// Options shared by `rotate` and `switch-pair`.  At least one delivery
/// (`--show`, `--exec`, `--vault-kv`) is required: the server returns the new
/// password once, so a rotation without delivery would lose it.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("delivery")
    .required(true)
    .multiple(true)
    .args(["show", "exec", "vault_kv"]))]
pub struct RotateOpts {
    /// Length of the generated password (server default: 24)
    #[arg(long, value_name = "N")]
    pub length: Option<i32>,

    /// Print the new password on stdout (once)
    #[arg(long, help_heading = DELIVERY_HEADING)]
    pub show: bool,

    /// Run CMD through `sh -c`; the password is written on its stdin,
    /// PGPP_ROLE and PGPP_VALID_UNTIL are set in its environment
    ///
    /// CMD itself must read the whole password line from its stdin before it
    /// exits (`cat`, `read -r pw`, `--from-file=/dev/stdin`): once CMD has
    /// exited, pgpp checks that nothing is left in the pipe.  A CMD that
    /// ignores its stdin or exits with a non-zero status is a failed
    /// delivery.  A CMD that leaves the reading to a background process
    /// (`cat > file &`) gives a non-deterministic result (reported as
    /// delivered or failed depending on timing): do not do that.
    #[arg(long, value_name = "CMD", help_heading = DELIVERY_HEADING)]
    pub exec: Option<String>,

    /// Longest run time of the --exec command (e.g. 300s, 5m, 1h; a bare
    /// number is in seconds; 0: no limit).  Past it, or on Ctrl-C, the
    /// process group of the command is killed and the delivery fails
    #[arg(
        long = "exec-timeout",
        value_name = "DELAY",
        default_value_t = ExecTimeout(Some(EXEC_DEFAULT_TIMEOUT)),
        value_parser = exec_timeout_arg,
        requires = "exec",
        help_heading = DELIVERY_HEADING
    )]
    pub exec_timeout: ExecTimeout,

    /// Write the credentials to HashiCorp Vault KV v2 at PATH: <mount>/<path>
    /// (first component = mount), or the path below the mount when
    /// --vault-mount is given
    #[arg(long = "vault-kv", value_name = "PATH", help_heading = DELIVERY_HEADING)]
    pub vault_kv: Option<String>,

    /// Vault KV v2 mount point; --vault-kv is then the path below it, without
    /// the mount (--vault-mount kv --vault-kv db/app writes kv/data/db/app)
    #[arg(long = "vault-mount", value_name = "MOUNT", requires = "vault_kv", help_heading = DELIVERY_HEADING)]
    pub vault_mount: Option<String>,

    /// Do not check VAULT_TOKEN (lookup-self, capabilities-self) before the
    /// rotation, for a token created with -no-default-policy.  An invalid
    /// token is then only detected by the write, after the rotation
    #[arg(
        long = "vault-skip-preflight",
        env = "PGPP_VAULT_SKIP_PREFLIGHT",
        action = clap::ArgAction::SetTrue,
        value_parser = skip_preflight_arg,
        help_heading = DELIVERY_HEADING
    )]
    pub vault_skip_preflight: bool,
}

const DELIVERY_HEADING: &str = "Delivery (choose at least one: --show, --exec or --vault-kv)";

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Password and lock status of login roles (view v_role_status)
    Status {
        /// Only this role
        #[arg(long, value_name = "ROLE")]
        role: Option<String>,
    },

    /// Roles in warning / grace / expired state, or expiring within a delay
    Expiring {
        /// Also list roles whose password expires within this delay (e.g. 14d, 12h, 30m)
        #[arg(long, value_name = "DELAY", value_parser = duration_arg)]
        within: Option<Duration>,
    },

    /// Currently locked roles (view v_locked)
    Locked,

    /// Generate and set a new password for a role (pass_policy.rotate_password)
    Rotate {
        /// Role to rotate
        role: String,
        #[command(flatten)]
        opts: RotateOpts,
    },

    /// Zero-downtime rotation of a role pair (pass_policy.switch_rotation_pair)
    #[command(name = "switch-pair")]
    SwitchPair {
        /// Pair name
        pair: String,
        #[command(flatten)]
        opts: RotateOpts,
    },

    /// Lock a role (pass_policy.lock_role)
    Lock {
        /// Role to lock
        role: String,
        /// Lock duration (e.g. 30m, 2h, 1d); without it the lock lasts until `unlock`
        #[arg(long = "for", value_name = "DURATION", value_parser = duration_arg)]
        duration: Option<Duration>,
        /// Reason stored in role_state and in the audit log
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
    },

    /// Unlock a role and reset its failure counter (pass_policy.unlock_role)
    Unlock {
        /// Role to unlock
        role: String,
    },

    /// Force the expiry of a role password now (pass_policy.expire_password)
    Expire {
        /// Role to expire
        role: String,
    },

    /// Manage password policy profiles
    Profile {
        #[command(subcommand)]
        action: ProfileCommand,
    },

    /// Audit log (pass_policy.audit_log), most recent first
    Audit {
        /// Only events newer than this delay (e.g. 24h, 7d)
        #[arg(long, value_name = "DELAY", value_parser = duration_arg)]
        since: Option<Duration>,
        /// Only this role
        #[arg(long, value_name = "ROLE")]
        role: Option<String>,
        /// Only this event type (e.g. password_rotated, role_locked)
        #[arg(long = "type", value_name = "TYPE")]
        event_type: Option<String>,
        /// Maximum number of rows (at least 1)
        #[arg(long, value_name = "N", default_value_t = 100,
              value_parser = clap::value_parser!(i64).range(1..))]
        limit: i64,
    },

    /// Check a candidate password against the effective profile of a role.
    /// The password is read from stdin (or prompted without echo on a terminal)
    /// and sent to the server as a bound parameter; exit code 3 when refused
    /// (1 is kept for real errors).
    Check {
        /// Role the password is intended for
        role: String,
    },

    /// Run one maintenance pass (pass_policy.run_maintenance) and list its actions
    Maintenance,

    /// Authentication failure counters held in shared memory
    #[command(name = "failed-attempts")]
    FailedAttempts,

    /// State of the background worker
    #[command(name = "worker-status")]
    WorkerStatus,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List profiles
    List,
    /// Show every setting of a profile
    Show {
        /// Profile name
        name: String,
    },
    /// Create a profile (settings default to the extension defaults)
    Create {
        /// Profile name
        name: String,
        /// Setting, as KEY=VALUE (repeatable), e.g. --set min_length=16 --set "max_age=30 days"
        #[arg(long = "set", value_name = "KEY=VALUE", value_parser = kv_arg)]
        set: Vec<(String, Value)>,
    },
    /// Change settings of a profile
    Alter {
        /// Profile name
        name: String,
        /// Setting, as KEY=VALUE (repeatable); VALUE "null" clears an optional setting
        #[arg(long = "set", value_name = "KEY=VALUE", required = true, value_parser = kv_arg)]
        set: Vec<(String, Value)>,
    },
    /// Drop an unassigned profile
    Drop {
        /// Profile name
        name: String,
    },
    /// Assign a profile to a role
    Assign {
        /// Role name
        role: String,
        /// Profile name
        profile: String,
    },
    /// Remove the profile assignment of a role (back to "default")
    Unassign {
        /// Role name
        role: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_rotate_options() {
        let cli = Cli::try_parse_from([
            "pgpp",
            "rotate",
            "app",
            "--length",
            "32",
            "--show",
            "--vault-kv",
            "secret/db/app",
            "-f",
            "json",
        ])
        .unwrap();
        assert_eq!(cli.format, Format::Json);
        match cli.command {
            Command::Rotate { role, opts } => {
                assert_eq!(role, "app");
                assert_eq!(opts.length, Some(32));
                assert!(opts.show);
                assert_eq!(opts.vault_kv.as_deref(), Some("secret/db/app"));
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn lock_for_parses_duration() {
        let cli = Cli::try_parse_from(["pgpp", "lock", "app", "--for", "30m"]).unwrap();
        match cli.command {
            Command::Lock { duration, .. } => {
                assert_eq!(duration, Some(Duration::from_secs(1800)));
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn invalid_duration_is_a_usage_error() {
        let err = Cli::try_parse_from(["pgpp", "lock", "app", "--for", "soon"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        let err = Cli::try_parse_from(["pgpp", "lock", "app", "--for", "36501d"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        let err = Cli::try_parse_from(["pgpp", "audit", "--since", "9999999999d"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn vault_mount_requires_vault_kv() {
        let err = Cli::try_parse_from(["pgpp", "rotate", "app", "--vault-mount", "kv", "--show"])
            .unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn help_documents_the_delivery_constraints() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let rotate = cmd.find_subcommand_mut("rotate").unwrap();
        let long = rotate.render_long_help().to_string();
        assert!(long.contains("background process"), "{long}");
        assert!(long.contains("kv/data/db/app"), "{long}");
        let short = rotate.render_help().to_string();
        assert!(short.contains("path below it"), "{short}");
        assert!(!short.contains("background process"), "{short}");
    }

    #[test]
    fn vault_skip_preflight_flag() {
        let parse = |args: &[&str]| match Cli::try_parse_from(args).unwrap().command {
            Command::Rotate { opts, .. } => opts.vault_skip_preflight,
            other => panic!("unexpected command {other:?}"),
        };
        assert!(parse(&[
            "pgpp",
            "rotate",
            "app",
            "--vault-kv",
            "secret/app",
            "--vault-skip-preflight"
        ]));
        // without --vault-kv the flag is accepted and has no effect (no
        // `requires`: PGPP_VAULT_SKIP_PREFLIGHT may be exported for every
        // invocation); PGPP_VAULT_SKIP_PREFLIGHT itself is exercised by the
        // integration tests, setting it here would race with other threads
        assert!(
            Cli::try_parse_from(["pgpp", "rotate", "app", "--show", "--vault-skip-preflight"])
                .is_ok()
        );
    }

    #[test]
    fn an_empty_skip_preflight_value_counts_as_absent() {
        for v in ["", "  "] {
            assert_eq!(skip_preflight_arg(v), Ok(false), "{v:?}");
        }
        for v in ["1", "true", "TRUE", "yes", "on", "y", "t"] {
            assert_eq!(skip_preflight_arg(v), Ok(true), "{v:?}");
        }
        for v in ["0", "false", "no", "off", "n", "f"] {
            assert_eq!(skip_preflight_arg(v), Ok(false), "{v:?}");
        }
        assert!(skip_preflight_arg("maybe").is_err());
        // the value given to the flag by the command line
        let err = Cli::try_parse_from([
            "pgpp",
            "rotate",
            "app",
            "--show",
            "--vault-skip-preflight=maybe",
        ])
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn rotation_without_delivery_is_a_usage_error() {
        for cmd in ["rotate", "switch-pair"] {
            let err = Cli::try_parse_from(["pgpp", cmd, "app"]).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{cmd}");
            let err = Cli::try_parse_from(["pgpp", cmd, "app", "--length", "32"]).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{cmd}");
            assert!(Cli::try_parse_from(["pgpp", cmd, "app", "--show"]).is_ok());
            assert!(Cli::try_parse_from(["pgpp", cmd, "app", "--exec", "cat"]).is_ok());
            assert!(Cli::try_parse_from(["pgpp", cmd, "app", "--vault-kv", "secret/app"]).is_ok());
            assert!(Cli::try_parse_from([
                "pgpp",
                cmd,
                "app",
                "--show",
                "--exec",
                "cat",
                "--vault-kv",
                "secret/app"
            ])
            .is_ok());
        }
    }

    #[test]
    fn exec_timeout_values() {
        let parse = |args: &[&str]| {
            let mut full = vec!["pgpp", "rotate", "app", "--exec", "cat"];
            full.extend_from_slice(args);
            match Cli::try_parse_from(full).map(|c| c.command) {
                Ok(Command::Rotate { opts, .. }) => Ok(opts.exec_timeout.0),
                Ok(other) => panic!("unexpected command {other:?}"),
                Err(e) => Err(e.exit_code()),
            }
        };
        assert_eq!(parse(&[]), Ok(Some(EXEC_DEFAULT_TIMEOUT)), "default");
        assert_eq!(EXEC_DEFAULT_TIMEOUT, Duration::from_secs(300), "README");
        // the default shown by --help is the one parsed
        let help = Cli::try_parse_from(["pgpp", "rotate", "--help"])
            .unwrap_err()
            .to_string();
        assert!(help.contains("[default: 300s]"), "{help}");
        assert_eq!(ExecTimeout(None).to_string(), "0");
        assert_eq!(
            parse(&["--exec-timeout", "5m"]),
            Ok(Some(Duration::from_secs(300)))
        );
        assert_eq!(
            parse(&["--exec-timeout", "45"]),
            Ok(Some(Duration::from_secs(45)))
        );
        assert_eq!(
            parse(&["--exec-timeout", "1h30m"]),
            Ok(Some(Duration::from_secs(5400)))
        );
        assert_eq!(parse(&["--exec-timeout", "0"]), Ok(None), "unbounded");
        assert_eq!(parse(&["--exec-timeout", "000"]), Ok(None), "unbounded");
        assert_eq!(
            parse(&["--exec-timeout", &MAX_DURATION_SECS.to_string()]),
            Ok(Some(Duration::from_secs(MAX_DURATION_SECS)))
        );
        let over = (MAX_DURATION_SECS + 1).to_string();
        for bad in ["", "-1", "5x", "0s", "99999999999999999999999", &over] {
            assert_eq!(parse(&["--exec-timeout", bad]), Err(2), "{bad:?}");
        }
        // only with --exec
        let err = Cli::try_parse_from(["pgpp", "rotate", "app", "--show", "--exec-timeout", "5m"])
            .unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn audit_limit_must_be_positive() {
        let err = Cli::try_parse_from(["pgpp", "audit", "--limit", "0"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        let err = Cli::try_parse_from(["pgpp", "audit", "--limit", "-5"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(Cli::try_parse_from(["pgpp", "audit", "--limit", "1"]).is_ok());
    }

    #[test]
    fn profile_set_is_parsed_by_clap() {
        let err =
            Cli::try_parse_from(["pgpp", "profile", "create", "p", "--set", "nokv"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        let cli = Cli::try_parse_from([
            "pgpp",
            "profile",
            "alter",
            "p",
            "--set",
            "min_length=16",
            "--set",
            "max_age=null",
        ])
        .unwrap();
        match cli.command {
            Command::Profile {
                action: ProfileCommand::Alter { name, set },
            } => {
                assert_eq!(name, "p");
                assert_eq!(set[0], ("min_length".to_string(), Value::from(16)));
                assert_eq!(set[1], ("max_age".to_string(), Value::Null));
            }
            other => panic!("unexpected command {other:?}"),
        }
    }
}
