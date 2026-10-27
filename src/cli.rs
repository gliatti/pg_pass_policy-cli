//! Command-line definitions (clap derive).

use std::time::Duration;

use clap::{ArgGroup, Args, Parser, Subcommand};
use serde_json::Value;

use crate::duration::parse_duration;
use crate::kv::parse_kv;
use crate::output::Format;

fn duration_arg(s: &str) -> Result<Duration, String> {
    parse_duration(s).map_err(|e| e.to_string())
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
#[derive(Debug, Args, Default)]
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
    #[arg(long, value_name = "CMD", help_heading = DELIVERY_HEADING)]
    pub exec: Option<String>,

    /// Write the credentials to HashiCorp Vault KV v2 at PATH
    /// (first path component = mount unless --vault-mount is given)
    #[arg(long = "vault-kv", value_name = "PATH", help_heading = DELIVERY_HEADING)]
    pub vault_kv: Option<String>,

    /// Vault KV v2 mount point (default: first component of --vault-kv)
    #[arg(long = "vault-mount", value_name = "MOUNT", requires = "vault_kv", help_heading = DELIVERY_HEADING)]
    pub vault_mount: Option<String>,
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
    }

    #[test]
    fn vault_mount_requires_vault_kv() {
        let err = Cli::try_parse_from(["pgpp", "rotate", "app", "--vault-mount", "kv", "--show"])
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
