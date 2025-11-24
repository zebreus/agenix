//! Command-line argument parsing and definitions for agenix.
//!
//! This module defines the CLI interface using clap's derive macros with subcommands.

use clap::{Parser, Subcommand};
use std::env;

#[derive(Parser, Debug)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "edit and rekey age secret files",
    after_help = concat!("agenix version: ", env!("CARGO_PKG_VERSION"))
)]
pub struct Args {
    /// Path to Nix rules file (can also be set via RULES env var)
    #[arg(
        short = 'r',
        long,
        env = "RULES",
        value_name = "FILE",
        default_value = "./secrets.nix",
        global = true
    )]
    pub rules: String,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Edit a secret file using $EDITOR
    #[command(visible_alias = "e")]
    Edit {
        /// The secret file to edit
        #[arg(value_name = "FILE", allow_hyphen_values = true)]
        file: String,

        /// Identity (private key) to use when decrypting
        #[arg(short, long, value_name = "KEY")]
        identity: Option<String>,

        /// Editor command to use (defaults to $EDITOR or vi)
        #[arg(short = 'e', long, env = "EDITOR", value_name = "COMMAND", default_value_t = String::from("vi"))]
        editor: String,
    },

    /// Decrypt a secret file to stdout or a file
    #[command(visible_alias = "d")]
    Decrypt {
        /// The secret file to decrypt
        #[arg(value_name = "FILE", allow_hyphen_values = true)]
        file: String,

        /// Identity (private key) to use when decrypting
        #[arg(short, long, value_name = "KEY")]
        identity: Option<String>,

        /// Output file (defaults to stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Re-encrypt all secrets with updated recipients
    #[command(visible_alias = "r")]
    Rekey {
        /// Identity (private key) to use when decrypting
        #[arg(short, long, value_name = "KEY")]
        identity: Option<String>,
    },

    /// Generate secrets using generator functions from rules
    #[command(visible_alias = "g")]
    Generate {
        /// Overwrite existing secret files
        #[arg(short, long)]
        force: bool,

        /// Show what would be generated without making changes
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    /// Helper to restore environment variable after test
    fn with_env_var<F>(key: &str, value: Option<&str>, f: F)
    where
        F: FnOnce(),
    {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let original = std::env::var(key).ok();

        match value {
            // SAFETY: We hold ENV_LOCK to ensure no other thread is accessing env vars
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }

        f();

        match original {
            // SAFETY: We hold ENV_LOCK to ensure no other thread is accessing env vars
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn test_edit_subcommand() {
        let args = Args::try_parse_from(["agenix", "edit", "test.age"]).unwrap();
        assert!(matches!(args.command, Some(Command::Edit { .. })));
        assert!(!args.verbose);
        if let Some(Command::Edit { file, identity, .. }) = args.command {
            assert_eq!(file, "test.age".to_string());
            assert_eq!(identity, None);
        }
    }

    #[test]
    fn test_edit_short_alias() {
        let args = Args::try_parse_from(["agenix", "e", "test.age"]).unwrap();
        assert!(matches!(args.command, Some(Command::Edit { .. })));
    }

    #[test]
    fn test_rekey_subcommand() {
        let args = Args::try_parse_from(["agenix", "rekey"]).unwrap();
        assert!(matches!(args.command, Some(Command::Rekey { .. })));
    }

    #[test]
    fn test_rekey_short_alias() {
        let args = Args::try_parse_from(["agenix", "r"]).unwrap();
        assert!(matches!(args.command, Some(Command::Rekey { .. })));
    }

    #[test]
    fn test_decrypt_subcommand_with_identity() {
        let args = Args::try_parse_from(["agenix", "decrypt", "secret.age", "-i", "/path/to/key"])
            .unwrap();
        if let Some(Command::Decrypt { file, identity, .. }) = args.command {
            assert_eq!(file, "secret.age".to_string());
            assert_eq!(identity, Some("/path/to/key".to_string()));
        } else {
            panic!("Expected Decrypt command");
        }
    }

    #[test]
    fn test_decrypt_short_alias() {
        let args = Args::try_parse_from(["agenix", "d", "secret.age"]).unwrap();
        assert!(matches!(args.command, Some(Command::Decrypt { .. })));
    }

    #[test]
    fn test_verbose_flag_with_edit() {
        let args = Args::try_parse_from(["agenix", "-v", "edit", "test.age"]).unwrap();
        assert!(args.verbose);
        assert!(matches!(args.command, Some(Command::Edit { .. })));
    }

    #[test]
    fn test_verbose_flag_after_subcommand() {
        let args = Args::try_parse_from(["agenix", "edit", "-v", "test.age"]).unwrap();
        assert!(args.verbose);
        assert!(matches!(args.command, Some(Command::Edit { .. })));
    }

    #[test]
    fn test_args_parsing_default_editor() {
        with_env_var("EDITOR", None, || {
            let args = Args::try_parse_from(["agenix", "edit", "test.age"]).unwrap();
            if let Some(Command::Edit { file, editor, .. }) = args.command {
                assert_eq!(file, "test.age".to_string());
                assert_eq!(editor, "vi");
            } else {
                panic!("Expected Edit command");
            }
        });
    }

    #[test]
    fn test_editor_env_overrides_default() {
        with_env_var("EDITOR", Some("nano"), || {
            let args = Args::try_parse_from(["agenix", "edit", "test.age"]).unwrap();
            if let Some(Command::Edit { editor, .. }) = args.command {
                assert_eq!(editor, "nano");
            } else {
                panic!("Expected Edit command");
            }
        });
    }

    #[test]
    fn test_editor_flag_overrides_env() {
        with_env_var("EDITOR", Some("nano"), || {
            let args =
                Args::try_parse_from(["agenix", "edit", "--editor", "vim", "test.age"]).unwrap();
            if let Some(Command::Edit { editor, .. }) = args.command {
                assert_eq!(editor, "vim");
            } else {
                panic!("Expected Edit command");
            }
        });
    }

    #[test]
    fn test_editor_flag_without_env() {
        with_env_var("EDITOR", None, || {
            let args =
                Args::try_parse_from(["agenix", "edit", "--editor", "micro", "test.age"]).unwrap();
            if let Some(Command::Edit { editor, .. }) = args.command {
                assert_eq!(editor, "micro");
            } else {
                panic!("Expected Edit command");
            }
        });
    }

    #[test]
    fn test_rules_env_var() {
        with_env_var("RULES", Some("/custom/path/secrets.nix"), || {
            let args = Args::try_parse_from(["agenix", "generate"]).unwrap();
            assert_eq!(args.rules, "/custom/path/secrets.nix");
        });
    }

    #[test]
    fn test_generate_subcommand() {
        let args = Args::try_parse_from(["agenix", "generate"]).unwrap();
        assert!(matches!(args.command, Some(Command::Generate { .. })));
        if let Some(Command::Generate { force, dry_run }) = args.command {
            assert!(!force);
            assert!(!dry_run);
        }
    }

    #[test]
    fn test_generate_short_alias() {
        let args = Args::try_parse_from(["agenix", "g"]).unwrap();
        assert!(matches!(args.command, Some(Command::Generate { .. })));
    }

    #[test]
    fn test_generate_force_flag() {
        let args = Args::try_parse_from(["agenix", "generate", "--force"]).unwrap();
        if let Some(Command::Generate { force, dry_run }) = args.command {
            assert!(force);
            assert!(!dry_run);
        } else {
            panic!("Expected Generate command");
        }
    }

    #[test]
    fn test_generate_force_short_flag() {
        let args = Args::try_parse_from(["agenix", "generate", "-f"]).unwrap();
        if let Some(Command::Generate { force, dry_run }) = args.command {
            assert!(force);
            assert!(!dry_run);
        } else {
            panic!("Expected Generate command");
        }
    }

    #[test]
    fn test_generate_dry_run_flag() {
        let args = Args::try_parse_from(["agenix", "generate", "--dry-run"]).unwrap();
        if let Some(Command::Generate { force, dry_run }) = args.command {
            assert!(!force);
            assert!(dry_run);
        } else {
            panic!("Expected Generate command");
        }
    }

    #[test]
    fn test_generate_dry_run_short_flag() {
        let args = Args::try_parse_from(["agenix", "generate", "-n"]).unwrap();
        if let Some(Command::Generate { force, dry_run }) = args.command {
            assert!(!force);
            assert!(dry_run);
        } else {
            panic!("Expected Generate command");
        }
    }

    #[test]
    fn test_generate_force_and_dry_run() {
        let args = Args::try_parse_from(["agenix", "generate", "--force", "--dry-run"]).unwrap();
        if let Some(Command::Generate { force, dry_run }) = args.command {
            assert!(force);
            assert!(dry_run);
        } else {
            panic!("Expected Generate command");
        }
    }

    #[test]
    fn test_generate_short_flags_combined() {
        let args = Args::try_parse_from(["agenix", "generate", "-f", "-n"]).unwrap();
        if let Some(Command::Generate { force, dry_run }) = args.command {
            assert!(force);
            assert!(dry_run);
        } else {
            panic!("Expected Generate command");
        }
    }

    #[test]
    fn test_help_contains_version() {
        use clap::CommandFactory;

        let mut cmd = Args::command();
        let help = cmd.render_help().to_string();

        // Check that help contains the version information at the end
        let expected_version_line = format!("agenix version: {}", env!("CARGO_PKG_VERSION"));
        assert!(
            help.contains(&expected_version_line),
            "Help output should contain version line: {expected_version_line}",
        );

        // Also verify it's near the end (after the Commands section)
        let commands_pos = help
            .find("Commands:")
            .expect("Help should contain Commands section");
        let version_pos = help
            .find(&expected_version_line)
            .expect("Help should contain version line");
        assert!(
            version_pos > commands_pos,
            "Version line should appear after Commands section"
        );
    }

    #[test]
    fn test_no_subcommand() {
        let args = Args::try_parse_from(["agenix"]).unwrap();
        assert!(args.command.is_none());
    }

    #[test]
    fn test_decrypt_with_output() {
        let args =
            Args::try_parse_from(["agenix", "decrypt", "secret.age", "-o", "/path/to/output"])
                .unwrap();
        if let Some(Command::Decrypt { file, output, .. }) = args.command {
            assert_eq!(file, "secret.age".to_string());
            assert_eq!(output, Some("/path/to/output".to_string()));
        } else {
            panic!("Expected Decrypt command");
        }
    }

    #[test]
    fn test_rekey_with_identity() {
        let args = Args::try_parse_from(["agenix", "rekey", "-i", "/path/to/key"]).unwrap();
        if let Some(Command::Rekey { identity }) = args.command {
            assert_eq!(identity, Some("/path/to/key".to_string()));
        } else {
            panic!("Expected Rekey command");
        }
    }

    #[test]
    fn test_global_rules_option() {
        let args =
            Args::try_parse_from(["agenix", "--rules", "/custom/rules.nix", "generate"]).unwrap();
        assert_eq!(args.rules, "/custom/rules.nix");
        assert!(matches!(args.command, Some(Command::Generate { .. })));
    }

    #[test]
    fn test_global_rules_short_flag() {
        let args = Args::try_parse_from(["agenix", "-r", "/custom/rules.nix", "generate"]).unwrap();
        assert_eq!(args.rules, "/custom/rules.nix");
        assert!(matches!(args.command, Some(Command::Generate { .. })));
    }

    #[test]
    fn test_edit_editor_short_flag() {
        let args = Args::try_parse_from(["agenix", "edit", "-e", "nano", "test.age"]).unwrap();
        if let Some(Command::Edit { editor, .. }) = args.command {
            assert_eq!(editor, "nano");
        } else {
            panic!("Expected Edit command");
        }
    }

    // Tests to ensure old flag-based interface no longer works
    // These verify that the migration to subcommands is complete

    #[test]
    fn test_old_edit_flag_rejected() {
        // Old: agenix -e file.age
        // New: agenix edit file.age
        let result = Args::try_parse_from(["agenix", "-e", "test.age"]);
        assert!(result.is_err(), "Old -e flag should be rejected");
    }

    #[test]
    fn test_old_edit_long_flag_rejected() {
        // Old: agenix --edit file.age
        let result = Args::try_parse_from(["agenix", "--edit", "test.age"]);
        assert!(result.is_err(), "Old --edit flag should be rejected");
    }

    #[test]
    fn test_old_decrypt_flag_rejected() {
        // Old: agenix -d file.age
        // New: agenix decrypt file.age
        let result = Args::try_parse_from(["agenix", "-d", "test.age"]);
        assert!(result.is_err(), "Old -d flag should be rejected");
    }

    #[test]
    fn test_old_decrypt_long_flag_rejected() {
        // Old: agenix --decrypt file.age
        let result = Args::try_parse_from(["agenix", "--decrypt", "test.age"]);
        assert!(result.is_err(), "Old --decrypt flag should be rejected");
    }

    #[test]
    fn test_rules_short_flag_requires_value() {
        // -r is now for --rules and requires a value
        let result = Args::try_parse_from(["agenix", "-r"]);
        assert!(result.is_err(), "-r requires a value");
    }

    #[test]
    fn test_old_rekey_long_flag_rejected() {
        // Old: agenix --rekey
        let result = Args::try_parse_from(["agenix", "--rekey"]);
        assert!(result.is_err(), "Old --rekey flag should be rejected");
    }

    #[test]
    fn test_old_generate_flag_rejected() {
        // Old: agenix -g
        // New: agenix generate
        let result = Args::try_parse_from(["agenix", "-g"]);
        assert!(result.is_err(), "Old -g flag should be rejected");
    }

    #[test]
    fn test_old_generate_long_flag_rejected() {
        // Old: agenix --generate
        let result = Args::try_parse_from(["agenix", "--generate"]);
        assert!(result.is_err(), "Old --generate flag should be rejected");
    }

    #[test]
    fn test_old_identity_flag_at_root_rejected() {
        // Old: agenix -i key -e file.age (identity at root level)
        // New: agenix edit -i key file.age (identity in subcommand)
        let result = Args::try_parse_from(["agenix", "-i", "/path/to/key", "edit", "test.age"]);
        assert!(
            result.is_err(),
            "Old -i flag at root level should be rejected"
        );
    }

    #[test]
    fn test_old_output_flag_at_root_rejected() {
        // Old: agenix -o output -d file.age (output at root level)
        // New: agenix decrypt -o output file.age (output in subcommand)
        let result = Args::try_parse_from(["agenix", "-o", "output.txt", "decrypt", "test.age"]);
        assert!(
            result.is_err(),
            "Old -o flag at root level should be rejected"
        );
    }
}
