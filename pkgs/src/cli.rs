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
    /// Edit FILE using $EDITOR
    #[command(visible_alias = "e")]
    Edit {
        /// The file to edit
        #[arg(value_name = "FILE", allow_hyphen_values = true)]
        file: String,

        /// Identity to use when decrypting
        #[arg(short, long, value_name = "PRIVATE_KEY")]
        identity: Option<String>,

        /// Editor to use when editing secrets.
        ///
        /// This setting is only used when stdin is a terminal, otherwise we always read from stdin.
        #[arg(long, env = "EDITOR", value_name = "EDITOR", default_value_t = String::from("vi"))]
        editor: String,
    },

    /// Decrypt FILE to STDOUT (or to --output)
    #[command(visible_alias = "d")]
    Decrypt {
        /// The file to decrypt
        #[arg(value_name = "FILE", allow_hyphen_values = true)]
        file: String,

        /// Identity to use when decrypting
        #[arg(short, long, value_name = "PRIVATE_KEY")]
        identity: Option<String>,

        /// Write decrypt output to FILE instead of STDOUT
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Re-encrypts all secrets with specified recipients
    #[command(visible_alias = "r")]
    Rekey {
        /// Identity to use when decrypting
        #[arg(short, long, value_name = "PRIVATE_KEY")]
        identity: Option<String>,
    },

    /// Generate secrets using generator functions from rules
    #[command(visible_alias = "g")]
    Generate,
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
        assert!(matches!(args.command, Some(Command::Generate)));
    }

    #[test]
    fn test_generate_short_alias() {
        let args = Args::try_parse_from(["agenix", "g"]).unwrap();
        assert!(matches!(args.command, Some(Command::Generate)));
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
        assert!(matches!(args.command, Some(Command::Generate)));
    }
}
