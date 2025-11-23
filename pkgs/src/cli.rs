//! Command-line argument parsing and definitions for agenix.
//!
//! This module defines the CLI interface using clap's derive macros.

use clap::Parser;
use std::env;

#[derive(Parser, Debug)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "edit and rekey age secret files",
    after_help = concat!("agenix version: ", env!("CARGO_PKG_VERSION"))
)]
pub struct Args {
    /// Edit FILE using $EDITOR
    #[arg(short, long, value_name = "FILE", allow_hyphen_values = true)]
    pub edit: Option<String>,

    /// Identity to use when decrypting
    #[arg(short, long, value_name = "PRIVATE_KEY")]
    pub identity: Option<String>,

    /// Re-encrypts all secrets with specified recipients
    #[arg(short, long)]
    pub rekey: bool,

    /// Decrypt FILE to STDOUT (or to --output)
    #[arg(short, long, value_name = "FILE", allow_hyphen_values = true)]
    pub decrypt: Option<String>,

    /// Write decrypt output to FILE instead of STDOUT
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<String>,

    /// Path to Nix rules file (can also be set via RULES env var)
    #[arg(
        long,
        env = "RULES",
        value_name = "FILE",
        default_value = "./secrets.nix"
    )]
    pub rules: String,

    /// Editor to use when editing secrets.
    ///
    /// This setting is only used when stdin is a terminal, otherwise we always read from stdin.
    /// A special case is ":" which means ???
    #[arg(long, env = "EDITOR", value_name = "EDITOR", default_value_t = String::from("vi"))]
    pub editor: String,

    /// Generate secrets using generator functions from rules
    #[arg(short, long)]
    pub generate: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
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
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }

        f();

        match original {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn test_args_parsing() {
        let args = Args::try_parse_from(["agenix", "-e", "test.age"]).unwrap();
        assert_eq!(args.edit, Some("test.age".to_string()));
        assert!(!args.rekey);
        assert_eq!(args.decrypt, None);
        assert_eq!(args.identity, None);
        assert!(!args.verbose);
    }

    #[test]
    fn test_rekey_flag() {
        let args = Args::try_parse_from(["agenix", "-r"]).unwrap();
        assert!(args.rekey);
        assert_eq!(args.edit, None);
    }

    #[test]
    fn test_decrypt_with_identity() {
        let args =
            Args::try_parse_from(["agenix", "-d", "secret.age", "-i", "/path/to/key"]).unwrap();
        assert_eq!(args.decrypt, Some("secret.age".to_string()));
        assert_eq!(args.identity, Some("/path/to/key".to_string()));
    }

    #[test]
    fn test_verbose_flag() {
        let args = Args::try_parse_from(["agenix", "-v", "-e", "test.age"]).unwrap();
        assert!(args.verbose);
        assert_eq!(args.edit, Some("test.age".to_string()));
    }

    #[test]
    fn test_args_parsing_default_editor() {
        with_env_var("EDITOR", None, || {
            let args = Args::try_parse_from(["agenix", "-e", "test.age"]).unwrap();
            assert_eq!(args.edit, Some("test.age".to_string()));
            assert_eq!(args.editor, "vi");
        });
    }

    #[test]
    fn test_editor_env_overrides_default() {
        with_env_var("EDITOR", Some("nano"), || {
            let args = Args::try_parse_from(["agenix"]).unwrap();
            assert_eq!(args.editor, "nano");
        });
    }

    #[test]
    fn test_editor_flag_overrides_env() {
        with_env_var("EDITOR", Some("nano"), || {
            let args = Args::try_parse_from(["agenix", "--editor", "vim"]).unwrap();
            assert_eq!(args.editor, "vim");
        });
    }

    #[test]
    fn test_editor_flag_without_env() {
        with_env_var("EDITOR", None, || {
            let args = Args::try_parse_from(["agenix", "--editor", "micro"]).unwrap();
            assert_eq!(args.editor, "micro");
        });
    }

    #[test]
    fn test_rules_env_var() {
        with_env_var("RULES", Some("/custom/path/secrets.nix"), || {
            let args = Args::try_parse_from(["agenix"]).unwrap();
            assert_eq!(args.rules, "/custom/path/secrets.nix");
        });
    }

    #[test]
    fn test_generate_flag() {
        let args = Args::try_parse_from(["agenix", "-g"]).unwrap();
        assert!(args.generate);
        assert_eq!(args.edit, None);
        assert!(!args.rekey);
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

        // Also verify it's near the end (after the options section)
        let options_pos = help
            .find("Options:")
            .expect("Help should contain Options section");
        let version_pos = help
            .find(&expected_version_line)
            .expect("Help should contain version line");
        assert!(
            version_pos > options_pos,
            "Version line should appear after Options section"
        );
    }
}
