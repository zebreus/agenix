mod cli;
mod crypto;
mod editor;
mod nix;

use anyhow::{Context, Result};
use clap::Parser;

/// Configuration for identity management
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Explicitly specified identities (in order)
    pub identities: Vec<String>,
    /// Whether to exclude system identities
    pub no_system_identities: bool,
}

impl IdentityConfig {
    /// Create a new identity configuration
    pub fn new(identities: Vec<String>, no_system_identities: bool) -> Self {
        Self {
            identities,
            no_system_identities,
        }
    }

    /// Get the identities slice for use in crypto operations
    pub fn get_identity_paths(&self) -> Option<&[String]> {
        if self.identities.is_empty() && !self.no_system_identities {
            None // Use default behavior
        } else {
            Some(&self.identities)
        }
    }
}

/// Parse CLI arguments and execute the requested action.
///
/// This is the single public entrypoint used by the binary and tests.
///
/// # Errors
/// Returns an error if required dependencies (`age`, `nix-instantiate`) are missing,
/// if parsing arguments fails, or if any operation (rekey, decrypt, edit) fails.
pub fn run<I, T>(iter: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args = cli::Args::parse_from(iter);

    let identity_config = IdentityConfig::new(args.identity.clone(), args.no_system_identities);

    match args.command {
        Some(cli::Command::Rekey {}) => {
            editor::rekey_all_files(&args.rules, &identity_config).context("Failed to rekey files")
        }
        Some(cli::Command::Generate { force, dry_run }) => {
            editor::generate_secrets(&args.rules, force, dry_run)
                .context("Failed to generate secrets")
        }
        Some(cli::Command::Decrypt { file, output }) => {
            editor::decrypt_file(&args.rules, &file, output.as_deref(), &identity_config)
                .with_context(|| format!("Failed to decrypt {file}"))
        }
        Some(cli::Command::Edit { file, editor }) => {
            editor::edit_file(&args.rules, &file, &editor, &identity_config)
                .with_context(|| format!("Failed to edit {file}"))
        }
        None => Ok(()),
    }
}
