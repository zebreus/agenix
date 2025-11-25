mod cli;
mod crypto;
mod editor;
mod nix;

use anyhow::{Context, Result};
use clap::Parser;

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

    match args.command {
        Some(cli::Command::Rekey { secrets }) => editor::rekey_files(
            &args.rules,
            &secrets,
            &args.identity,
            args.no_system_identities,
        )
        .context("Failed to rekey files"),
        Some(cli::Command::Generate {
            force,
            dry_run,
            with_dependencies,
            secrets,
        }) => editor::generate_secrets(&args.rules, force, dry_run, with_dependencies, &secrets)
            .context("Failed to generate secrets"),
        Some(cli::Command::Decrypt { file, output }) => editor::decrypt_file(
            &args.rules,
            &file,
            output.as_deref(),
            &args.identity,
            args.no_system_identities,
        )
        .with_context(|| format!("Failed to decrypt {file}")),
        Some(cli::Command::Edit { file, editor }) => editor::edit_file(
            &args.rules,
            &file,
            &editor,
            &args.identity,
            args.no_system_identities,
        )
        .with_context(|| format!("Failed to edit {file}")),
        None => Ok(()),
    }
}
