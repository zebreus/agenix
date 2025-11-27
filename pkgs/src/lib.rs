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
        Some(cli::Command::Rekey { secrets, partial }) => editor::rekey_files(
            &args.rules,
            &secrets,
            &args.identity,
            args.no_system_identities,
            partial,
        )
        .context("Failed to rekey files"),
        Some(cli::Command::Generate {
            force,
            dry_run,
            no_dependencies,
            secrets,
        }) => editor::generate_secrets(&args.rules, force, dry_run, !no_dependencies, &secrets)
            .context("Failed to generate secrets"),
        Some(cli::Command::Decrypt { file, output }) => editor::decrypt_file(
            &args.rules,
            &file,
            output.as_deref(),
            &args.identity,
            args.no_system_identities,
        )
        .with_context(|| format!("Failed to decrypt {file}")),
        Some(cli::Command::Edit {
            file,
            editor,
            force,
        }) => editor::edit_file(
            &args.rules,
            &file,
            &editor,
            &args.identity,
            args.no_system_identities,
            force,
        )
        .with_context(|| format!("Failed to edit {file}")),
        Some(cli::Command::Encrypt { file, force }) => {
            editor::encrypt_file(&args.rules, &file, force)
                .with_context(|| format!("Failed to encrypt {file}"))
        }
        Some(cli::Command::List { detailed }) => editor::list_secrets(
            &args.rules,
            detailed,
            &args.identity,
            args.no_system_identities,
        )
        .context("Failed to list secrets"),
        Some(cli::Command::Check { secrets }) => editor::check_secrets(
            &args.rules,
            &secrets,
            &args.identity,
            args.no_system_identities,
        )
        .context("Failed to check secrets"),
        Some(cli::Command::Completions { shell }) => {
            cli::print_completions(shell, &mut cli::build_cli());
            Ok(())
        }
        None => Ok(()),
    }
}
