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
        Some(cli::Command::Rekey { identity }) => {
            editor::rekey_all_files(&args.rules, identity.as_deref())
                .context("Failed to rekey files")
        }
        Some(cli::Command::Generate) => {
            editor::generate_secrets(&args.rules).context("Failed to generate secrets")
        }
        Some(cli::Command::Decrypt {
            file,
            identity,
            output,
        }) => editor::decrypt_file(&args.rules, &file, output.as_deref(), identity.as_deref())
            .with_context(|| format!("Failed to decrypt {file}")),
        Some(cli::Command::Edit {
            file,
            identity,
            editor,
        }) => editor::edit_file(&args.rules, &file, &editor, identity.as_deref())
            .with_context(|| format!("Failed to edit {file}")),
        None => Ok(()),
    }
}
