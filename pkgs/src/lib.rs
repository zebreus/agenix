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

    if args.rekey {
        return editor::rekey_all_files(&args.rules, args.identity.as_deref())
            .context("Failed to rekey files");
    }
    if args.generate {
        return editor::generate_secrets(&args.rules).context("Failed to generate secrets");
    }
    if let Some(file) = &args.decrypt {
        return editor::decrypt_file(
            &args.rules,
            file,
            args.output.as_deref(),
            args.identity.as_deref(),
        )
        .with_context(|| format!("Failed to decrypt {file}"));
    }
    if let Some(file) = &args.edit {
        return editor::edit_file(&args.rules, file, &args.editor, args.identity.as_deref())
            .with_context(|| format!("Failed to edit {file}"));
    }
    Ok(())
}
