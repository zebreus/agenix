mod cli;
mod crypto;
mod editor;
mod nix;

use anyhow::{Context, Result};
use clap::Parser;
use std::process::Command;

use crate::nix::NIX_INSTANTIATE;

fn validate_dependencies() -> Result<(), Vec<String>> {
    let mut missing = Vec::new();
    // Only check for nix-instantiate since we use the age crate instead of the binary
    if Command::new(NIX_INSTANTIATE)
        .arg("--version")
        .output()
        .is_err()
    {
        missing.push(format!("nix-instantiate ({NIX_INSTANTIATE})"));
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
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
    if let Err(missing) = validate_dependencies() {
        eprintln!("Missing required dependencies:");
        for dep in missing {
            eprintln!("  - {dep}");
        }
        return Err(anyhow::anyhow!("Required dependencies are missing"));
    }

    let args = cli::Args::parse_from(iter);

    if args.rekey {
        return editor::rekey_all_files(&args.rules, args.identity.as_deref())
            .context("Failed to rekey files");
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
