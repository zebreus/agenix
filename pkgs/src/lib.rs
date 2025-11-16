mod cli;
mod crypto;
mod editor;
mod nix;

use anyhow::{Context, Result};
use clap::Parser;
use std::process::Command;

use crate::crypto::AGE_BIN;
use crate::nix::NIX_INSTANTIATE;

fn validate_dependencies() -> Result<(), Vec<String>> {
    let mut missing = Vec::new();
    let binaries = [(AGE_BIN, "age"), (NIX_INSTANTIATE, "nix-instantiate")];
    for (path, name) in &binaries {
        if Command::new(path).arg("--version").output().is_err() {
            missing.push(format!("{name} ({path})"));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

/// Single public entrypoint: parse CLI args and execute
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
