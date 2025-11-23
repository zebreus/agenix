use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::{self, IsTerminal, Read, stdin};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

use crate::crypto::{decrypt_to_file, encrypt_from_file, files_equal};
use crate::nix::{generate_secret_with_public, get_all_files, get_public_keys, should_armor};

/// Edit a file with encryption/decryption
pub fn edit_file(
    rules_path: &str,
    file: &str,
    editor_cmd: &str,
    identity: Option<&str>,
) -> Result<()> {
    let public_keys = get_public_keys(rules_path, file)?;
    let armor = should_armor(rules_path, file)?;

    if public_keys.is_empty() {
        return Err(anyhow!("No public keys found for file: {file}"));
    }

    // Create temporary directory for cleartext
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let cleartext_file = temp_dir.path().join(Path::new(file).file_name().unwrap());

    // Decrypt if file exists
    if Path::new(file).exists() {
        decrypt_to_file(file, &cleartext_file, identity)?;
    }

    // Create backup
    let backup_file = format!("{}.backup", cleartext_file.to_string_lossy());
    if cleartext_file.exists() {
        fs::copy(&cleartext_file, &backup_file)?;
    }

    // If editor_cmd is ":" we skip invoking an editor (used for rekey)
    if editor_cmd != ":" {
        if !stdin().is_terminal() {
            // Read directly from stdin instead of using shell command
            let mut stdin_content = String::new();
            io::stdin()
                .read_to_string(&mut stdin_content)
                .context("Failed to read from stdin")?;

            fs::write(&cleartext_file, stdin_content)
                .context("Failed to write stdin content to file")?;
        } else {
            // Use the specified editor command
            let status = Command::new("sh")
                .args([
                    "-c",
                    &format!("{} '{}'", editor_cmd, cleartext_file.to_string_lossy()),
                ])
                .status()
                .context("Failed to run editor")?;

            if !status.success() {
                return Err(anyhow!("Editor exited with non-zero status"));
            }
        }
    }

    if !cleartext_file.exists() {
        eprintln!("Warning: {file} wasn't created");
        return Ok(());
    }

    // Check if file changed (only when an editor was actually invoked)
    if editor_cmd != ":"
        && Path::new(&backup_file).exists()
        && files_equal(&backup_file, &cleartext_file.to_string_lossy())?
    {
        eprintln!("Warning: {file} wasn't changed, skipping re-encryption");
        return Ok(());
    }

    // Encrypt the file
    encrypt_from_file(&cleartext_file.to_string_lossy(), file, &public_keys, armor)?;

    Ok(())
}

/// Decrypt a file to stdout or another location
pub fn decrypt_file(
    rules_path: &str,
    file: &str,
    output: Option<&str>,
    identity: Option<&str>,
) -> Result<()> {
    let public_keys = get_public_keys(rules_path, file)?;
    if public_keys.is_empty() {
        return Err(anyhow!("No public keys found for file: {file}"));
    }

    match output {
        Some(out_file) => decrypt_to_file(file, Path::new(out_file), identity)?,
        None => decrypt_to_file(file, Path::new("/dev/stdout"), identity)?,
    }

    Ok(())
}

/// Rekey all files in the rules (no-op editor used to avoid launching an editor)
pub fn rekey_all_files(rules_path: &str, identity: Option<&str>) -> Result<()> {
    let files = get_all_files(rules_path)?;

    files.iter().try_for_each(|file| {
        eprintln!("Rekeying {file}...");
        edit_file(rules_path, file, ":", identity)
    })?;

    Ok(())
}

/// Generate secrets using generator functions from rules
/// Only generates secrets if:
/// 1. The file has a generator function defined
/// 2. The secret file doesn't already exist
pub fn generate_secrets(rules_path: &str) -> Result<()> {
    let files = get_all_files(rules_path)?;

    for file in files {
        // Skip if the file already exists
        if Path::new(&file).exists() {
            if let Ok(Some(_)) = generate_secret_with_public(rules_path, &file) {
                eprintln!("Skipping {file}: already exists");
            }
            continue;
        }

        // Check if there's a generator for this file
        if let Some(generator_output) = generate_secret_with_public(rules_path, &file)? {
            eprintln!("Generating {file}...");

            let public_keys = get_public_keys(rules_path, &file)?;
            let armor = should_armor(rules_path, &file)?;

            if public_keys.is_empty() {
                eprintln!("Warning: No public keys found for {file}, skipping");
                continue;
            }

            // Create temporary file with the generated secret content
            let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
            let temp_file = temp_dir.path().join("generated_secret");
            fs::write(&temp_file, &generator_output.secret)
                .context("Failed to write generated content to temporary file")?;

            // Encrypt the generated secret content
            encrypt_from_file(&temp_file.to_string_lossy(), &file, &public_keys, armor)
                .with_context(|| format!("Failed to encrypt generated secret {file}"))?;

            eprintln!("Generated and encrypted {file}");

            // If there's public content, write it to a .pub file
            if let Some(public_content) = &generator_output.public {
                let pub_file = format!("{}.pub", file);
                fs::write(&pub_file, public_content)
                    .with_context(|| format!("Failed to write public file {pub_file}"))?;
                eprintln!("Generated public file {pub_file}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
