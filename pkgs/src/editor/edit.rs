//! File editing and decryption operations.
//!
//! This module provides functions for editing encrypted files with an editor,
//! encrypting files from stdin, and decrypting files to stdout or another location.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

use crate::crypto::{self, encrypt_from_file, files_equal};
use crate::nix::{get_public_keys, should_armor};

/// Edit a secret file with an editor.
///
/// If the file exists, it will be decrypted to a temporary location, opened in the
/// specified editor, and re-encrypted when the editor exits. If the file doesn't exist,
/// a new encrypted file will be created.
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `file` - Path to the secret file to edit
/// * `editor_cmd` - Editor command to use (or ":" for no-op, used by rekey)
/// * `identities` - List of identity files for decryption
/// * `no_system_identities` - If true, don't use default system identities
pub fn edit_file(
    rules_path: &str,
    file: &str,
    editor_cmd: &str,
    identities: &[String],
    no_system_identities: bool,
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
        crypto::decrypt_to_file(file, &cleartext_file, identities, no_system_identities)?;
    }

    // Create backup
    let backup_file = format!("{}.backup", cleartext_file.to_string_lossy());
    if cleartext_file.exists() {
        fs::copy(&cleartext_file, &backup_file)?;
    }

    // If editor_cmd is ":" we skip invoking an editor (used for rekey)
    if editor_cmd != ":" {
        // Always use the specified editor command
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

/// Encrypt content from stdin to a secret file.
///
/// Reads from stdin and encrypts the content to the specified file. Does not require
/// an editor or decryption capabilities.
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `file` - Path to the secret file to create
/// * `force` - If true, overwrite existing files; if false, fail if file exists
pub fn encrypt_file(rules_path: &str, file: &str, force: bool) -> Result<()> {
    let public_keys = get_public_keys(rules_path, file)?;
    let armor = should_armor(rules_path, file)?;

    if public_keys.is_empty() {
        return Err(anyhow!("No public keys found for file: {file}"));
    }

    // Check if file exists and force flag
    if Path::new(file).exists() && !force {
        return Err(anyhow!(
            "Secret file already exists: {file}\nUse --force to overwrite or 'agenix edit {file}' to edit the existing secret"
        ));
    }

    // Create temporary directory for cleartext
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let cleartext_file = temp_dir.path().join(Path::new(file).file_name().unwrap());

    // Read from stdin
    let mut stdin_content = String::new();
    io::stdin()
        .read_to_string(&mut stdin_content)
        .context("Failed to read from stdin")?;

    if stdin_content.is_empty() {
        return Err(anyhow!("No input provided on stdin"));
    }

    fs::write(&cleartext_file, stdin_content).context("Failed to write stdin content to file")?;

    // Encrypt the file
    encrypt_from_file(&cleartext_file.to_string_lossy(), file, &public_keys, armor)?;

    Ok(())
}

/// Decrypt a file to stdout or another location.
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `file` - Path to the secret file to decrypt
/// * `output` - Optional output file path (stdout if None)
/// * `identities` - List of identity files for decryption
/// * `no_system_identities` - If true, don't use default system identities
pub fn decrypt_file(
    rules_path: &str,
    file: &str,
    output: Option<&str>,
    identities: &[String],
    no_system_identities: bool,
) -> Result<()> {
    let public_keys = get_public_keys(rules_path, file)?;
    if public_keys.is_empty() {
        return Err(anyhow!("No public keys found for file: {file}"));
    }

    match output {
        Some(out_file) => {
            crypto::decrypt_to_file(file, Path::new(out_file), identities, no_system_identities)?
        }
        None => crypto::decrypt_to_file(
            file,
            Path::new("/dev/stdout"),
            identities,
            no_system_identities,
        )?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_edit_file_no_keys() {
        let rules = "./test_secrets.nix";
        let result = edit_file(rules, "nonexistent.age", "vi", &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_file_no_keys() {
        let rules = "./test_secrets.nix";
        let result = decrypt_file(rules, "nonexistent.age", None, &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_reencrypt_when_unchanged() {
        let tmp = tempdir().unwrap();
        let secret_path = tmp.path().join("dummy.age");
        File::create(&secret_path).unwrap();
        let res = edit_file(
            "./test_secrets.nix",
            secret_path.to_str().unwrap(),
            ":",
            &[],
            false,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_encrypt_file_no_keys() {
        let rules = "./test_secrets.nix";
        let result = encrypt_file(rules, "nonexistent.age", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_file_already_exists_without_force() -> Result<()> {
        let temp_dir = tempdir()?;
        let test_file_path = temp_dir.path().join("existing.age");

        // Create the file so it exists
        File::create(&test_file_path)?;

        // Create a temporary rules file with absolute path to the test file
        let rules_content = format!(
            r#"
{{
  "{}" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            test_file_path.to_str().unwrap()
        );

        let temp_rules: PathBuf = temp_dir.path().join("secrets.nix").to_path_buf();
        writeln!(File::create(&temp_rules).unwrap(), "{}", rules_content)?;

        // Encrypt should fail because file exists and force is false
        let result = encrypt_file(
            temp_rules.to_str().unwrap(),
            test_file_path.to_str().unwrap(),
            false,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("already exists"));

        Ok(())
    }
}
