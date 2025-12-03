//! File editing and decryption operations.
//!
//! This module provides functions for editing encrypted files with an editor,
//! encrypting files from stdin, and decrypting files to stdout or another location.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

use crate::crypto::{self, encrypt_from_file, files_equal};
use crate::editor::secret_name::SecretName;
use crate::nix::{get_all_files, get_public_keys, should_armor};
use crate::{log, verbose};

/// Get the rules directory from a rules file path
fn get_rules_dir(rules_path: &str) -> PathBuf {
    let path = Path::new(rules_path);
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// Context for encryption operations, containing validated settings from the rules file.
struct EncryptionContext {
    public_keys: Vec<String>,
    armor: bool,
}

impl EncryptionContext {
    /// Load encryption settings from rules file for a given secret.
    /// The secret_name is the name as it appears in secrets.nix (without .age suffix).
    fn new(rules_path: &str, secret_name: &str) -> Result<Self> {
        let public_keys = get_public_keys(rules_path, secret_name)?;
        if public_keys.is_empty() {
            return Err(anyhow!("No public keys found for secret: {secret_name}"));
        }
        let armor = should_armor(rules_path, secret_name)?;
        Ok(Self { public_keys, armor })
    }

    /// Encrypt a cleartext file to the output path.
    fn encrypt(&self, cleartext_path: &str, output_path: &str) -> Result<()> {
        encrypt_from_file(cleartext_path, output_path, &self.public_keys, self.armor)
    }
}

/// Get the filename component for creating temporary files.
fn get_temp_filename(secret_name: &str) -> Result<String> {
    // Use just the secret name for the temp file
    Ok(secret_name.to_string())
}

/// Create a temporary directory with a cleartext file inside.
fn create_temp_cleartext(secret_name: &str) -> Result<(TempDir, std::path::PathBuf)> {
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let cleartext_file = temp_dir.path().join(secret_name);
    Ok((temp_dir, cleartext_file))
}

/// Determine the effective editor to use.
///
/// Priority:
/// 1. Explicitly provided editor (via -e flag or EDITOR env var)
/// 2. If stdin is not a TTY (piped input), use stdin directly
/// 3. Default to "vi"
fn determine_editor(editor: Option<&str>) -> EditorChoice {
    // If editor was explicitly provided (via -e flag or EDITOR env var), use it
    if let Some(cmd) = editor {
        verbose!("Using editor: {}", cmd);
        return EditorChoice::Command(cmd.to_string());
    }

    // Check if stdin is a TTY
    let stdin_is_tty = io::stdin().is_terminal();

    if !stdin_is_tty {
        verbose!("Stdin is not a TTY, reading content directly from stdin");
        return EditorChoice::Stdin;
    }

    // Default to vi
    verbose!("Using default editor: vi");
    EditorChoice::Command("vi".to_string())
}

/// Represents the choice of how to edit a file
enum EditorChoice {
    /// Use an external editor command
    Command(String),
    /// Read directly from stdin (for non-TTY/piped input)
    Stdin,
}

/// Edit a secret file with an editor.
///
/// The `secret_name` parameter is the name as it appears in secrets.nix (without .age suffix).
/// The actual secret file path will be constructed as <rules_dir>/<secret_name>.age
///
/// If the file exists, it will be decrypted to a temporary location, opened in the
/// specified editor, and re-encrypted when the editor exits. If the file doesn't exist,
/// a new encrypted file will be created.
///
/// When stdin is not a TTY and no editor is explicitly specified, the content
/// is read directly from stdin instead of launching an editor.
///
/// In dry-run mode, the editor is still opened and content can be modified, but
/// the encrypted file is not actually updated.
pub fn edit_file(
    rules_path: &str,
    secret_name: &str,
    editor_cmd: Option<&str>,
    identities: &[String],
    no_system_identities: bool,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Normalize the secret name (strip .age if provided for backwards compatibility)
    let sname = SecretName::new(secret_name);
    let secret_name = sname.name();

    // Construct the actual secret file path
    let rules_dir = get_rules_dir(rules_path);
    let secret_file = rules_dir.join(sname.secret_file());
    let secret_file_str = secret_file
        .to_str()
        .ok_or_else(|| anyhow!("Invalid path encoding"))?;

    let ctx = EncryptionContext::new(rules_path, secret_name)?;
    let temp_filename = get_temp_filename(secret_name)?;
    let (_temp_dir, cleartext_file) = create_temp_cleartext(&temp_filename)?;

    verbose!("Editing secret: {}", secret_name);

    // Decrypt existing file if present
    if secret_file.exists() {
        verbose!("Decrypting existing file: {}", secret_file.display());
        if let Err(e) = crypto::decrypt_to_file(
            secret_file_str,
            &cleartext_file,
            identities,
            no_system_identities,
        ) {
            if force {
                log!(
                    "Warning: Could not decrypt {secret_name}, starting with empty content: {e:#}"
                );
            } else {
                return Err(e).with_context(|| {
                    format!(
                        "Failed to decrypt {secret_name}. Use --force to start with empty content"
                    )
                });
            }
        }
    }

    // Create backup for change detection
    let backup_file = format!("{}.backup", cleartext_file.to_string_lossy());
    if cleartext_file.exists() {
        fs::copy(&cleartext_file, &backup_file)?;
    }

    // Determine how to edit the file
    let editor_choice = determine_editor(editor_cmd);

    // Edit the file based on the chosen method
    let skip_change_check = match &editor_choice {
        EditorChoice::Command(cmd) if cmd == ":" => {
            // Skip editor (used for rekey)
            verbose!("Skipping editor (rekey mode)");
            true
        }
        EditorChoice::Command(cmd) => {
            // Run external editor
            verbose!("Running editor: {}", cmd);
            let status = Command::new("sh")
                .args([
                    "-c",
                    &format!("{} '{}'", cmd, cleartext_file.to_string_lossy()),
                ])
                .status()
                .context("Failed to run editor")?;

            if !status.success() {
                return Err(anyhow!("Editor exited with non-zero status"));
            }
            false
        }
        EditorChoice::Stdin => {
            // Read from stdin directly
            verbose!("Reading content from stdin");
            let mut stdin_content = String::new();
            io::stdin()
                .read_to_string(&mut stdin_content)
                .context("Failed to read from stdin")?;

            if stdin_content.is_empty() {
                return Err(anyhow!("No input provided on stdin"));
            }

            fs::write(&cleartext_file, stdin_content).context("Failed to write stdin content")?;
            false
        }
    };

    // Handle case where editor didn't create the file
    if !cleartext_file.exists() {
        log!("Warning: {secret_name} wasn't created");
        return Ok(());
    }

    // Skip re-encryption if content unchanged (only when editor was invoked)
    if !skip_change_check
        && Path::new(&backup_file).exists()
        && files_equal(&backup_file, &cleartext_file.to_string_lossy())?
    {
        log!("Warning: {secret_name} wasn't changed, skipping re-encryption");
        return Ok(());
    }

    log!("Encrypting to: {}", secret_file.display());

    // In dry-run mode, skip the actual encryption to disk
    if dry_run {
        log!("Dry-run mode: not saving changes to {}", secret_name);
        return Ok(());
    }

    ctx.encrypt(&cleartext_file.to_string_lossy(), secret_file_str)
}

/// Encrypt content from stdin or a file to a secret file.
///
/// The `secret_name` parameter is the name as it appears in secrets.nix (without .age suffix).
/// The actual secret file path will be constructed as <rules_dir>/<secret_name>.age
///
/// Reads from stdin (or the specified input file) and encrypts the content to the specified file.
/// Does not require an editor or decryption capabilities.
///
/// In dry-run mode, the content is read and validated but not encrypted to disk.
pub fn encrypt_file(
    rules_path: &str,
    secret_name: &str,
    input: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Normalize the secret name (strip .age if provided for backwards compatibility)
    let sname = SecretName::new(secret_name);
    let secret_name = sname.name();

    // Construct the actual secret file path
    let rules_dir = get_rules_dir(rules_path);
    let secret_file = rules_dir.join(sname.secret_file());
    let secret_file_str = secret_file
        .to_str()
        .ok_or_else(|| anyhow!("Invalid path encoding"))?;

    // Check if file exists before doing any work
    if secret_file.exists() && !force {
        return Err(anyhow!(
            "Secret file already exists: {}\nUse --force to overwrite or 'agenix edit' to edit the existing secret",
            secret_file.display()
        ));
    }

    verbose!("Encrypting secret: {}", secret_name);

    let ctx = EncryptionContext::new(rules_path, secret_name)?;
    let temp_filename = get_temp_filename(secret_name)?;
    let (_temp_dir, cleartext_file) = create_temp_cleartext(&temp_filename)?;

    // Read content from input file or stdin
    let content = match input {
        Some(input_path) => {
            verbose!("Reading content from file: {}", input_path);
            fs::read_to_string(input_path)
                .with_context(|| format!("Failed to read input file: {}", input_path))?
        }
        None => {
            verbose!("Reading content from stdin");
            let mut stdin_content = String::new();
            io::stdin()
                .read_to_string(&mut stdin_content)
                .context("Failed to read from stdin")?;
            stdin_content
        }
    };

    if content.is_empty() {
        return Err(anyhow!(
            "{}",
            match input {
                Some(path) => format!("Input file is empty: {}", path),
                None => "No input provided on stdin".to_string(),
            }
        ));
    }

    // Write content to temp file (same code path for both modes)
    fs::write(&cleartext_file, content).context("Failed to write content to file")?;

    log!("Encrypting to: {}", secret_file.display());

    // In dry-run mode, skip only the final file write
    if dry_run {
        return Ok(());
    }

    ctx.encrypt(&cleartext_file.to_string_lossy(), secret_file_str)
}

/// Decrypt a file to stdout or another location.
///
/// The `secret_name` parameter is the name as it appears in secrets.nix (without .age suffix).
/// The actual secret file path will be constructed as <rules_dir>/<secret_name>.age
///
/// Validates the secret exists in rules before decrypting.
/// Note: Decryption only requires identity (private key), not publicKeys.
pub fn decrypt_file(
    rules_path: &str,
    secret_name: &str,
    output: Option<&str>,
    identities: &[String],
    no_system_identities: bool,
) -> Result<()> {
    // Normalize the secret name (strip .age if provided for backwards compatibility)
    let sname = SecretName::new(secret_name);
    let secret_name = sname.name();

    validate_secret_exists(rules_path, secret_name)?;

    // Construct the actual secret file path
    let rules_dir = get_rules_dir(rules_path);
    let secret_file = rules_dir.join(sname.secret_file());
    let secret_file_str = secret_file
        .to_str()
        .ok_or_else(|| anyhow!("Invalid path encoding"))?;

    verbose!("Decrypting secret: {}", secret_name);
    let output_path = output.unwrap_or("/dev/stdout");
    verbose!("Decrypting to: {}", output_path);

    crypto::decrypt_to_file(
        secret_file_str,
        Path::new(output_path),
        identities,
        no_system_identities,
    )
}

/// Validate that a secret exists in the rules file (without requiring publicKeys).
///
/// This is used for --public operations where we only need to verify the secret
/// is defined in secrets.nix, but don't need publicKeys since we're not encrypting.
fn validate_secret_exists(rules_path: &str, secret_name: &str) -> Result<()> {
    let all_files = get_all_files(rules_path)?;
    if all_files.iter().any(|f| f == secret_name) {
        Ok(())
    } else {
        Err(anyhow!("Secret not found in rules: {secret_name}"))
    }
}

/// Run an editor workflow on a file, handling stdin, change detection, and dry-run.
fn run_editor_workflow(
    secret_name: &str,
    editor_cmd: Option<&str>,
    force: bool,
    dry_run: bool,
    load_content: impl FnOnce() -> Result<Option<String>>,
    save_content: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    let temp_filename = get_temp_filename(secret_name)?;
    let (_temp_dir, temp_file) = create_temp_cleartext(&temp_filename)?;

    // Load existing content if file exists, otherwise start with empty content
    match load_content() {
        Ok(Some(content)) => {
            fs::write(&temp_file, content).context("Failed to write to temporary file")?;
        }
        Ok(None) => {
            // File doesn't exist - start with empty content (no --force needed to create new files)
        }
        Err(e) => {
            if force {
                log!(
                    "Warning: Could not read {}, starting with empty content: {:#}",
                    secret_name,
                    e
                );
            } else {
                return Err(e).with_context(|| {
                    format!(
                        "Failed to read {}. Use --force to start with empty content",
                        secret_name
                    )
                });
            }
        }
    }

    // Create backup for change detection
    let backup_file = format!("{}.backup", temp_file.to_string_lossy());
    if temp_file.exists() {
        fs::copy(&temp_file, &backup_file)?;
    }

    // Edit the file
    let skip_change_check = run_editor(editor_cmd, &temp_file)?;

    // Handle case where editor didn't create the file
    if !temp_file.exists() {
        log!("Warning: {} wasn't created", secret_name);
        return Ok(());
    }

    // Skip save if content unchanged
    if !skip_change_check
        && Path::new(&backup_file).exists()
        && files_equal(&backup_file, &temp_file.to_string_lossy())?
    {
        log!("Warning: {} wasn't changed, skipping save", secret_name);
        return Ok(());
    }

    log!("Saving to: {}", secret_name);

    if dry_run {
        log!("Dry-run mode: not saving changes to {}", secret_name);
        return Ok(());
    }

    let content = fs::read_to_string(&temp_file).context("Failed to read edited content")?;
    save_content(&content)
}

/// Run the editor and return whether to skip change detection.
fn run_editor(editor_cmd: Option<&str>, temp_file: &Path) -> Result<bool> {
    match determine_editor(editor_cmd) {
        EditorChoice::Command(cmd) if cmd == ":" => {
            verbose!("Skipping editor (rekey mode)");
            Ok(true)
        }
        EditorChoice::Command(cmd) => {
            verbose!("Running editor: {}", cmd);
            let status = Command::new("sh")
                .args(["-c", &format!("{} '{}'", cmd, temp_file.to_string_lossy())])
                .status()
                .context("Failed to run editor")?;
            if !status.success() {
                return Err(anyhow!("Editor exited with non-zero status"));
            }
            Ok(false)
        }
        EditorChoice::Stdin => {
            verbose!("Reading content from stdin");
            let mut content = String::new();
            io::stdin()
                .read_to_string(&mut content)
                .context("Failed to read from stdin")?;
            if content.is_empty() {
                return Err(anyhow!("No input provided on stdin"));
            }
            fs::write(temp_file, content).context("Failed to write stdin content")?;
            Ok(false)
        }
    }
}

/// Read content from stdin or a file.
fn read_input(input: Option<&str>) -> Result<String> {
    match input {
        Some(path) => {
            verbose!("Reading content from file: {}", path);
            fs::read_to_string(path).with_context(|| format!("Failed to read: {}", path))
        }
        None => {
            verbose!("Reading content from stdin");
            let mut content = String::new();
            io::stdin()
                .read_to_string(&mut content)
                .context("Failed to read from stdin")?;
            Ok(content)
        }
    }
}

/// Read the public file associated with a secret to stdout or a file.
///
/// The `secret_name` parameter is the name as it appears in secrets.nix (without .age suffix).
/// The public file path will be constructed as <rules_dir>/<secret_name>.pub
pub fn read_public_file(rules_path: &str, secret_name: &str, output: Option<&str>) -> Result<()> {
    // Normalize the secret name
    let sname = SecretName::new(secret_name);
    let secret_name = sname.name();

    validate_secret_exists(rules_path, secret_name)?;

    // Construct the public file path
    let rules_dir = get_rules_dir(rules_path);
    let pub_file = rules_dir.join(sname.public_file());

    if !pub_file.exists() {
        return Err(anyhow!(
            "Public file does not exist: {}\nHint: Generate the secret first with 'agenix generate'",
            pub_file.display()
        ));
    }

    let content = fs::read_to_string(&pub_file)
        .with_context(|| format!("Failed to read: {}", pub_file.display()))?;
    let output_path = output.unwrap_or("/dev/stdout");
    fs::write(output_path, content).with_context(|| format!("Failed to write to: {}", output_path))
}

/// Write content to the public file associated with a secret.
///
/// The `secret_name` parameter is the name as it appears in secrets.nix (without .age suffix).
/// The public file path will be constructed as <rules_dir>/<secret_name>.pub
pub fn write_public_file(
    rules_path: &str,
    secret_name: &str,
    input: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Normalize the secret name
    let sname = SecretName::new(secret_name);
    let secret_name = sname.name();

    validate_secret_exists(rules_path, secret_name)?;

    // Construct the public file path
    let rules_dir = get_rules_dir(rules_path);
    let pub_file = rules_dir.join(sname.public_file());

    if pub_file.exists() && !force {
        return Err(anyhow!(
            "Public file already exists: {}\nUse --force to overwrite",
            pub_file.display()
        ));
    }

    let content = read_input(input)?;
    if content.is_empty() {
        return Err(anyhow!("No input provided"));
    }

    if dry_run {
        log!("Dry-run: would write to {}", pub_file.display());
        return Ok(());
    }

    fs::write(&pub_file, content)
        .with_context(|| format!("Failed to write: {}", pub_file.display()))
}

/// Edit the public file associated with a secret using an editor.
///
/// The `secret_name` parameter is the name as it appears in secrets.nix (without .age suffix).
/// The public file path will be constructed as <rules_dir>/<secret_name>.pub
pub fn edit_public_file(
    rules_path: &str,
    secret_name: &str,
    editor_cmd: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Normalize the secret name
    let sname = SecretName::new(secret_name);
    let secret_name = sname.name();

    validate_secret_exists(rules_path, secret_name)?;

    // Construct the public file path
    let rules_dir = get_rules_dir(rules_path);
    let pub_file = rules_dir.join(sname.public_file());

    run_editor_workflow(
        secret_name,
        editor_cmd,
        force,
        dry_run,
        || {
            if pub_file.exists() {
                fs::read_to_string(&pub_file)
                    .map(Some)
                    .with_context(|| format!("Failed to read: {}", pub_file.display()))
            } else {
                Ok(None)
            }
        },
        |content| {
            fs::write(&pub_file, content)
                .with_context(|| format!("Failed to write: {}", pub_file.display()))
        },
    )
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
        let result = edit_file(
            rules,
            "nonexistent.age",
            Some("vi"),
            &[],
            false,
            false,
            false,
        );
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
            Some(":"),
            &[],
            false,
            false,
            false,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_encrypt_file_no_keys() {
        let rules = "./test_secrets.nix";
        let result = encrypt_file(rules, "nonexistent.age", None, false, false);
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
            None,
            false,
            false,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("already exists"));

        Ok(())
    }

    #[test]
    fn test_edit_file_invalid_path() {
        // Test with a path that has no filename component
        let rules = "./test_secrets.nix";
        let result = edit_file(rules, "/", Some("vi"), &[], false, false, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_file_invalid_path() {
        // Test with a path that has no filename component
        let rules = "./test_secrets.nix";
        let result = encrypt_file(rules, "/", None, false, false);
        assert!(result.is_err());
    }
}
