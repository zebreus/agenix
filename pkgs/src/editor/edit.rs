//! File editing and decryption operations.
//!
//! This module provides functions for editing encrypted files with an editor,
//! encrypting files from stdin, and decrypting files to stdout or another location.

use anyhow::{Context, Result, anyhow};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

use crate::crypto::{self, encrypt_from_file, files_equal};
use crate::nix::{get_public_keys, should_armor};
use crate::{log, verbose};

/// Context for encryption operations, containing validated settings from the rules file.
struct EncryptionContext {
    public_keys: Vec<String>,
    armor: bool,
}

impl EncryptionContext {
    /// Load encryption settings from rules file for a given secret.
    fn new(rules_path: &str, file: &str) -> Result<Self> {
        let public_keys = get_public_keys(rules_path, file)?;
        if public_keys.is_empty() {
            return Err(anyhow!("No public keys found for file: {file}"));
        }
        let armor = should_armor(rules_path, file)?;
        Ok(Self { public_keys, armor })
    }

    /// Encrypt a cleartext file to the output path.
    fn encrypt(&self, cleartext_path: &str, output_path: &str) -> Result<()> {
        encrypt_from_file(cleartext_path, output_path, &self.public_keys, self.armor)
    }
}

/// Get the filename component from a path with proper error handling.
fn get_filename(file: &str) -> Result<&OsStr> {
    Path::new(file)
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file path: {file}"))
}

/// Create a temporary directory with a cleartext file inside.
fn create_temp_cleartext(filename: &OsStr) -> Result<(TempDir, std::path::PathBuf)> {
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let cleartext_file = temp_dir.path().join(filename);
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
    file: &str,
    editor_cmd: Option<&str>,
    identities: &[String],
    no_system_identities: bool,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let ctx = EncryptionContext::new(rules_path, file)?;
    let filename = get_filename(file)?;
    let (_temp_dir, cleartext_file) = create_temp_cleartext(filename)?;

    verbose!("Editing secret: {}", file);

    // Decrypt existing file if present
    if Path::new(file).exists() {
        verbose!("Decrypting existing file: {}", file);
        if let Err(e) =
            crypto::decrypt_to_file(file, &cleartext_file, identities, no_system_identities)
        {
            if force {
                log!("Warning: Could not decrypt {file}, starting with empty content: {e:#}");
            } else {
                return Err(e).with_context(|| {
                    format!("Failed to decrypt {file}. Use --force to start with empty content")
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
        log!("Warning: {file} wasn't created");
        return Ok(());
    }

    // Skip re-encryption if content unchanged (only when editor was invoked)
    if !skip_change_check
        && Path::new(&backup_file).exists()
        && files_equal(&backup_file, &cleartext_file.to_string_lossy())?
    {
        log!("Warning: {file} wasn't changed, skipping re-encryption");
        return Ok(());
    }

    log!("Encrypting to: {}", file);

    // In dry-run mode, skip the actual encryption to disk
    if dry_run {
        log!("Dry-run mode: not saving changes to {}", file);
        return Ok(());
    }

    ctx.encrypt(&cleartext_file.to_string_lossy(), file)
}

/// Encrypt content from stdin or a file to a secret file.
///
/// Reads from stdin (or the specified input file) and encrypts the content to the specified file.
/// Does not require an editor or decryption capabilities.
///
/// In dry-run mode, the content is read and validated but not encrypted to disk.
pub fn encrypt_file(
    rules_path: &str,
    file: &str,
    input: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Check if file exists before doing any work
    if Path::new(file).exists() && !force {
        return Err(anyhow!(
            "Secret file already exists: {}\nUse --force to overwrite or 'agenix edit' to edit the existing secret",
            file
        ));
    }

    verbose!("Encrypting secret: {}", file);

    let ctx = EncryptionContext::new(rules_path, file)?;
    let filename = get_filename(file)?;
    let (_temp_dir, cleartext_file) = create_temp_cleartext(filename)?;

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

    log!("Encrypting to: {}", file);

    // In dry-run mode, skip only the final file write
    if dry_run {
        return Ok(());
    }

    ctx.encrypt(&cleartext_file.to_string_lossy(), file)
}

/// Decrypt a file to stdout or another location.
///
/// Validates the secret exists in rules before decrypting using the same
/// EncryptionContext validation as encrypt operations for unified code paths.
pub fn decrypt_file(
    rules_path: &str,
    file: &str,
    output: Option<&str>,
    identities: &[String],
    no_system_identities: bool,
) -> Result<()> {
    // Validate secret exists in rules using EncryptionContext (unified with encrypt)
    let _ = EncryptionContext::new(rules_path, file)?;

    verbose!("Decrypting secret: {}", file);
    let output_path = output.unwrap_or("/dev/stdout");
    verbose!("Decrypting to: {}", output_path);

    crypto::decrypt_to_file(
        file,
        Path::new(output_path),
        identities,
        no_system_identities,
    )
}

/// Compute the public file path for a secret.
///
/// The public file is always `{secret}.pub` (e.g., `secret.age.pub` for `secret.age`).
fn get_public_file_path(file: &str) -> String {
    format!("{}.pub", file)
}

/// Read the public file associated with a secret.
///
/// Outputs the contents of the `.pub` file to stdout or a specified output file.
/// The secret must exist in the rules file (validated via EncryptionContext).
pub fn read_public_file(rules_path: &str, file: &str, output: Option<&str>) -> Result<()> {
    // Validate secret exists in rules using EncryptionContext
    let _ = EncryptionContext::new(rules_path, file)?;

    let pub_file = get_public_file_path(file);
    verbose!("Reading public file: {}", pub_file);

    if !Path::new(&pub_file).exists() {
        return Err(anyhow!(
            "Public file does not exist: {}\nHint: Generate the secret first with 'agenix generate'",
            pub_file
        ));
    }

    let content = fs::read_to_string(&pub_file)
        .with_context(|| format!("Failed to read public file: {}", pub_file))?;

    let output_path = output.unwrap_or("/dev/stdout");
    verbose!("Writing to: {}", output_path);

    fs::write(output_path, content).with_context(|| format!("Failed to write to: {}", output_path))
}

/// Write content to the public file associated with a secret.
///
/// Reads content from stdin or a file and writes it to the `.pub` file.
/// The secret must exist in the rules file (validated via EncryptionContext).
///
/// In dry-run mode, validates the input but does not write the file.
pub fn write_public_file(
    rules_path: &str,
    file: &str,
    input: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Validate secret exists in rules using EncryptionContext
    let _ = EncryptionContext::new(rules_path, file)?;

    let pub_file = get_public_file_path(file);
    verbose!("Writing public file: {}", pub_file);

    // Check if file exists before doing any work
    if Path::new(&pub_file).exists() && !force {
        return Err(anyhow!(
            "Public file already exists: {}\nUse --force to overwrite or 'agenix edit --public' to edit the existing file",
            pub_file
        ));
    }

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

    log!("Writing to: {}", pub_file);

    // In dry-run mode, skip only the final file write
    if dry_run {
        log!("Dry-run mode: not saving changes to {}", pub_file);
        return Ok(());
    }

    fs::write(&pub_file, content)
        .with_context(|| format!("Failed to write public file: {}", pub_file))
}

/// Edit the public file associated with a secret using an editor.
///
/// Opens the `.pub` file in an editor for modification. If the file doesn't exist,
/// starts with an empty file. The secret must exist in the rules file.
///
/// In dry-run mode, opens the editor but does not save the changes.
pub fn edit_public_file(
    rules_path: &str,
    file: &str,
    editor_cmd: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    // Validate secret exists in rules using EncryptionContext
    let _ = EncryptionContext::new(rules_path, file)?;

    let pub_file = get_public_file_path(file);
    verbose!("Editing public file: {}", pub_file);

    let filename = get_filename(&pub_file)?;
    let (_temp_dir, temp_file) = create_temp_cleartext(filename)?;

    // Load existing content if present
    if Path::new(&pub_file).exists() {
        verbose!("Loading existing public file: {}", pub_file);
        let content = fs::read_to_string(&pub_file)
            .with_context(|| format!("Failed to read public file: {}", pub_file))?;
        fs::write(&temp_file, content).context("Failed to write to temporary file")?;
    } else if !force {
        return Err(anyhow!(
            "Public file does not exist: {}\nUse --force to create a new file or generate the secret first",
            pub_file
        ));
    }

    // Create backup for change detection
    let backup_file = format!("{}.backup", temp_file.to_string_lossy());
    if temp_file.exists() {
        fs::copy(&temp_file, &backup_file)?;
    }

    // Determine how to edit the file
    let editor_choice = determine_editor(editor_cmd);

    // Edit the file based on the chosen method
    let skip_change_check = match &editor_choice {
        EditorChoice::Command(cmd) if cmd == ":" => {
            verbose!("Skipping editor (rekey mode)");
            true
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
            false
        }
        EditorChoice::Stdin => {
            verbose!("Reading content from stdin");
            let mut stdin_content = String::new();
            io::stdin()
                .read_to_string(&mut stdin_content)
                .context("Failed to read from stdin")?;

            if stdin_content.is_empty() {
                return Err(anyhow!("No input provided on stdin"));
            }

            fs::write(&temp_file, stdin_content).context("Failed to write stdin content")?;
            false
        }
    };

    // Handle case where editor didn't create the file
    if !temp_file.exists() {
        log!("Warning: {} wasn't created", pub_file);
        return Ok(());
    }

    // Skip save if content unchanged (only when editor was invoked)
    if !skip_change_check
        && Path::new(&backup_file).exists()
        && files_equal(&backup_file, &temp_file.to_string_lossy())?
    {
        log!("Warning: {} wasn't changed, skipping save", pub_file);
        return Ok(());
    }

    log!("Saving to: {}", pub_file);

    // In dry-run mode, skip the actual save
    if dry_run {
        log!("Dry-run mode: not saving changes to {}", pub_file);
        return Ok(());
    }

    // Copy content from temp file to pub file
    let content = fs::read_to_string(&temp_file).context("Failed to read edited content")?;
    fs::write(&pub_file, content)
        .with_context(|| format!("Failed to write public file: {}", pub_file))
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
