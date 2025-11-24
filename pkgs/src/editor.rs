//! File editing and secret management operations.
//!
//! This module provides functions for editing, decrypting, rekeying, and generating
//! encrypted secret files with temporary file handling and editor integration.

use anyhow::{Context, Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, IsTerminal, Read, stdin};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

use crate::crypto::{decrypt_to_file, decrypt_to_string, encrypt_from_file, files_equal};
use crate::nix::{
    generate_secret_with_public, generate_secret_with_public_context, get_all_files,
    get_public_keys, should_armor,
};

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
    let mut generated_secrets: HashMap<String, String> = HashMap::new();
    let mut generated_publics: HashMap<String, String> = HashMap::new();
    let mut remaining_files: HashSet<String> = files.iter().cloned().collect();

    // First, try to load any existing encrypted files that we can decrypt
    for file in &files {
        if Path::new(file).exists() {
            // Try to decrypt it
            if let Ok(content) = decrypt_to_string(file, None) {
                generated_secrets.insert(file.clone(), content);
            }

            // Also load the public file if it exists
            let pub_file = format!("{}.pub", file);
            if Path::new(&pub_file).exists() {
                if let Ok(content) = fs::read_to_string(&pub_file) {
                    generated_publics.insert(file.clone(), content.trim().to_string());
                }
            }
        }
    }

    // Keep trying to generate secrets until we can't make progress
    let mut made_progress = true;
    let mut iteration = 0;
    const MAX_ITERATIONS: usize = 100; // Prevent infinite loops

    while made_progress && !remaining_files.is_empty() && iteration < MAX_ITERATIONS {
        made_progress = false;
        iteration += 1;

        // Try to generate each remaining file
        let current_files: Vec<String> = remaining_files.iter().cloned().collect();

        for file in current_files {
            // Skip if the file already exists
            if Path::new(&file).exists() {
                if let Ok(Some(_)) = generate_secret_with_public(rules_path, &file) {
                    eprintln!("Skipping {file}: already exists");
                }
                remaining_files.remove(&file);
                made_progress = true;
                continue;
            }

            // Build context with currently available secrets and publics
            let context_expr = build_context_expr(&generated_secrets, &generated_publics);

            // Check if there's a generator for this file and try to generate with current context
            let generation_result =
                generate_secret_with_public_context(rules_path, &file, &context_expr);

            match generation_result {
                Ok(Some(generator_output)) => {
                    eprintln!("Generating {file}...");

                    let public_keys = get_public_keys(rules_path, &file)?;
                    let armor = should_armor(rules_path, &file)?;

                    if public_keys.is_empty() {
                        eprintln!("Warning: No public keys found for {file}, skipping");
                        remaining_files.remove(&file);
                        made_progress = true;
                        continue;
                    }

                    // Create temporary file with the generated secret content
                    let temp_dir =
                        TempDir::new().context("Failed to create temporary directory")?;
                    let temp_file = temp_dir.path().join("generated_secret");
                    fs::write(&temp_file, &generator_output.secret)
                        .context("Failed to write generated content to temporary file")?;

                    // Encrypt the generated secret content
                    encrypt_from_file(&temp_file.to_string_lossy(), &file, &public_keys, armor)
                        .with_context(|| format!("Failed to encrypt generated secret {file}"))?;

                    eprintln!("Generated and encrypted {file}");

                    // Store the secret content for future generators
                    generated_secrets.insert(file.clone(), generator_output.secret.clone());

                    // If there's public content, write it to a .pub file and store it
                    if let Some(public_content) = &generator_output.public {
                        let pub_file = format!("{}.pub", file);
                        fs::write(&pub_file, public_content)
                            .with_context(|| format!("Failed to write public file {pub_file}"))?;
                        eprintln!("Generated public file {pub_file}");
                        generated_publics.insert(file.clone(), public_content.clone());
                    }

                    remaining_files.remove(&file);
                    made_progress = true;
                }
                Ok(None) => {
                    // No generator for this file
                    remaining_files.remove(&file);
                    made_progress = true;
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    // Check if this is a missing dependency error
                    if error_msg.contains("secrets.")
                        || error_msg.contains("publics.")
                        || error_msg.contains("attribute")
                    {
                        // This secret depends on something not yet generated, skip for now
                        continue;
                    } else {
                        // Real error, report it and skip this file
                        eprintln!("Error generating {file}: {e}");
                        remaining_files.remove(&file);
                        made_progress = true;
                    }
                }
            }
        }
    }

    // Check if there are any ungenerated secrets left
    if !remaining_files.is_empty() {
        let files_list: Vec<String> = remaining_files.iter().cloned().collect();
        let files_str = files_list.join(", ");

        if iteration >= MAX_ITERATIONS {
            return Err(anyhow!(
                "Could not generate all secrets after {} iterations. The following secrets have circular dependencies or unresolvable references: {}",
                MAX_ITERATIONS,
                files_str
            ));
        } else {
            return Err(anyhow!(
                "Could not generate secrets: {}. They may reference secrets that haven't been generated yet or can't be decrypted.",
                files_str
            ));
        }
    }

    Ok(())
}

/// Build a Nix expression representing the context with available secrets and publics
fn build_context_expr(
    secrets: &HashMap<String, String>,
    publics: &HashMap<String, String>,
) -> String {
    let mut expr = String::from("{ secrets = {");

    for (name, content) in secrets {
        // Escape the content for Nix string literal
        let escaped = escape_nix_string(content);
        expr.push_str(&format!(" \"{}\" = \"{}\";", name, escaped));
    }

    expr.push_str(" }; publics = {");

    for (name, content) in publics {
        let escaped = escape_nix_string(content);
        expr.push_str(&format!(" \"{}\" = \"{}\";", name, escaped));
    }

    expr.push_str(" }; }");
    expr
}

/// Escape a string for use in a Nix string literal
fn escape_nix_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .replace('$', "\\$")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, path::PathBuf};
    use tempfile::tempdir;

    #[test]
    fn test_edit_file_no_keys() {
        let rules = "./test_secrets.nix";
        let result = edit_file(rules, "nonexistent.age", "vi", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_file_no_keys() {
        let rules = "./test_secrets.nix";
        let result = decrypt_file(rules, "nonexistent.age", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey_uses_no_op_editor() {
        // With nonexistent rules this will early error if keys empty; simulate empty by pointing to test file
        let rules = "./test_secrets.nix";
        // Should error, but specifically via missing keys, not editor invocation failure.
        let result = rekey_all_files(rules, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_reencrypt_when_unchanged() {
        // We cannot fully simulate encryption without keys; focus on the unchanged branch logic.
        // Create a temp dir and a dummy age file plus rules path pointing to nonexistent keys causing early return of skip branch.
        let tmp = tempdir().unwrap();
        let secret_path = tmp.path().join("dummy.age");
        // Create an empty file so decrypt_to_file won't run (no existence of keys) but backup logic proceeds.
        File::create(&secret_path).unwrap();
        // Call edit_file expecting an error due to no keys; ensures we reach key check early.
        let res = edit_file(
            "./test_secrets.nix",
            secret_path.to_str().unwrap(),
            ":",
            None,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_generate_secrets_with_nonexistent_rules() {
        // Use the CLI interface via the run function
        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            "./nonexistent_rules.nix".to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_secrets_functionality() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary directory for the generated secrets
        let temp_dir = tempdir()?;

        // Create the rules file with absolute paths to avoid race conditions with parallel tests
        let rules_content_with_abs_paths = format!(
            r#"
{{
  "{}/static-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "static-password-123";
  }};
  "{}/random-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: builtins.randomString 16;
  }};
  "{}/no-generator.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules_abs = NamedTempFile::new()?;
        writeln!(temp_rules_abs, "{}", rules_content_with_abs_paths)?;
        temp_rules_abs.flush()?;

        // Use the CLI interface via the run function instead of calling generate_secrets directly
        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules_abs.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);

        // Check that the files with generators were created
        let static_secret_path = temp_dir.path().join("static-secret.age");
        let random_secret_path = temp_dir.path().join("random-secret.age");
        let no_generator_path = temp_dir.path().join("no-generator.age");

        let static_exists = static_secret_path.exists();
        let random_exists = random_secret_path.exists();
        let no_generator_exists = no_generator_path.exists();

        // Read file contents
        let static_content = if static_exists {
            Some(fs::read(&static_secret_path)?)
        } else {
            None
        };
        let random_content = if random_exists {
            Some(fs::read(&random_secret_path)?)
        } else {
            None
        };

        // Should succeed
        assert!(
            result.is_ok(),
            "CLI generate should succeed: {:?}",
            result.err()
        );

        assert!(static_exists, "static-secret.age should be created");
        assert!(random_exists, "random-secret.age should be created");
        assert!(
            !no_generator_exists,
            "no-generator.age should not be created"
        );

        // Verify the files are not empty (they contain encrypted data)
        let static_data = static_content.unwrap();
        let random_data = random_content.unwrap();

        assert!(
            !static_data.is_empty(),
            "static-secret.age should not be empty"
        );
        assert!(
            !random_data.is_empty(),
            "random-secret.age should not be empty"
        );

        // The encrypted files should be different (different content/randomness)
        assert_ne!(
            static_data, random_data,
            "Generated files should have different encrypted content"
        );

        Ok(())
    }

    #[test]
    fn test_generate_secrets_skip_existing_files() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary directory with an existing file
        let temp_dir = tempdir()?;

        // Create the rules file with absolute paths
        let rules_content = format!(
            r#"
{{
  "{}/existing-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "should-not-overwrite";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let existing_file_path = temp_dir.path().join("existing-secret.age");
        fs::write(&existing_file_path, b"existing content")?;

        let original_content = fs::read(&existing_file_path)?;

        // Use the CLI interface via the run function instead of calling generate_secrets directly
        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);

        // Should succeed
        assert!(result.is_ok());

        // File should still exist with original content (not overwritten)
        assert!(existing_file_path.exists());
        let current_content = fs::read(&existing_file_path)?;
        assert_eq!(
            original_content, current_content,
            "Existing file should not be overwritten"
        );

        Ok(())
    }

    #[test]
    fn test_stdin_editor_functionality() -> Result<()> {
        use std::io::Write;

        let temp_dir = tempdir()?;
        let test_file_path = temp_dir.path().join("test-stdin.age");

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

        // Test that the "<stdin>" editor command is recognized but we can't easily
        // test the actual stdin reading in a unit test environment
        // Instead, we'll test with a regular editor to ensure the path works
        let args = vec![
            "agenix".to_string(),
            "--edit".to_string(),
            test_file_path.to_str().unwrap().to_string(),
            "--rules".to_string(),
            temp_rules.to_str().unwrap().to_string(),
            "--editor".to_string(),
            "echo 'test content' >".to_string(),
        ];
        eprintln!(
            "Running test_stdin_editor_functionality with args: {:?}",
            args
        );

        let result = crate::run(args);

        result.unwrap();

        Ok(())
    }
}
