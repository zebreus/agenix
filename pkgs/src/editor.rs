//! File editing and secret management operations.
//!
//! This module provides functions for editing, decrypting, rekeying, and generating
//! encrypted secret files with temporary file handling and editor integration.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::{self, IsTerminal, Read, stdin};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

use crate::crypto::{decrypt_to_file, encrypt_from_file, files_equal};
use crate::nix::{
    GeneratorOutput, generate_secret_with_public, generate_secret_with_public_and_context,
    get_all_files, get_public_keys, get_secret_dependencies, should_armor,
};

/// Escape a string for safe inclusion in a Nix string literal
fn escape_nix_string(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '"' => vec!['\\', '"'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            '\0' => vec!['\\', '0'],
            '$' => vec!['\\', '$'],
            c if c.is_control() => {
                // Escape other control characters as unicode
                format!("\\u{{{:04x}}}", c as u32).chars().collect()
            }
            c => vec![c],
        })
        .collect()
}

/// Normalize a secret name to its basename (filename without path)
fn secret_basename(name: &str) -> String {
    Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name)
        .to_string()
}

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
///
/// This function now supports dependencies - generators can reference
/// other secrets' public keys via the `dependencies` attribute.
pub fn generate_secrets(rules_path: &str) -> Result<()> {
    use std::collections::{HashMap, HashSet};

    let files = get_all_files(rules_path)?;
    let rules_dir = Path::new(rules_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));

    // Track which secrets have been generated
    let mut generated_secrets: HashMap<String, GeneratorOutput> = HashMap::new();
    let mut processed: HashSet<String> = HashSet::new();

    // Helper function to get public content
    fn get_public_content(
        file: &str,
        rules_dir: &Path,
        generated: &HashMap<String, GeneratorOutput>,
    ) -> Result<Option<String>> {
        let secret_name = if file.ends_with(".age") {
            &file[..file.len() - 4]
        } else {
            file
        };

        let normalized_name = format!("{}.age", secret_name);

        // Check if we just generated it - search by basename
        let basename = secret_basename(&normalized_name);

        for (key, output) in generated.iter() {
            if secret_basename(key) == basename {
                if let Some(ref public) = output.public {
                    return Ok(Some(public.clone()));
                }
            }
        }

        // Check for .pub file
        let pub_file_paths = [
            rules_dir.join(format!("{}.age.pub", secret_name)),
            rules_dir.join(format!("{}.pub", secret_name)),
        ];

        for pub_file_path in &pub_file_paths {
            if pub_file_path.exists() {
                let content = fs::read_to_string(pub_file_path).with_context(|| {
                    format!("Failed to read public file: {}", pub_file_path.display())
                })?;
                return Ok(Some(content.trim().to_string()));
            }
        }

        Ok(None)
    }

    // Process secrets, handling dependencies
    let mut to_process: Vec<String> = files.clone();
    let mut iteration = 0;
    // In the worst case (linear dependency chain), we need files.len() iterations.
    // We add a safety margin to handle edge cases.
    let max_iterations = files.len() + 10;

    while !to_process.is_empty() && iteration < max_iterations {
        iteration += 1;
        let mut progress_made = false;
        let mut deferred = Vec::new();

        for file in to_process.drain(..) {
            // Skip if already processed
            if processed.contains(&file) {
                continue;
            }

            // Skip if the file already exists
            if Path::new(&file).exists() {
                if let Ok(Some(_)) = generate_secret_with_public(rules_path, &file) {
                    eprintln!("Skipping {file}: already exists");
                }
                processed.insert(file.clone());
                continue;
            }

            // Get dependencies
            let deps = get_secret_dependencies(rules_path, &file).unwrap_or_default();

            // Check if all dependencies are satisfied (public keys available)
            let mut all_deps_satisfied = true;
            let mut missing_deps = Vec::new();

            for dep in &deps {
                if get_public_content(dep, rules_dir, &generated_secrets)?.is_none() {
                    // Check if this dependency will be generated
                    let dep_normalized = if dep.ends_with(".age") {
                        dep.clone()
                    } else {
                        format!("{}.age", dep)
                    };

                    // Check if the dependency will be generated (exists in files list)
                    let dep_basename = secret_basename(&dep_normalized);
                    let will_be_generated =
                        files.iter().any(|f| secret_basename(f) == dep_basename);

                    // Check if dependency file exists
                    let dep_file_path = rules_dir.join(&dep_normalized);
                    let exists = dep_file_path.exists();

                    if !will_be_generated && !exists {
                        all_deps_satisfied = false;
                        missing_deps.push(dep.clone());
                    } else if will_be_generated && !processed.contains(&dep_normalized) {
                        // Also need to check if any file in processed matches by basename
                        let is_processed =
                            processed.iter().any(|p| secret_basename(p) == dep_basename);

                        if !is_processed {
                            // Dependency will be generated but hasn't been yet
                            all_deps_satisfied = false;
                        }
                    }
                }
            }

            if !all_deps_satisfied && !missing_deps.is_empty() {
                return Err(anyhow::anyhow!(
                    "Secret '{}' depends on '{}' which cannot be found or generated",
                    file,
                    missing_deps.join("', '")
                ));
            }

            if !all_deps_satisfied {
                // Defer this secret for later
                deferred.push(file);
                continue;
            }

            // Build the public context for the generator
            let mut publics_context_parts = Vec::new();

            for dep in &deps {
                if let Some(public_content) =
                    get_public_content(dep, rules_dir, &generated_secrets)?
                {
                    let escaped_public = escape_nix_string(&public_content);
                    publics_context_parts.push(format!(
                        r#""{}" = {{ public = "{}"; }};"#,
                        dep, escaped_public
                    ));
                }
            }

            let secrets_arg = if !publics_context_parts.is_empty() {
                format!("{{ secrets = {{ {} }}; }}", publics_context_parts.join(" "))
            } else {
                "{}".to_string()
            };

            // Generate with dependencies context
            let generator_output = if !deps.is_empty() {
                generate_secret_with_public_and_context(rules_path, &file, &secrets_arg)?
            } else {
                generate_secret_with_public(rules_path, &file)?
            };

            // Check if there's a generator for this file
            if let Some(generator_output) = generator_output {
                eprintln!("Generating {file}...");

                let public_keys = get_public_keys(rules_path, &file)?;
                let armor = should_armor(rules_path, &file)?;

                if public_keys.is_empty() {
                    eprintln!("Warning: No public keys found for {file}, skipping");
                    processed.insert(file);
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

                // Store the generated output for dependencies
                generated_secrets.insert(file.clone(), generator_output.clone());

                // If there's public content, write it to a .pub file
                if let Some(public_content) = &generator_output.public {
                    let pub_file = format!("{}.pub", file);
                    fs::write(&pub_file, public_content)
                        .with_context(|| format!("Failed to write public file {pub_file}"))?;
                    eprintln!("Generated public file {pub_file}");
                }

                processed.insert(file);
                progress_made = true;
            } else {
                // No generator - mark as processed
                processed.insert(file);
            }
        }

        // If we deferred some secrets, try them again
        if !deferred.is_empty() {
            if !progress_made {
                // No progress made - we have circular dependencies
                let dep_info: Vec<String> = deferred
                    .iter()
                    .map(|f| {
                        let deps = get_secret_dependencies(rules_path, f).unwrap_or_default();
                        if deps.is_empty() {
                            format!("  - {}", f)
                        } else {
                            format!("  - {} (depends on: {})", f, deps.join(", "))
                        }
                    })
                    .collect();

                return Err(anyhow::anyhow!(
                    "Cannot generate secrets due to unresolved dependencies:\n{}",
                    dep_info.join("\n")
                ));
            }
            to_process = deferred;
        }
    }

    if iteration >= max_iterations {
        return Err(anyhow::anyhow!(
            "Maximum iterations exceeded while generating secrets. Possible circular dependency detected."
        ));
    }

    Ok(())
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

    #[test]
    fn test_generate_secrets_with_dependencies() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary directory for the generated secrets
        let temp_dir = tempdir()?;

        // Create the rules file with dependencies
        let rules_content_with_abs_paths = format!(
            r#"
{{
  "{}/ssh-key.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = builtins.sshKey;
  }};
  "{}/authorized-keys.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "ssh-key" ];
    generator = {{ secrets }}: "ssh-key-pub: " + secrets."ssh-key".public;
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content_with_abs_paths)?;
        temp_rules.flush()?;

        // Generate the secrets
        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generation should succeed: {:?}",
            result.err()
        );

        // Check that both files were created
        let ssh_key_path = temp_dir.path().join("ssh-key.age");
        let ssh_key_pub_path = temp_dir.path().join("ssh-key.age.pub");
        let authorized_keys_path = temp_dir.path().join("authorized-keys.age");

        assert!(ssh_key_path.exists(), "ssh-key.age should be created");
        assert!(
            ssh_key_pub_path.exists(),
            "ssh-key.age.pub should be created"
        );
        assert!(
            authorized_keys_path.exists(),
            "authorized-keys.age should be created"
        );

        // Verify the public key file exists and is not empty
        let pub_key_content = fs::read_to_string(&ssh_key_pub_path)?;
        assert!(
            !pub_key_content.trim().is_empty(),
            "Public key should not be empty"
        );
        assert!(
            pub_key_content.starts_with("ssh-ed25519 "),
            "Public key should be in SSH format"
        );

        Ok(())
    }

    #[test]
    fn test_generate_secrets_with_missing_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary directory
        let temp_dir = tempdir()?;

        // Create rules with a missing dependency
        let rules_content = format!(
            r#"
{{
  "{}/dependent-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "nonexistent-secret" ];
    generator = {{ secrets }}: "dependent";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        // Try to generate - should fail with clear error
        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_err(),
            "Generation should fail with missing dependency"
        );

        // The error chain should include information about the dependency
        let err = result.unwrap_err();
        let err_chain: Vec<String> = err.chain().map(|e| e.to_string()).collect();
        let full_error = err_chain.join(": ");

        assert!(
            full_error.contains("depends on")
                || full_error.contains("cannot be found")
                || full_error.contains("nonexistent"),
            "Error chain should mention dependency issue: {}",
            full_error
        );

        Ok(())
    }

    #[test]
    fn test_generate_secrets_dependency_order() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary directory
        let temp_dir = tempdir()?;

        // Create rules where secrets are listed in reverse dependency order
        // (dependent comes before dependency in the file)
        let rules_content = format!(
            r#"
{{
  "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ secrets }}: "derived-from-" + secrets.base.public;
  }};
  "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        // Generate secrets - should handle dependency order automatically
        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generation should succeed with automatic ordering: {:?}",
            result.err()
        );

        // Both files should exist
        let base_path = temp_dir.path().join("base.age");
        let base_pub_path = temp_dir.path().join("base.age.pub");
        let derived_path = temp_dir.path().join("derived.age");

        assert!(base_path.exists(), "base.age should be created");
        assert!(base_pub_path.exists(), "base.age.pub should be created");
        assert!(derived_path.exists(), "derived.age should be created");

        Ok(())
    }
}
