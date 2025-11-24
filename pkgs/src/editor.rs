//! File editing and secret management operations.
//!
//! This module provides functions for editing, decrypting, rekeying, and generating
//! encrypted secret files with temporary file handling and editor integration.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::{self, IsTerminal, Read, stdin};
use std::path::{Path, PathBuf};
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

/// Strip .age suffix from a name if present
fn strip_age_suffix(name: &str) -> &str {
    name.strip_suffix(".age").unwrap_or(name)
}

/// Normalize a secret name: extract basename and strip .age suffix
fn normalize_secret_name(name: &str) -> String {
    let basename = secret_basename(name);
    strip_age_suffix(&basename).to_string()
}

/// Resolve a dependency name to its full file path from the files list
/// Maps simple names like "level2" to full paths like "/tmp/test/level2.age"
fn resolve_dependency_path<'a>(dep: &'a str, files: &'a [String]) -> &'a str {
    files
        .iter()
        .find(|f| {
            let f_normalized = normalize_secret_name(f);
            let dep_normalized = strip_age_suffix(dep);
            f_normalized == dep_normalized
        })
        .map(|s| s.as_str())
        .unwrap_or(dep)
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

/// Get public content for a secret from either generated secrets or .pub files
fn get_public_content(
    file: &str,
    rules_dir: &Path,
    generated: &std::collections::HashMap<String, GeneratorOutput>,
) -> Result<Option<String>> {
    let secret_name = strip_age_suffix(file);
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
    // If secret_name looks like an absolute path, use it directly
    // Otherwise, join with rules_dir
    let pub_file_paths = if secret_name.starts_with('/') || secret_name.starts_with('\\') {
        // Absolute path - use directly
        vec![
            PathBuf::from(format!("{}.age.pub", secret_name)),
            PathBuf::from(format!("{}.pub", secret_name)),
        ]
    } else {
        // Relative path - join with rules_dir
        vec![
            rules_dir.join(format!("{}.age.pub", secret_name)),
            rules_dir.join(format!("{}.pub", secret_name)),
        ]
    };

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

/// Check if a single dependency is satisfied (has public content available)
fn check_dependency_satisfied(
    dep: &str,
    file: &str,
    files: &[String],
    rules_dir: &Path,
    generated_secrets: &std::collections::HashMap<String, GeneratorOutput>,
    processed: &std::collections::HashSet<String>,
) -> Result<(bool, bool)> {
    // Map dependency name to full file path
    let dep_file = resolve_dependency_path(dep, files);

    // Normalize the dependency name
    let dep_normalized = if dep_file.ends_with(".age") {
        dep_file.to_string()
    } else {
        format!("{}.age", dep_file)
    };

    // Check if the dependency will be generated (exists in files list)
    let dep_basename = secret_basename(&dep_normalized);
    let will_be_generated = files.iter().any(|f| secret_basename(f) == dep_basename);

    // Check if dependency file exists
    let dep_file_path = rules_dir.join(&dep_normalized);
    let exists = dep_file_path.exists();

    // Check if we have public content already (use full path for lookup)
    let has_public_content = get_public_content(dep_file, rules_dir, generated_secrets)?.is_some();

    if !will_be_generated && !exists && !has_public_content {
        // Dependency cannot be satisfied at all
        return Ok((false, true)); // (not satisfied, is missing)
    } else if will_be_generated && !has_public_content {
        // Check if dependency has been processed
        let is_processed = processed.iter().any(|p| secret_basename(p) == dep_basename);

        if !is_processed {
            // Dependency will be generated but hasn't been yet
            return Ok((false, false)); // (not satisfied, not missing - just pending)
        }
    } else if exists && !has_public_content {
        // File exists but no public content available
        return Ok((false, false)); // (not satisfied, not missing - just no public)
    }

    Ok((true, false)) // (satisfied, not missing)
}

/// Check if all dependencies for a secret are satisfied
fn are_all_dependencies_satisfied(
    file: &str,
    deps: &[String],
    files: &[String],
    rules_dir: &Path,
    generated_secrets: &std::collections::HashMap<String, GeneratorOutput>,
    processed: &std::collections::HashSet<String>,
) -> Result<(bool, Vec<String>)> {
    let mut all_deps_satisfied = true;
    let mut missing_deps = Vec::new();

    for dep in deps {
        let (satisfied, is_missing) =
            check_dependency_satisfied(dep, file, files, rules_dir, generated_secrets, processed)?;

        if is_missing {
            missing_deps.push(dep.clone());
        }
        if !satisfied {
            all_deps_satisfied = false;
        }
    }

    Ok((all_deps_satisfied, missing_deps))
}

/// Build the Nix context (secrets and publics attrsets) for dependencies
fn build_dependency_context(
    deps: &[String],
    files: &[String],
    rules_dir: &Path,
    generated_secrets: &std::collections::HashMap<String, GeneratorOutput>,
) -> Result<String> {
    if deps.is_empty() {
        return Ok("{}".to_string());
    }

    let mut secrets_context_parts = Vec::new();
    let mut publics_context_parts = Vec::new();

    for dep in deps {
        // Map dependency name to full file path
        let dep_file = resolve_dependency_path(dep, files);

        // Extract basename for use as key in context
        let dep_key = normalize_secret_name(dep_file);

        // Add public content
        if let Some(public_content) = get_public_content(dep_file, rules_dir, generated_secrets)? {
            let escaped_public = escape_nix_string(&public_content);
            publics_context_parts.push(format!(r#""{}" = "{}";"#, dep_key, escaped_public));
        }

        // Add secret content if available (from generated_secrets)
        let dep_basename = if dep_file.ends_with(".age") {
            dep_file.to_string()
        } else {
            format!("{}.age", dep_file)
        };
        let dep_basename_norm = secret_basename(&dep_basename);

        for (key, output) in generated_secrets.iter() {
            if secret_basename(key) == dep_basename_norm {
                let escaped_secret = escape_nix_string(&output.secret);
                secrets_context_parts.push(format!(r#""{}" = "{}";"#, dep_key, escaped_secret));
                break;
            }
        }
    }

    let secrets_part = if !secrets_context_parts.is_empty() {
        format!("secrets = {{ {} }};", secrets_context_parts.join(" "))
    } else {
        "secrets = {};".to_string()
    };

    let publics_part = if !publics_context_parts.is_empty() {
        format!("publics = {{ {} }};", publics_context_parts.join(" "))
    } else {
        "publics = {};".to_string()
    };

    Ok(format!("{{ {} {} }}", secrets_part, publics_part))
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
            let (all_deps_satisfied, missing_deps) = are_all_dependencies_satisfied(
                &file,
                &deps,
                &files,
                rules_dir,
                &generated_secrets,
                &processed,
            )?;

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

            // Build the context for the generator
            let secrets_arg =
                build_dependency_context(&deps, &files, rules_dir, &generated_secrets)?;

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
                    "Cannot generate secrets due to unresolved dependencies (possible circular dependency):\n{}",
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
    generator = {{ publics }}: "ssh-key-pub: " + publics."ssh-key";
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
    generator = {{ publics }}: "derived-from-" + publics.base;
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

    #[test]
    fn test_generate_secrets_with_different_generator_patterns() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary directory
        let temp_dir = tempdir()?;

        // Create rules with generators accepting different parameter patterns
        let rules_content = format!(
            r#"
{{
  "{}/base-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret-value"; public = "base-public-value"; }};
  }};
  "{}/only-publics.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base-secret" ];
    generator = {{ publics }}: "public: " + publics."base-secret";
  }};
  "{}/only-secrets.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base-secret" ];
    generator = {{ secrets }}: "secret: " + secrets."base-secret";
  }};
  "{}/both-secrets-and-publics.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base-secret" ];
    generator = {{ secrets, publics }}: "secret: " + secrets."base-secret" + ", public: " + publics."base-secret";
  }};
  "{}/ignore-deps-with-empty.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base-secret" ];
    generator = {{ }}: "ignoring-all-params";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        // Generate secrets - should handle all patterns
        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generation should succeed with different parameter patterns: {:?}",
            result.err()
        );

        // All files should exist
        let base_path = temp_dir.path().join("base-secret.age");
        let only_publics_path = temp_dir.path().join("only-publics.age");
        let only_secrets_path = temp_dir.path().join("only-secrets.age");
        let both_path = temp_dir.path().join("both-secrets-and-publics.age");
        let ignore_path = temp_dir.path().join("ignore-deps-with-empty.age");

        assert!(base_path.exists(), "base-secret.age should be created");
        assert!(
            only_publics_path.exists(),
            "only-publics.age should be created"
        );
        assert!(
            only_secrets_path.exists(),
            "only-secrets.age should be created"
        );
        assert!(
            both_path.exists(),
            "both-secrets-and-publics.age should be created"
        );
        assert!(
            ignore_path.exists(),
            "ignore-deps-with-empty.age should be created"
        );

        Ok(())
    }

    // Complex dependency chain tests
    #[test]
    fn test_dependency_chain_full() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Chain: level1 -> level2 -> level3
        let rules_content = format!(
            r#"
{{
  "{}/level1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "level2-" + publics."level1"; public = "level2-public"; }};
  }};
  "{}/level3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: "level3-" + publics."level2";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle full dependency chain: {:?}",
            result.err()
        );

        // All three files should be created
        assert!(temp_dir.path().join("level1.age").exists());
        assert!(temp_dir.path().join("level2.age").exists());
        assert!(temp_dir.path().join("level3.age").exists());

        Ok(())
    }

    #[test]
    fn test_dependency_chain_middle_exists() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Pre-create middle secret with public key
        let level2_path = temp_dir.path().join("level2.age");
        let level2_pub_path = temp_dir.path().join("level2.age.pub");
        std::fs::write(&level2_path, "existing-level2-encrypted")?;
        std::fs::write(&level2_pub_path, "existing-level2-public")?;

        // Chain: level1 -> level2 (exists) -> level3
        let rules_content = format!(
            r#"
{{
  "{}/level1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "level2-" + publics."level1"; public = "level2-public"; }};
  }};
  "{}/level3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: "level3-" + publics."level2";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle chain with existing middle: {:?}",
            result.err()
        );

        // level1 and level3 should be generated, level2 should be skipped
        assert!(temp_dir.path().join("level1.age").exists());
        assert!(temp_dir.path().join("level3.age").exists());
        // level2 content should remain unchanged
        let level2_content = std::fs::read_to_string(&level2_path)?;
        assert_eq!(level2_content, "existing-level2-encrypted");

        Ok(())
    }

    #[test]
    fn test_dependency_chain_middle_needs_secret_only_public_available() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Pre-create middle secret with only public key (no encrypted file)
        let level2_pub_path = temp_dir.path().join("level2.age.pub");
        std::fs::write(&level2_pub_path, "existing-level2-public")?;

        // Chain where level3 needs the SECRET from level2 but only public is available
        let rules_content = format!(
            r#"
{{
  "{}/level1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "level2-" + publics."level1"; public = "level2-public"; }};
  }};
  "{}/level3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ secrets }}: "level3-" + secrets."level2";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);

        // This should succeed because level2 will be generated (not skipped)
        // since it doesn't already exist as an encrypted file
        assert!(
            result.is_ok(),
            "Should generate level2 and then level3: {:?}",
            result.err()
        );

        assert!(temp_dir.path().join("level2.age").exists());
        assert!(temp_dir.path().join("level3.age").exists());

        Ok(())
    }

    #[test]
    fn test_dependency_chain_missing_middle() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Chain where middle secret is not defined in rules
        let rules_content = format!(
            r#"
{{
  "{}/level1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "level2" ];
    generator = {{ publics }}: "level3-" + publics."level2";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Should fail with missing dependency");

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("depends on")
                || err_msg.contains("level2")
                || err_msg.contains("cannot be found"),
            "Error message should mention missing dependency 'level2': {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_circular_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Circular: secret1 -> secret2 -> secret1
        let rules_content = format!(
            r#"
{{
  "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "s1-" + publics."secret2"; public = "p1"; }};
  }};
  "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "s2-" + publics."secret1"; public = "p2"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Should fail with circular dependency");

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("Maximum iterations")
                || err_msg.contains("circular")
                || err_msg.contains("depends"),
            "Error message should indicate circular dependency issue: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_diamond_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Diamond: base -> left + right -> top
        let rules_content = format!(
            r#"
{{
  "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/left.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "left-" + publics."base"; public = "left-public"; }};
  }};
  "{}/right.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "right-" + publics."base"; public = "right-public"; }};
  }};
  "{}/top.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: "top-" + publics."left" + "-" + publics."right";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle diamond dependency: {:?}",
            result.err()
        );

        // All four files should be created
        assert!(temp_dir.path().join("base.age").exists());
        assert!(temp_dir.path().join("left.age").exists());
        assert!(temp_dir.path().join("right.age").exists());
        assert!(temp_dir.path().join("top.age").exists());

        Ok(())
    }

    #[test]
    fn test_multiple_independent_chains() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Two independent chains: chain1: a -> b and chain2: x -> y
        let rules_content = format!(
            r#"
{{
  "{}/a.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "a-secret"; public = "a-public"; }};
  }};
  "{}/b.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: "b-" + publics."a";
  }};
  "{}/x.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "x-secret"; public = "x-public"; }};
  }};
  "{}/y.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: "y-" + publics."x";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle multiple independent chains: {:?}",
            result.err()
        );

        // All files should be created
        assert!(temp_dir.path().join("a.age").exists());
        assert!(temp_dir.path().join("b.age").exists());
        assert!(temp_dir.path().join("x.age").exists());
        assert!(temp_dir.path().join("y.age").exists());

        Ok(())
    }

    #[test]
    fn test_mixed_explicit_and_auto_dependencies() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Mix of explicit dependencies and auto-detected ones
        let rules_content = format!(
            r#"
{{
  "{}/key1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "key1"; public = "pub1"; }};
  }};
  "{}/key2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "key2"; public = "pub2"; }};
  }};
  "{}/auto-detected.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: publics."key1";
  }};
  "{}/explicit.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "key2" ];
    generator = {{ publics }}: publics."key2";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle mixed explicit and auto dependencies: {:?}",
            result.err()
        );

        assert!(temp_dir.path().join("key1.age").exists());
        assert!(temp_dir.path().join("key2.age").exists());
        assert!(temp_dir.path().join("auto-detected.age").exists());
        assert!(temp_dir.path().join("explicit.age").exists());

        Ok(())
    }

    #[test]
    fn test_dependency_on_both_secret_and_public() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // One secret depends on both the secret and public parts of another
        let rules_content = format!(
            r#"
{{
  "{}/source.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "source-secret"; public = "source-public"; }};
  }};
  "{}/combined.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ secrets, publics }}: secrets."source" + ":" + publics."source";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle dependency on both secret and public: {:?}",
            result.err()
        );

        assert!(temp_dir.path().join("source.age").exists());
        assert!(temp_dir.path().join("combined.age").exists());

        Ok(())
    }

    #[test]
    fn test_long_chain_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Long chain: step1 -> step2 -> step3 -> step4 -> step5
        let rules_content = format!(
            r#"
{{
  "{}/step1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "step1"; public = "pub1"; }};
  }};
  "{}/step2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "step2-" + publics."step1"; public = "pub2"; }};
  }};
  "{}/step3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "step3-" + publics."step2"; public = "pub3"; }};
  }};
  "{}/step4.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "step4-" + publics."step3"; public = "pub4"; }};
  }};
  "{}/step5.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: "step5-" + publics."step4";
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle long dependency chain: {:?}",
            result.err()
        );

        // All five files should be created
        for i in 1..=5 {
            assert!(
                temp_dir.path().join(format!("step{}.age", i)).exists(),
                "step{}.age should be created",
                i
            );
        }

        Ok(())
    }

    #[test]
    fn test_self_circular_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Self-circular: secret depends on itself
        let rules_content = format!(
            r#"
{{
  "{}/self.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "s-" + publics."self"; public = "p"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Should fail with self-circular dependency");

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("circular") || err_msg.contains("depends"),
            "Error message should indicate circular dependency: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_deep_circular_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Deep circular: A -> B -> C -> A
        let rules_content = format!(
            r#"
{{
  "{}/secretA.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "A-" + publics."secretB"; public = "pA"; }};
  }};
  "{}/secretB.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "B-" + publics."secretC"; public = "pB"; }};
  }};
  "{}/secretC.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "C-" + publics."secretA"; public = "pC"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Should fail with deep circular dependency");

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("circular") || err_msg.contains("depends"),
            "Error message should indicate circular dependency: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_missing_dependency_in_long_chain() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Chain with missing middle: step1 -> step2 -> [missing] -> step4
        let rules_content = format!(
            r#"
{{
  "{}/step1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "step1"; public = "pub1"; }};
  }};
  "{}/step2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "step2-" + publics."step1"; public = "pub2"; }};
  }};
  "{}/step4.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "step4-" + publics."step3"; public = "pub4"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Should fail with missing dependency");

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("step3") || err_msg.contains("cannot be found"),
            "Error message should mention missing 'step3': {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_multiple_circular_clusters() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Two independent circular clusters: (A -> B -> A) and (C -> D -> C)
        let rules_content = format!(
            r#"
{{
  "{}/secretA.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "A-" + publics."secretB"; public = "pA"; }};
  }};
  "{}/secretB.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "B-" + publics."secretA"; public = "pB"; }};
  }};
  "{}/secretC.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "C-" + publics."secretD"; public = "pC"; }};
  }};
  "{}/secretD.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "D-" + publics."secretC"; public = "pD"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_err(),
            "Should fail with multiple circular dependencies"
        );

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("circular") || err_msg.contains("depends"),
            "Error message should indicate circular dependency: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_mixed_generated_and_manual_secrets() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Mix of secrets with generators and without
        // manual.age (no generator) -> generated.age (has generator, depends on manual)

        // Create manual.age file and its .pub file
        let manual_secret = temp_dir.path().join("manual.age");
        fs::write(&manual_secret, b"manually created secret")?;
        let manual_pub = temp_dir.path().join("manual.age.pub");
        fs::write(&manual_pub, "manual-public-key")?;

        let rules_content = format!(
            r#"
{{
  "{}/manual.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/generated.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "gen-" + publics."manual"; public = "gen-pub"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle mix of manual and generated secrets: {:?}",
            result.err()
        );

        // Check that generated.age was created
        assert!(
            temp_dir.path().join("generated.age").exists(),
            "generated.age should be created"
        );

        Ok(())
    }

    #[test]
    fn test_dependency_with_explicit_age_suffix() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Test that dependencies work whether they include .age suffix or not
        let rules_content = format!(
            r#"
{{
  "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base"; public = "base-pub"; }};
  }};
  "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base.age" ];
    generator = {{ publics }}: {{ secret = "derived-" + publics."base"; public = "derived-pub"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle .age suffix in dependencies: {:?}",
            result.err()
        );

        assert!(
            temp_dir.path().join("base.age").exists(),
            "base.age should be created"
        );
        assert!(
            temp_dir.path().join("derived.age").exists(),
            "derived.age should be created"
        );

        Ok(())
    }

    #[test]
    fn test_complex_multi_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Secret depends on multiple other secrets
        let rules_content = format!(
            r#"
{{
  "{}/key1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "k1-secret"; public = "k1-pub"; }};
  }};
  "{}/key2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "k2-secret"; public = "k2-pub"; }};
  }};
  "{}/key3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "k3-secret"; public = "k3-pub"; }};
  }};
  "{}/combined.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ 
      secret = publics."key1" + "-" + publics."key2" + "-" + publics."key3"; 
      public = "combined-pub"; 
    }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle multi-dependency: {:?}",
            result.err()
        );

        // All files should be created
        assert!(temp_dir.path().join("key1.age").exists());
        assert!(temp_dir.path().join("key2.age").exists());
        assert!(temp_dir.path().join("key3.age").exists());
        assert!(temp_dir.path().join("combined.age").exists());

        Ok(())
    }

    #[test]
    fn test_partial_circular_with_independent() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Mix: independent.age (no deps) + circular pair (A -> B -> A)
        let rules_content = format!(
            r#"
{{
  "{}/independent.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "independent"; public = "ind-pub"; }};
  }};
  "{}/circA.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "A-" + publics."circB"; public = "pA"; }};
  }};
  "{}/circB.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "B-" + publics."circA"; public = "pB"; }};
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_err(),
            "Should fail due to circular dependency even with independent secret"
        );

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("circular") || err_msg.contains("depends"),
            "Error message should indicate circular dependency: {}",
            err_msg
        );

        // Independent secret should still be created
        assert!(
            temp_dir.path().join("independent.age").exists(),
            "independent.age should be created before circular error"
        );

        Ok(())
    }

    #[test]
    fn test_very_long_dependency_chain() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_dir = tempdir()?;

        // Chain of 10 secrets: s1 -> s2 -> ... -> s10
        let mut rules_parts = vec![];

        rules_parts.push(format!(
            r#"  "{}/s1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "s1"; public = "p1"; }};
  }};"#,
            temp_dir.path().to_str().unwrap()
        ));

        for i in 2..=10 {
            rules_parts.push(format!(
                r#"  "{}/s{}.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ publics }}: {{ secret = "s{}-" + publics."s{}"; public = "p{}"; }};
  }};"#,
                temp_dir.path().to_str().unwrap(),
                i,
                i,
                i - 1,
                i
            ));
        }

        let rules_content = format!("{{\n{}\n}}", rules_parts.join("\n"));

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        let args = vec![
            "agenix".to_string(),
            "--generate".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Should handle very long dependency chain: {:?}",
            result.err()
        );

        // All 10 files should be created
        for i in 1..=10 {
            assert!(
                temp_dir.path().join(format!("s{}.age", i)).exists(),
                "s{}.age should be created",
                i
            );
        }

        Ok(())
    }
}
