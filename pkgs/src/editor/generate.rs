//! Secret generation operations.
//!
//! This module handles generating secrets using generator functions
//! defined in the rules file.

use anyhow::{Context, Result, anyhow};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

use crate::crypto::encrypt_from_file;
use crate::log;
use crate::nix::{
    generate_secret_with_public, generate_secret_with_public_and_context, get_all_files,
    get_public_keys, get_secret_dependencies, should_armor,
};

use super::context::SecretContext;
use super::dependency_resolver::DependencyResolver;
use super::filter_files;
use super::secret_name::SecretName;

/// Result of processing a single secret.
#[derive(Debug, PartialEq)]
pub enum ProcessResult {
    /// Secret was generated successfully
    Generated,
    /// Secret processing was deferred (waiting for dependencies)
    Deferred,
    /// Secret was already processed
    AlreadyProcessed,
    /// Secret has no generator defined
    NoGenerator,
    /// Secret has no public keys defined
    NoPublicKeys,
    /// Generator produced only public output (no secret to encrypt)
    PublicOnlyGenerated,
}

/// Validate that requested secrets exist in the rules file.
use super::validate_secrets_exist;

/// Build the list of files to process, including dependencies if requested.
fn build_processing_list(
    ctx: &SecretContext,
    secrets: &[String],
    with_dependencies: bool,
) -> Result<Vec<String>> {
    let mut files_to_process = if secrets.is_empty() {
        ctx.all_files().to_vec()
    } else {
        let filtered = filter_files(ctx.all_files(), secrets);
        validate_secrets_exist(&filtered, secrets)?;
        filtered
    };

    // If with_dependencies is set, expand the list to include dependencies
    if !secrets.is_empty() {
        let resolver = DependencyResolver::new(ctx);
        let mut deps_to_add: HashSet<String> = HashSet::new();

        for file in &files_to_process {
            resolver.collect_dependencies(file, &mut deps_to_add);
        }

        if with_dependencies {
            // Add dependencies to the processing list
            let existing_files: HashSet<_> = files_to_process.iter().cloned().collect();
            for dep in &deps_to_add {
                if !existing_files.contains(dep) {
                    files_to_process.push(dep.clone());
                }
            }
        } else if !deps_to_add.is_empty() {
            // Check if any required dependencies are missing
            check_missing_dependencies(ctx, &files_to_process, &deps_to_add)?;
        }
    }

    Ok(files_to_process)
}

/// Check for missing dependencies when --no-dependencies is used.
fn check_missing_dependencies(
    ctx: &SecretContext,
    files_to_process: &[String],
    deps_to_add: &HashSet<String>,
) -> Result<()> {
    let existing_files: HashSet<_> = files_to_process.iter().cloned().collect();

    let missing_deps: Vec<_> = deps_to_add
        .iter()
        .filter(|dep| {
            if existing_files.contains(*dep) {
                return false;
            }

            // Check if .pub file exists for this dependency
            let dep_name = SecretName::new(dep);
            let base_name = dep_name.normalized();

            let pub_paths = [
                std::path::PathBuf::from(format!("{}.pub", dep)),
                ctx.rules_dir().join(format!("{}.pub", base_name)),
                ctx.rules_dir().join(format!("{}.age.pub", base_name)),
            ];

            !pub_paths.iter().any(|p| p.exists())
        })
        .cloned()
        .collect();

    if !missing_deps.is_empty() {
        let deps_formatted: Vec<String> =
            missing_deps.iter().map(|d| format!("  - {}", d)).collect();
        return Err(anyhow!(
            "Cannot generate secrets: required dependencies are not being generated:\n{}\n\nHint: Remove --no-dependencies to automatically generate dependencies, or generate the missing dependencies first.",
            deps_formatted.join("\n")
        ));
    }

    Ok(())
}

/// Write the public key file if the generator produced one.
/// In dry-run mode, only logs what would happen without writing.
fn write_public_key_file(
    file: &str,
    output: &crate::nix::GeneratorOutput,
    dry_run: bool,
) -> Result<()> {
    if let Some(public_content) = &output.public {
        let pub_file = format!("{}.pub", file);
        if !dry_run {
            fs::write(&pub_file, public_content)
                .with_context(|| format!("Failed to write public file {pub_file}"))?;
        }
        log!("Generated public file {pub_file}");
    }
    Ok(())
}

/// Encrypt the generated secret content to the output file.
/// In dry-run mode, only validates that encryption would succeed without writing.
fn encrypt_secret(
    file: &str,
    secret_content: &str,
    rules_path: &str,
    dry_run: bool,
) -> Result<ProcessResult> {
    let public_keys = get_public_keys(rules_path, file)?;
    let armor = should_armor(rules_path, file)?;

    if public_keys.is_empty() {
        log!("Warning: No public keys found for {file}, skipping");
        return Ok(ProcessResult::NoPublicKeys);
    }

    // Skip actual encryption in dry-run mode
    if dry_run {
        return Ok(ProcessResult::Generated);
    }

    // Create temporary file with the generated secret content
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let temp_file = temp_dir.path().join("generated_secret");
    fs::write(&temp_file, secret_content)
        .context("Failed to write generated content to temporary file")?;

    // Encrypt the generated secret content
    encrypt_from_file(&temp_file.to_string_lossy(), file, &public_keys, armor)
        .with_context(|| format!("Failed to encrypt generated secret {file}"))?;

    Ok(ProcessResult::Generated)
}

/// Process a single secret file - check dependencies, generate, encrypt, and store.
fn process_single_secret(
    file: &str,
    ctx: &SecretContext,
    resolver: &mut DependencyResolver,
    force: bool,
    dry_run: bool,
) -> Result<ProcessResult> {
    // Skip if already processed
    if resolver.is_processed(file) {
        return Ok(ProcessResult::AlreadyProcessed);
    }

    // Skip if the file already exists (unless force is set)
    if Path::new(file).exists() && !force {
        if let Ok(Some(_)) = generate_secret_with_public(ctx.rules_path(), file) {
            log!("Skipping {file}: already exists (use --force to overwrite)");
        }
        resolver.mark_processed(file);
        return Ok(ProcessResult::AlreadyProcessed);
    }

    // Get dependencies
    let deps = get_secret_dependencies(ctx.rules_path(), file).unwrap_or_default();

    // Check if all dependencies are satisfied
    let (all_satisfied, missing) = resolver.are_all_dependencies_satisfied(&deps)?;

    if !all_satisfied && !missing.is_empty() {
        return Err(anyhow!(
            "Secret '{}' depends on '{}' which cannot be found or generated",
            file,
            missing.join("', '")
        ));
    }

    if !all_satisfied {
        return Ok(ProcessResult::Deferred);
    }

    // Build dependency context and generate the secret
    let context = resolver.build_dependency_context(&deps)?;
    let output_result = if !deps.is_empty() {
        generate_secret_with_public_and_context(ctx.rules_path(), file, &context)
    } else {
        generate_secret_with_public(ctx.rules_path(), file)
    };

    // Handle generator errors with helpful context about dependencies
    let output = match output_result {
        Ok(out) => out,
        Err(err) => {
            // Check if this might be a dependency-related error
            let err_str = err.to_string();
            if !deps.is_empty()
                && (err_str.contains("attribute") || err_str.contains("not found"))
            {
                // Get dependency availability info to provide better error context
                let dep_info = resolver.get_dependency_availability_info(&deps);
                if !dep_info.is_empty() {
                    return Err(anyhow!(
                        "Failed to generate '{}': {}\n\nPossible dependency issues:\n{}",
                        file,
                        err,
                        dep_info.join("\n")
                    ));
                }
            }
            return Err(err.context(format!("Failed to generate secret '{}'", file)));
        }
    };

    let Some(output) = output else {
        resolver.mark_processed(file);
        return Ok(ProcessResult::NoGenerator);
    };

    // Handle public-only generator output
    let Some(secret_content) = &output.secret else {
        // Generator produced only public output - write .pub file but no encrypted file
        log!("Generating public-only output for {file}...");
        write_public_key_file(file, &output, dry_run)?;
        resolver.store_generated(file, output.clone());
        resolver.mark_processed(file);
        log!("Generated public file for {file} (no secret to encrypt)");
        return Ok(ProcessResult::PublicOnlyGenerated);
    };

    // Encrypt and write the secret. In dry-run mode, validation occurs but no files are written.
    log!("Generating {file}...");
    let result = encrypt_secret(file, secret_content, ctx.rules_path(), dry_run)?;

    if result == ProcessResult::NoPublicKeys {
        resolver.mark_processed(file);
        return Ok(result);
    }

    log!("Generated and encrypted {file}");
    resolver.store_generated(file, output.clone());
    write_public_key_file(file, &output, dry_run)?;
    resolver.mark_processed(file);

    Ok(ProcessResult::Generated)
}

/// Format circular dependency error message.
fn handle_circular_dependency_error(deferred: &[String], rules_path: &str) -> Result<()> {
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

    Err(anyhow!(
        "Cannot generate secrets due to unresolved dependencies (possible circular dependency):\n{}",
        dep_info.join("\n")
    ))
}

/// Generate secrets using generator functions from rules.
///
/// Only generates secrets if:
/// 1. The file has a generator function defined
/// 2. The secret file doesn't already exist (unless force is set)
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `force` - Overwrite existing secret files
/// * `dry_run` - Show what would be generated without making changes
/// * `with_dependencies` - Generate dependencies of specified secrets (default: true)
/// * `secrets` - If empty, generates all secrets; otherwise only specified secrets
pub fn generate_secrets(
    rules_path: &str,
    force: bool,
    dry_run: bool,
    with_dependencies: bool,
    secrets: &[String],
) -> Result<()> {
    let all_files = get_all_files(rules_path)?;
    let ctx = SecretContext::new(rules_path, all_files.clone());

    let files_to_process = build_processing_list(&ctx, secrets, with_dependencies)?;

    // Create dependency resolver
    let mut resolver = DependencyResolver::new(&ctx);

    // Process secrets, handling dependencies
    let mut to_process: Vec<String> = files_to_process.clone();
    let mut iteration = 0;
    // Safety buffer for dependency resolution to handle edge cases
    const DEPENDENCY_RESOLUTION_BUFFER: usize = 10;
    let max_iterations = all_files.len() + DEPENDENCY_RESOLUTION_BUFFER;

    while !to_process.is_empty() && iteration < max_iterations {
        iteration += 1;
        let mut progress_made = false;
        let mut deferred = Vec::new();

        for file in to_process.drain(..) {
            match process_single_secret(&file, &ctx, &mut resolver, force, dry_run)? {
                ProcessResult::Generated | ProcessResult::PublicOnlyGenerated => {
                    progress_made = true
                }
                ProcessResult::Deferred => deferred.push(file),
                ProcessResult::AlreadyProcessed
                | ProcessResult::NoGenerator
                | ProcessResult::NoPublicKeys => {}
            }
        }

        // Handle deferred secrets
        if !deferred.is_empty() {
            if !progress_made {
                return handle_circular_dependency_error(&deferred, rules_path);
            }
            to_process = deferred;
        }
    }

    if iteration >= max_iterations {
        return Err(anyhow!(
            "Maximum iterations exceeded while generating secrets. Possible circular dependency detected."
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_generate_secrets_with_nonexistent_rules() {
        // Use the CLI interface via the run function
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
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
    fn test_generate_force_overwrites_existing() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        // Create a temporary directory with an existing file
        let temp_dir = tempdir()?;
        // Create the rules file with absolute paths
        let rules_content = format!(
            r#"
    {{
      "{}/force-test.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "new-generated-content";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        let existing_file_path = temp_dir.path().join("force-test.age");
        fs::write(&existing_file_path, b"existing content")?;
        let original_content = fs::read(&existing_file_path)?;
        // Use --force flag to overwrite
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--force".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "generate --force should succeed: {:?}",
            result.err()
        );
        // File should have been overwritten (content should be different)
        let current_content = fs::read(&existing_file_path)?;
        assert_ne!(
            original_content, current_content,
            "Existing file should be overwritten with --force"
        );
        Ok(())
    }
    #[test]
    fn test_generate_dry_run_no_changes() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/dry-run-test.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "should-not-be-created";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        // Use --dry-run flag
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--dry-run".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "generate --dry-run should succeed: {:?}",
            result.err()
        );
        // File should NOT have been created
        let secret_path = temp_dir.path().join("dry-run-test.age");
        assert!(
            !secret_path.exists(),
            "Secret file should not be created in dry-run mode"
        );
        Ok(())
    }
    #[test]
    fn test_generate_dry_run_with_existing_file() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/existing-dry-run.age" = {{
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
        let existing_file_path = temp_dir.path().join("existing-dry-run.age");
        fs::write(&existing_file_path, b"existing content")?;
        let original_content = fs::read(&existing_file_path)?;
        // Use --force --dry-run flags (should preview overwrite but not change)
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--force".to_string(),
            "--dry-run".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "generate --force --dry-run should succeed: {:?}",
            result.err()
        );
        // File should NOT have been overwritten
        let current_content = fs::read(&existing_file_path)?;
        assert_eq!(
            original_content, current_content,
            "Existing file should not be overwritten in dry-run mode even with --force"
        );
        Ok(())
    }
    #[test]
    fn test_generate_dry_run_with_dependencies() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Create rules with dependencies to test dry-run resolves them correctly
        let rules_content = format!(
            r#"
    {{
      "{}/base-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base-secret" ];
    generator = {{ publics }}: "derived-from-" + publics."base-secret";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        // Use --dry-run flag
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--dry-run".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "generate --dry-run with dependencies should succeed: {:?}",
            result.err()
        );
        // Neither file should be created
        assert!(
            !temp_dir.path().join("base-secret.age").exists(),
            "base-secret.age should not be created in dry-run mode"
        );
        assert!(
            !temp_dir.path().join("derived-secret.age").exists(),
            "derived-secret.age should not be created in dry-run mode"
        );
        Ok(())
    }
    #[test]
    fn test_generate_force_short_flag() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/force-short.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "new-content";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        let existing_file_path = temp_dir.path().join("force-short.age");
        fs::write(&existing_file_path, b"existing content")?;
        let original_content = fs::read(&existing_file_path)?;
        // Use -f short flag for --force
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "-f".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "generate -f should succeed: {:?}",
            result.err()
        );
        let current_content = fs::read(&existing_file_path)?;
        assert_ne!(
            original_content, current_content,
            "Existing file should be overwritten with -f"
        );
        Ok(())
    }
    #[test]
    fn test_generate_dry_run_short_flag() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/dry-run-short.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "should-not-be-created";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        // Use -n short flag for --dry-run
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "-n".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "generate -n should succeed: {:?}",
            result.err()
        );
        let secret_path = temp_dir.path().join("dry-run-short.age");
        assert!(
            !secret_path.exists(),
            "Secret file should not be created in dry-run mode with -n"
        );
        Ok(())
    }
    // Tests for positional secrets filtering
    #[test]
    fn test_generate_specific_secrets() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content1";
      }};
      "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content2";
      }};
      "{}/secret3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content3";
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
        // Only generate secret1.age
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "secret1".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate specific secrets should succeed: {:?}",
            result.err()
        );
        // Only secret1.age should be created
        assert!(
            temp_dir.path().join("secret1.age").exists(),
            "secret1.age should be created"
        );
        assert!(
            !temp_dir.path().join("secret2.age").exists(),
            "secret2.age should NOT be created"
        );
        assert!(
            !temp_dir.path().join("secret3.age").exists(),
            "secret3.age should NOT be created"
        );
        Ok(())
    }
    #[test]
    fn test_generate_multiple_specific_secrets() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content1";
      }};
      "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content2";
      }};
      "{}/secret3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content3";
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
        // Generate secret1 and secret3
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "secret1".to_string(),
            "secret3".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate multiple specific secrets should succeed: {:?}",
            result.err()
        );
        // secret1 and secret3 should be created, secret2 should not
        assert!(
            temp_dir.path().join("secret1.age").exists(),
            "secret1.age should be created"
        );
        assert!(
            !temp_dir.path().join("secret2.age").exists(),
            "secret2.age should NOT be created"
        );
        assert!(
            temp_dir.path().join("secret3.age").exists(),
            "secret3.age should be created"
        );
        Ok(())
    }
    #[test]
    fn test_generate_with_age_suffix_in_filter() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content1";
      }};
      "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content2";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        // Test with .age suffix
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "secret1.age".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate with .age suffix should succeed: {:?}",
            result.err()
        );
        assert!(
            temp_dir.path().join("secret1.age").exists(),
            "secret1.age should be created"
        );
        assert!(
            !temp_dir.path().join("secret2.age").exists(),
            "secret2.age should NOT be created"
        );
        Ok(())
    }
    #[test]
    fn test_generate_nonexistent_secret_filter() {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
    {{
      "{}/existing.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();
        // Try to generate a nonexistent secret
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "nonexistent".to_string(),
        ];
        let result = crate::run(args);
        assert!(result.is_err(), "Generate nonexistent secret should fail");
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("No matching secrets"),
            "Error should mention no matching secrets: {}",
            err_msg
        );
    }
    #[test]
    fn test_generate_default_with_dependencies() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Create a dependency chain: base -> derived
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
      "{}/unrelated.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "unrelated";
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
        // Generate only derived.age - dependencies should be generated by default
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "derived".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate with dependencies should succeed by default: {:?}",
            result.err()
        );
        // Both derived and its dependency base should be created (deps are generated by default)
        assert!(
            temp_dir.path().join("base.age").exists(),
            "base.age (dependency) should be created by default"
        );
        assert!(
            temp_dir.path().join("derived.age").exists(),
            "derived.age should be created"
        );
        // unrelated should NOT be created
        assert!(
            !temp_dir.path().join("unrelated.age").exists(),
            "unrelated.age should NOT be created"
        );
        Ok(())
    }
    #[test]
    fn test_generate_no_dependencies_flag_fails_on_missing_dep() {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir().unwrap();
        // Create a dependency chain: base -> derived
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();
        // Generate only derived.age WITH --no-dependencies
        // This should fail because base.age doesn't exist
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "derived".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_err(),
            "Generate with --no-dependencies should fail when dependency is missing"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("--no-dependencies") || err_msg.contains("required dependencies"),
            "Error should mention --no-dependencies or missing dependencies: {}",
            err_msg
        );
    }
    #[test]
    fn test_generate_transitive_dependencies() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Chain: a -> b -> c
        let rules_content = format!(
            r#"
    {{
      "{}/a.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "a-secret"; public = "a-public"; }};
      }};
      "{}/b.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "a" ];
    generator = {{ publics }}: {{ secret = "b-" + publics."a"; public = "b-public"; }};
      }};
      "{}/c.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "b" ];
    generator = {{ publics }}: "c-" + publics."b";
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
        // Generate only c.age - dependencies should be generated by default
        // Should generate a, b, and c
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "c".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate with transitive dependencies should succeed: {:?}",
            result.err()
        );
        // All three should be created
        assert!(
            temp_dir.path().join("a.age").exists(),
            "a.age should be created"
        );
        assert!(
            temp_dir.path().join("b.age").exists(),
            "b.age should be created"
        );
        assert!(
            temp_dir.path().join("c.age").exists(),
            "c.age should be created"
        );
        Ok(())
    }
    // Tests for default behavior: no secrets specified means all secrets in rules file
    #[test]
    fn test_generate_no_args_generates_all_secrets() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        let rules_content = format!(
            r#"
    {{
      "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content1";
      }};
      "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content2";
      }};
      "{}/secret3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content3";
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
        // Generate without specifying any secrets - should generate ALL
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate without args should generate all: {:?}",
            result.err()
        );
        // All three secrets should be created
        assert!(
            temp_dir.path().join("secret1.age").exists(),
            "secret1.age should be created"
        );
        assert!(
            temp_dir.path().join("secret2.age").exists(),
            "secret2.age should be created"
        );
        assert!(
            temp_dir.path().join("secret3.age").exists(),
            "secret3.age should be created"
        );
        Ok(())
    }
    // Tests for dependency behavior when existing secret has .pub file
    #[test]
    fn test_generate_uses_existing_pub_file() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Create a rules file where derived depends on base
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        // Create an existing .pub file for base (simulating a pre-generated dependency)
        let base_pub_path = temp_dir.path().join("base.age.pub");
        fs::write(&base_pub_path, "existing-base-public")?;
        // Generate only derived.age with --no-dependencies
        // This should succeed because base.age.pub exists
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "derived".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate should succeed when dependency has .pub file: {:?}",
            result.err()
        );
        // derived.age should be created
        assert!(
            temp_dir.path().join("derived.age").exists(),
            "derived.age should be created"
        );
        // base.age should NOT be created (we didn't generate it)
        assert!(
            !temp_dir.path().join("base.age").exists(),
            "base.age should NOT be created with --no-dependencies"
        );
        Ok(())
    }
    // Tests for helpful error messages
    #[test]
    fn test_generate_no_deps_helpful_error() {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();
        // Generate with --no-dependencies when deps are missing
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "derived".to_string(),
        ];
        let result = crate::run(args);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        // Should contain helpful hint about removing --no-dependencies
        assert!(
            err_msg.contains("--no-dependencies") || err_msg.contains("dependencies"),
            "Error should mention --no-dependencies: {}",
            err_msg
        );
    }
    // Tests for rekey --partial CLI option
    #[test]
    fn test_generate_with_pub_file_for_direct_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Simple chain: base -> derived, where base has .pub file
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        // Pre-create base.age.pub (simulating base was already generated)
        let base_pub_path = temp_dir.path().join("base.age.pub");
        fs::write(&base_pub_path, "pre-existing-base-public")?;
        // Generate only derived.age with --no-dependencies
        // This should succeed because base.age.pub exists
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "derived".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate derived should succeed when dependency base has .pub file: {:?}",
            result.err()
        );
        // derived.age should be created
        assert!(
            temp_dir.path().join("derived.age").exists(),
            "derived.age should be created"
        );
        // base.age should NOT be created (we didn't generate it)
        assert!(
            !temp_dir.path().join("base.age").exists(),
            "base.age should NOT be created with --no-dependencies"
        );
        Ok(())
    }
    #[test]
    fn test_generate_chain_needs_all_pub_files() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Chain: a -> b -> c
        // With --no-dependencies and generating only c, ALL deps need .pub files
        let rules_content = format!(
            r#"
    {{
      "{}/a.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "a-secret"; public = "a-public"; }};
      }};
      "{}/b.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "a" ];
    generator = {{ publics }}: {{ secret = "b-" + publics."a"; public = "b-public"; }};
      }};
      "{}/c.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "b" ];
    generator = {{ publics }}: "c-" + publics."b";
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
        // Pre-create both a.age.pub and b.age.pub (all deps need .pub files)
        let a_pub_path = temp_dir.path().join("a.age.pub");
        fs::write(&a_pub_path, "pre-existing-a-public")?;
        let b_pub_path = temp_dir.path().join("b.age.pub");
        fs::write(&b_pub_path, "pre-existing-b-public")?;
        // Generate only c.age with --no-dependencies
        // This should succeed because all dependencies have .pub files
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "c".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate c should succeed when all deps have .pub files: {:?}",
            result.err()
        );
        // c.age should be created
        assert!(
            temp_dir.path().join("c.age").exists(),
            "c.age should be created"
        );
        // a.age and b.age should NOT be created
        assert!(
            !temp_dir.path().join("a.age").exists(),
            "a.age should NOT be created"
        );
        assert!(
            !temp_dir.path().join("b.age").exists(),
            "b.age should NOT be created"
        );
        Ok(())
    }
    // Test for multiple secrets dependency handling
    #[test]
    fn test_generate_multiple_secrets_shared_deps() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Create: shared -> derived1, shared -> derived2
        let rules_content = format!(
            r#"
    {{
      "{}/shared.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "shared-secret"; public = "shared-public"; }};
      }};
      "{}/derived1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "shared" ];
    generator = {{ publics }}: "derived1-" + publics."shared";
      }};
      "{}/derived2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "shared" ];
    generator = {{ publics }}: "derived2-" + publics."shared";
      }};
      "{}/unrelated.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "unrelated";
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
        // Generate derived1 and derived2 (should also generate shared, but not unrelated)
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "derived1".to_string(),
            "derived2".to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "Generate multiple secrets with shared dep should succeed: {:?}",
            result.err()
        );
        // shared, derived1, derived2 should be created
        assert!(
            temp_dir.path().join("shared.age").exists(),
            "shared.age should be created (dependency)"
        );
        assert!(
            temp_dir.path().join("derived1.age").exists(),
            "derived1.age should be created"
        );
        assert!(
            temp_dir.path().join("derived2.age").exists(),
            "derived2.age should be created"
        );
        // unrelated should NOT be created
        assert!(
            !temp_dir.path().join("unrelated.age").exists(),
            "unrelated.age should NOT be created"
        );
        Ok(())
    }
    // Test that no deps doesn't affect generate all
    #[test]
    fn test_generate_no_deps_with_no_secrets_arg() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;
        // Create rules with dependencies
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;
        // Generate all with --no-dependencies (should still generate all because no secrets specified)
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);
        assert!(
            result.is_ok(),
            "--no-dependencies with no secrets arg should generate all: {:?}",
            result.err()
        );
        // Both should be created because we're generating all
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
    // Tests for rekey pre-flight check behavior
    #[test]
    fn test_generate_all_vs_explicit_all_basic() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        // Test that generating all secrets implicitly produces the same result
        // as generating all secrets explicitly
        let temp_dir1 = tempdir()?;
        let temp_dir2 = tempdir()?;
        let rules_content1 = format!(
            r#"
    {{
      "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content1";
      }};
      "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content2";
      }};
    }}
    "#,
            temp_dir1.path().to_str().unwrap(),
            temp_dir1.path().to_str().unwrap()
        );
        let rules_content2 = format!(
            r#"
    {{
      "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content1";
      }};
      "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content2";
      }};
    }}
    "#,
            temp_dir2.path().to_str().unwrap(),
            temp_dir2.path().to_str().unwrap()
        );
        let mut temp_rules1 = NamedTempFile::new()?;
        writeln!(temp_rules1, "{}", rules_content1)?;
        temp_rules1.flush()?;
        let mut temp_rules2 = NamedTempFile::new()?;
        writeln!(temp_rules2, "{}", rules_content2)?;
        temp_rules2.flush()?;
        // Test 1: Generate without specifying secrets (implicit all)
        let args_implicit = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules1.path().to_str().unwrap().to_string(),
        ];
        let result_implicit = crate::run(args_implicit);
        assert!(
            result_implicit.is_ok(),
            "Generate all (implicit) should succeed: {:?}",
            result_implicit.err()
        );
        // Test 2: Generate with all secrets explicitly specified
        let args_explicit = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules2.path().to_str().unwrap().to_string(),
            "secret1".to_string(),
            "secret2".to_string(),
        ];
        let result_explicit = crate::run(args_explicit);
        assert!(
            result_explicit.is_ok(),
            "Generate all (explicit) should succeed: {:?}",
            result_explicit.err()
        );
        // Both should create the same files
        assert!(
            temp_dir1.path().join("secret1.age").exists(),
            "Implicit all should create secret1.age"
        );
        assert!(
            temp_dir1.path().join("secret2.age").exists(),
            "Implicit all should create secret2.age"
        );
        assert!(
            temp_dir2.path().join("secret1.age").exists(),
            "Explicit all should create secret1.age"
        );
        assert!(
            temp_dir2.path().join("secret2.age").exists(),
            "Explicit all should create secret2.age"
        );
        Ok(())
    }
    #[test]
    fn test_generate_all_vs_explicit_all_with_dependencies() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        // Test that dependency handling is the same for implicit vs explicit all
        let temp_dir1 = tempdir()?;
        let temp_dir2 = tempdir()?;
        let rules_content1 = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir1.path().to_str().unwrap(),
            temp_dir1.path().to_str().unwrap()
        );
        let rules_content2 = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir2.path().to_str().unwrap(),
            temp_dir2.path().to_str().unwrap()
        );
        let mut temp_rules1 = NamedTempFile::new()?;
        writeln!(temp_rules1, "{}", rules_content1)?;
        temp_rules1.flush()?;
        let mut temp_rules2 = NamedTempFile::new()?;
        writeln!(temp_rules2, "{}", rules_content2)?;
        temp_rules2.flush()?;
        // Test 1: Generate without specifying secrets (implicit all)
        let args_implicit = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules1.path().to_str().unwrap().to_string(),
        ];
        let result_implicit = crate::run(args_implicit);
        assert!(
            result_implicit.is_ok(),
            "Generate all (implicit) with deps should succeed: {:?}",
            result_implicit.err()
        );
        // Test 2: Generate with all secrets explicitly specified
        let args_explicit = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules2.path().to_str().unwrap().to_string(),
            "base".to_string(),
            "derived".to_string(),
        ];
        let result_explicit = crate::run(args_explicit);
        assert!(
            result_explicit.is_ok(),
            "Generate all (explicit) with deps should succeed: {:?}",
            result_explicit.err()
        );
        // Both should create the same files, including .pub files
        assert!(
            temp_dir1.path().join("base.age").exists(),
            "Implicit all should create base.age"
        );
        assert!(
            temp_dir1.path().join("base.age.pub").exists(),
            "Implicit all should create base.age.pub"
        );
        assert!(
            temp_dir1.path().join("derived.age").exists(),
            "Implicit all should create derived.age"
        );
        assert!(
            temp_dir2.path().join("base.age").exists(),
            "Explicit all should create base.age"
        );
        assert!(
            temp_dir2.path().join("base.age.pub").exists(),
            "Explicit all should create base.age.pub"
        );
        assert!(
            temp_dir2.path().join("derived.age").exists(),
            "Explicit all should create derived.age"
        );
        Ok(())
    }
    #[test]
    fn test_generate_all_only_nonexistent_secret() {
        use std::io::Write;
        use tempfile::NamedTempFile;
        // Test that specifying only nonexistent secrets results in an error
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
    {{
      "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "content1";
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();
        // Test: Generate with only nonexistent secrets
        let args_only_nonexistent = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "nonexistent".to_string(),
        ];
        let result = crate::run(args_only_nonexistent);
        assert!(
            result.is_err(),
            "Generate with only nonexistent secret should fail"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("No matching secrets"),
            "Error should mention no matching secrets: {}",
            err_msg
        );
    }
    #[test]
    fn test_generate_no_dependencies_flag_implicit_vs_explicit_all() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        // Test that --no-dependencies flag behaves the same for implicit vs explicit all
        // When all secrets are specified, --no-dependencies should be a no-op
        // because all secrets (including dependencies) are already in the list
        let temp_dir1 = tempdir()?;
        let temp_dir2 = tempdir()?;
        let rules_content1 = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir1.path().to_str().unwrap(),
            temp_dir1.path().to_str().unwrap()
        );
        let rules_content2 = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "derived-" + publics."base";
      }};
    }}
    "#,
            temp_dir2.path().to_str().unwrap(),
            temp_dir2.path().to_str().unwrap()
        );
        let mut temp_rules1 = NamedTempFile::new()?;
        writeln!(temp_rules1, "{}", rules_content1)?;
        temp_rules1.flush()?;
        let mut temp_rules2 = NamedTempFile::new()?;
        writeln!(temp_rules2, "{}", rules_content2)?;
        temp_rules2.flush()?;
        // Test 1: Generate with --no-dependencies without specifying secrets (implicit all)
        let args_implicit = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules1.path().to_str().unwrap().to_string(),
        ];
        let result_implicit = crate::run(args_implicit);
        assert!(
            result_implicit.is_ok(),
            "Generate --no-dependencies (implicit all) should succeed: {:?}",
            result_implicit.err()
        );
        // Test 2: Generate with --no-dependencies with all secrets explicitly specified
        let args_explicit = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--no-dependencies".to_string(),
            "--secrets-nix".to_string(),
            temp_rules2.path().to_str().unwrap().to_string(),
            "base".to_string(),
            "derived".to_string(),
        ];
        let result_explicit = crate::run(args_explicit);
        assert!(
            result_explicit.is_ok(),
            "Generate --no-dependencies (explicit all) should succeed: {:?}",
            result_explicit.err()
        );
        // Both should create the same files
        assert!(
            temp_dir1.path().join("base.age").exists(),
            "Implicit all should create base.age"
        );
        assert!(
            temp_dir1.path().join("derived.age").exists(),
            "Implicit all should create derived.age"
        );
        assert!(
            temp_dir2.path().join("base.age").exists(),
            "Explicit all should create base.age"
        );
        assert!(
            temp_dir2.path().join("derived.age").exists(),
            "Explicit all should create derived.age"
        );
        Ok(())
    }

    // ============================================================================
    // Tests for generator output variations ({secret}, {public}, or both)
    // ============================================================================

    #[test]
    fn test_generate_public_only_creates_pub_file_no_age() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Generator that only produces public output (no secret)
        let rules_content = format!(
            r#"
    {{
      "{}/public-only.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ public = "my-public-metadata"; }};
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate public-only should succeed: {:?}",
            result.err()
        );

        // .pub file should be created
        let pub_path = temp_dir.path().join("public-only.age.pub");
        assert!(pub_path.exists(), "public-only.age.pub should be created");

        // .age file should NOT be created (no secret to encrypt)
        let age_path = temp_dir.path().join("public-only.age");
        assert!(
            !age_path.exists(),
            "public-only.age should NOT be created for public-only generator"
        );

        // Verify .pub content
        let pub_content = fs::read_to_string(&pub_path)?;
        assert_eq!(pub_content.trim(), "my-public-metadata");

        Ok(())
    }

    #[test]
    fn test_generate_public_only_with_dependency() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Public-only generator, and another secret that depends on its public output
        let rules_content = format!(
            r#"
    {{
      "{}/metadata.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ public = "config-version-1.0"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "metadata" ];
    generator = {{ publics }}: "derived-from-" + publics."metadata";
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate with public-only dependency should succeed: {:?}",
            result.err()
        );

        // metadata.age.pub should exist, metadata.age should NOT exist
        assert!(
            temp_dir.path().join("metadata.age.pub").exists(),
            "metadata.age.pub should be created"
        );
        assert!(
            !temp_dir.path().join("metadata.age").exists(),
            "metadata.age should NOT be created"
        );

        // derived.age should exist (it has a secret)
        assert!(
            temp_dir.path().join("derived.age").exists(),
            "derived.age should be created"
        );

        Ok(())
    }

    #[test]
    fn test_generate_secret_only_no_pub_file() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Generator that only produces secret output (no public)
        let rules_content = format!(
            r#"
    {{
      "{}/secret-only.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "my-secret-value"; }};
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate secret-only should succeed: {:?}",
            result.err()
        );

        // .age file should be created
        let age_path = temp_dir.path().join("secret-only.age");
        assert!(age_path.exists(), "secret-only.age should be created");

        // .pub file should NOT be created (no public output)
        let pub_path = temp_dir.path().join("secret-only.age.pub");
        assert!(
            !pub_path.exists(),
            "secret-only.age.pub should NOT be created"
        );

        Ok(())
    }

    #[test]
    fn test_generate_both_secret_and_public() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Generator that produces both secret and public
        let rules_content = format!(
            r#"
    {{
      "{}/both.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "my-secret"; public = "my-public"; }};
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate both secret and public should succeed: {:?}",
            result.err()
        );

        // Both files should be created
        assert!(
            temp_dir.path().join("both.age").exists(),
            "both.age should be created"
        );
        assert!(
            temp_dir.path().join("both.age.pub").exists(),
            "both.age.pub should be created"
        );

        // Verify .pub content
        let pub_content = fs::read_to_string(temp_dir.path().join("both.age.pub"))?;
        assert_eq!(pub_content.trim(), "my-public");

        Ok(())
    }

    #[test]
    fn test_generate_string_return_creates_secret_no_public() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Generator that returns a plain string (shorthand for {secret = ...})
        let rules_content = format!(
            r#"
    {{
      "{}/string-gen.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "plain-string-secret";
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate string return should succeed: {:?}",
            result.err()
        );

        // .age file should be created
        assert!(
            temp_dir.path().join("string-gen.age").exists(),
            "string-gen.age should be created"
        );

        // .pub file should NOT be created
        assert!(
            !temp_dir.path().join("string-gen.age.pub").exists(),
            "string-gen.age.pub should NOT be created for string generator"
        );

        Ok(())
    }

    #[test]
    fn test_generate_empty_attrset_fails() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Generator that returns empty attrset (neither secret nor public)
        let rules_content = format!(
            r#"
    {{
      "{}/empty-attrset.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ }};
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(result.is_err(), "Generate empty attrset should fail");
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("at least 'secret' or 'public'"),
            "Error should mention at least secret or public: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_generate_unknown_key_only_fails() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Generator that returns attrset with only unknown keys
        let rules_content = format!(
            r#"
    {{
      "{}/unknown-key.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ unknown = "value"; }};
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(result.is_err(), "Generate unknown key only should fail");
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("at least 'secret' or 'public'"),
            "Error should mention at least secret or public: {}",
            err_msg
        );

        Ok(())
    }

    // ============================================================================
    // Tests for dependency edge cases with public-only generators
    // ============================================================================

    #[test]
    fn test_generate_dependency_needs_secret_but_only_public_available() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // base generates only public, derived needs secrets.base
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ public = "base-public-only"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ secrets }}: "needs-" + secrets."base";
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        // This should fail because derived needs secrets.base but base only produces public
        assert!(
            result.is_err(),
            "Generate should fail when dependency only has public but secret is needed"
        );

        // Error message should be helpful
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("base") || err_msg.contains("secret"),
            "Error should mention base or secret dependency: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_generate_dependency_needs_public_but_only_secret_available() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // base generates only secret, derived needs publics.base
        let rules_content = format!(
            r#"
    {{
      "{}/base.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ secret = "base-secret-only"; }};
      }};
      "{}/derived.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "base" ];
    generator = {{ publics }}: "needs-" + publics."base";
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        // This should fail because derived needs publics.base but base only produces secret
        assert!(
            result.is_err(),
            "Generate should fail when dependency only has secret but public is needed"
        );

        // Error message should be helpful
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("base") || err_msg.contains("public"),
            "Error should mention base or public dependency: {}",
            err_msg
        );

        Ok(())
    }

    #[test]
    fn test_generate_multiple_public_only_chain() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Chain of public-only generators, ending with one that has both
        let rules_content = format!(
            r#"
    {{
      "{}/meta1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ public = "meta1-value"; }};
      }};
      "{}/meta2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "meta1" ];
    generator = {{ publics }}: {{ public = "meta2-from-" + publics."meta1"; }};
      }};
      "{}/final.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    dependencies = [ "meta2" ];
    generator = {{ publics }}: {{ secret = "secret-from-" + publics."meta2"; public = "public-" + publics."meta2"; }};
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
            "generate".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate chain with public-only generators should succeed: {:?}",
            result.err()
        );

        // meta1 and meta2 should only have .pub files
        assert!(
            temp_dir.path().join("meta1.age.pub").exists(),
            "meta1.age.pub should be created"
        );
        assert!(
            !temp_dir.path().join("meta1.age").exists(),
            "meta1.age should NOT be created"
        );
        assert!(
            temp_dir.path().join("meta2.age.pub").exists(),
            "meta2.age.pub should be created"
        );
        assert!(
            !temp_dir.path().join("meta2.age").exists(),
            "meta2.age should NOT be created"
        );

        // final should have both .age and .pub
        assert!(
            temp_dir.path().join("final.age").exists(),
            "final.age should be created"
        );
        assert!(
            temp_dir.path().join("final.age.pub").exists(),
            "final.age.pub should be created"
        );

        Ok(())
    }

    #[test]
    fn test_generate_force_regenerates_public_only() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Create a public-only generator
        let rules_content = format!(
            r#"
    {{
      "{}/force-public.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ public = "new-public-value"; }};
      }};
    }}
    "#,
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new()?;
        writeln!(temp_rules, "{}", rules_content)?;
        temp_rules.flush()?;

        // Pre-create .pub file with old content
        let pub_path = temp_dir.path().join("force-public.age.pub");
        fs::write(&pub_path, "old-public-value")?;

        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--force".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate --force public-only should succeed: {:?}",
            result.err()
        );

        // .pub file should have new content
        let pub_content = fs::read_to_string(&pub_path)?;
        assert_eq!(pub_content.trim(), "new-public-value");

        Ok(())
    }

    #[test]
    fn test_generate_dry_run_public_only_no_changes() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let temp_dir = tempdir()?;

        // Create a public-only generator
        let rules_content = format!(
            r#"
    {{
      "{}/dry-public.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: {{ public = "dry-public-value"; }};
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
            "generate".to_string(),
            "--dry-run".to_string(),
            "--secrets-nix".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];
        let result = crate::run(args);

        assert!(
            result.is_ok(),
            "Generate --dry-run public-only should succeed: {:?}",
            result.err()
        );

        // No files should be created
        assert!(
            !temp_dir.path().join("dry-public.age.pub").exists(),
            "dry-public.age.pub should NOT be created in dry-run"
        );
        assert!(
            !temp_dir.path().join("dry-public.age").exists(),
            "dry-public.age should NOT be created in dry-run"
        );

        Ok(())
    }
}
