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
use crate::nix::{
    generate_secret_with_public, generate_secret_with_public_and_context, get_all_files,
    get_public_keys, get_secret_dependencies, should_armor,
};

use super::context::SecretContext;
use super::dependency_resolver::DependencyResolver;
use super::rekey::filter_files;
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
}

/// Validate that requested secrets exist in the rules file.
fn validate_secrets_exist(filtered_files: &[String], secrets: &[String]) -> Result<()> {
    if filtered_files.is_empty() && !secrets.is_empty() {
        return Err(anyhow!(
            "No matching secrets found in rules file for: {}",
            secrets.join(", ")
        ));
    }
    Ok(())
}

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
            let dep_path = Path::new(dep);
            let dep_name = SecretName::new(dep);
            let base_name = dep_name.normalized();

            let pub_paths = vec![
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
            eprintln!("Skipping {file}: already exists (use --force to overwrite)");
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

    // Build the context for the generator
    let context = resolver.build_dependency_context(&deps)?;

    // Generate with dependencies context
    let output = if !deps.is_empty() {
        generate_secret_with_public_and_context(ctx.rules_path(), file, &context)?
    } else {
        generate_secret_with_public(ctx.rules_path(), file)?
    };

    let Some(output) = output else {
        resolver.mark_processed(file);
        return Ok(ProcessResult::NoGenerator);
    };

    // In dry-run mode, just report what would be done
    if dry_run {
        if Path::new(file).exists() {
            eprintln!("Would overwrite {file}");
        } else {
            eprintln!("Would generate {file}");
        }
        if output.public.is_some() {
            let pub_file = format!("{}.pub", file);
            eprintln!("Would generate public file {pub_file}");
        }
        // Store the output for dependency resolution even in dry-run mode
        resolver.store_generated(file, output);
        resolver.mark_processed(file);
        return Ok(ProcessResult::Generated);
    }

    eprintln!("Generating {file}...");

    let public_keys = get_public_keys(ctx.rules_path(), file)?;
    let armor = should_armor(ctx.rules_path(), file)?;

    if public_keys.is_empty() {
        eprintln!("Warning: No public keys found for {file}, skipping");
        resolver.mark_processed(file);
        return Ok(ProcessResult::NoPublicKeys);
    }

    // Create temporary file with the generated secret content
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let temp_file = temp_dir.path().join("generated_secret");
    fs::write(&temp_file, &output.secret)
        .context("Failed to write generated content to temporary file")?;

    // Encrypt the generated secret content
    encrypt_from_file(&temp_file.to_string_lossy(), file, &public_keys, armor)
        .with_context(|| format!("Failed to encrypt generated secret {file}"))?;

    eprintln!("Generated and encrypted {file}");

    // Store the generated output for dependencies
    resolver.store_generated(file, output.clone());

    // If there's public content, write it to a .pub file
    if let Some(public_content) = &output.public {
        let pub_file = format!("{}.pub", file);
        fs::write(&pub_file, public_content)
            .with_context(|| format!("Failed to write public file {pub_file}"))?;
        eprintln!("Generated public file {pub_file}");
    }

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
                ProcessResult::Generated => progress_made = true,
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
    use super::*;

    #[test]
    fn test_generate_secrets_with_nonexistent_rules() {
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--rules".to_string(),
            "./nonexistent_rules.nix".to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err());
    }
}
