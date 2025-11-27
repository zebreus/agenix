//! File editing and secret management operations.
//!
//! This module provides functions for editing, decrypting, rekeying, and generating
//! encrypted secret files with temporary file handling and editor integration.
//!
//! # Module Structure
//!
//! - [`context`] - Secret context for bundling common parameters
//! - [`secret_name`] - Secret name normalization and handling
//! - [`dependency_resolver`] - Dependency resolution for secret generation
//! - [`edit`] - File editing and decryption operations
//! - [`rekey`] - Rekey operations for encrypted secrets
//! - [`generate`] - Secret generation operations
//! - [`list`] - List and status operations

pub mod context;
pub mod dependency_resolver;
pub mod edit;
pub mod generate;
pub mod list;
pub mod rekey;
pub mod secret_name;

use anyhow::{Result, anyhow};
use secret_name::SecretName;

/// Validate that requested secrets exist in the rules file.
///
/// Returns an error if secrets are specified but none match.
pub(crate) fn validate_secrets_exist(filtered_files: &[String], secrets: &[String]) -> Result<()> {
    if filtered_files.is_empty() && !secrets.is_empty() {
        return Err(anyhow!(
            "No matching secrets found in rules file for: {}",
            secrets.join(", ")
        ));
    }
    Ok(())
}

/// Filter files based on specified secrets.
///
/// If secrets is empty, return all files. Otherwise, return files that match
/// any of the specified secrets.
pub(crate) fn filter_files(files: &[String], secrets: &[String]) -> Vec<String> {
    if secrets.is_empty() {
        return files.to_vec();
    }

    files
        .iter()
        .filter(|file| {
            let file_name = SecretName::new(file);
            secrets.iter().any(|s| {
                let secret_name = SecretName::new(s);
                file_name.matches(&secret_name) || s == *file
            })
        })
        .cloned()
        .collect()
}

// Re-export main public functions for backwards compatibility
pub use edit::{decrypt_file, edit_file, encrypt_file};
pub use generate::generate_secrets;
pub use list::{check_secrets, list_secrets};
pub use rekey::rekey_files;
