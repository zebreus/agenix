//! Context for secret operations.
//!
//! This module provides a `SecretContext` struct that bundles together
//! the common parameters needed for secret operations, reducing parameter
//! passing complexity.

use std::path::{Path, PathBuf};

/// Context containing common parameters for secret operations.
///
/// This struct bundles together the rules file path, the directory containing
/// the rules file, and the list of all secrets defined in the rules file.
#[derive(Debug, Clone)]
pub struct SecretContext {
    /// Path to the rules file (e.g., "secrets.nix")
    pub rules_path: String,
    /// Directory containing the rules file
    pub rules_dir: PathBuf,
    /// All secret files defined in the rules
    pub all_files: Vec<String>,
}

impl SecretContext {
    /// Create a new SecretContext from a rules file path.
    ///
    /// # Arguments
    /// * `rules_path` - Path to the Nix rules file
    /// * `all_files` - List of all secret files from the rules
    pub fn new(rules_path: &str, all_files: Vec<String>) -> Self {
        let path = Path::new(rules_path);
        let rules_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        Self {
            rules_path: rules_path.to_string(),
            rules_dir,
            all_files,
        }
    }

    /// Get the rules path as a string slice.
    pub fn rules_path(&self) -> &str {
        &self.rules_path
    }

    /// Get the rules directory as a Path.
    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }

    /// Get the list of all files.
    pub fn all_files(&self) -> &[String] {
        &self.all_files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_context_new() {
        let ctx = SecretContext::new(
            "/path/to/secrets.nix",
            vec!["secret1.age".to_string(), "secret2.age".to_string()],
        );

        assert_eq!(ctx.rules_path(), "/path/to/secrets.nix");
        assert_eq!(ctx.rules_dir(), Path::new("/path/to"));
        assert_eq!(ctx.all_files().len(), 2);
    }

    #[test]
    fn test_secret_context_relative_path() {
        let ctx = SecretContext::new("secrets.nix", vec![]);

        assert_eq!(ctx.rules_path(), "secrets.nix");
        assert_eq!(ctx.rules_dir(), Path::new("."));
    }
}
