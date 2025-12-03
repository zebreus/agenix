//! Secret name normalization and handling.
//!
//! This module provides a `SecretName` newtype that handles secret names
//! which are used in secrets.nix (without .age suffix) and provides
//! methods to construct file paths.
//!
//! **Important**: Secret names MUST be simple names, not paths. All secret files
//! are located in the same directory as secrets.nix.

use anyhow::{Result, bail};

/// A secret name from secrets.nix that can be used to construct file paths.
///
/// Secret names appear in secrets.nix without .age suffix:
/// - In secrets.nix: `cool_key_ed25519`
/// - Secret file path: `cool_key_ed25519.age` (in same directory as secrets.nix)
/// - Public file path: `cool_key_ed25519.pub` (in same directory as secrets.nix)
///
/// **Important**: Secret names MUST be simple names without path separators.
/// Paths like `./secret`, `/path/to/secret`, or `../secret` are NOT allowed.
/// All secret files are always located next to the secrets.nix file.
///
/// `SecretName` provides methods to work with both the name and derived paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretName {
    /// The secret name as it appears in secrets.nix (without .age)
    name: String,
}

impl SecretName {
    /// Create a new SecretName from a string.
    ///
    /// If the input has .age suffix, it will be stripped to get the secret name.
    /// This allows the CLI to accept both forms for backwards compatibility.
    ///
    /// **Note**: This method does NOT validate that the name is not a path.
    /// Use `validate_and_create()` for validation at entry points.
    pub fn new(name: &str) -> Self {
        // Strip .age suffix if present to get the actual secret name
        let secret_name = name.strip_suffix(".age").unwrap_or(name).to_string();

        Self { name: secret_name }
    }

    /// Validate a secret name and create a SecretName if valid.
    ///
    /// The name must be a simple name without path separators (`/` or `\`).
    /// If the input has .age suffix, it will be stripped to get the secret name.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The name contains path separators (`/` or `\`)
    /// - The name is empty
    /// - The name starts with `.`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use agenix::editor::secret_name::SecretName;
    ///
    /// // Valid names
    /// assert!(SecretName::validate_and_create("my_secret").is_ok());
    /// assert!(SecretName::validate_and_create("my_secret.age").is_ok());
    ///
    /// // Invalid names (paths)
    /// assert!(SecretName::validate_and_create("./my_secret").is_err());
    /// assert!(SecretName::validate_and_create("/path/to/secret").is_err());
    /// assert!(SecretName::validate_and_create("../secret").is_err());
    /// ```
    pub fn validate_and_create(name: &str) -> Result<Self> {
        // Strip .age suffix if present to get the actual secret name
        let secret_name = name.strip_suffix(".age").unwrap_or(name);

        // Validate that the name is not empty
        if secret_name.is_empty() {
            bail!("Secret name cannot be empty");
        }

        // Validate that the name is not a path
        if secret_name.contains('/') || secret_name.contains('\\') {
            bail!(
                "Secret name '{}' contains path separators. \
                Secret names must be simple names, not paths. \
                All secret files are located in the same directory as secrets.nix.",
                name
            );
        }

        // Validate that the name doesn't start with '.'
        if secret_name.starts_with('.') {
            bail!(
                "Secret name '{}' starts with '.'. \
                Secret names must not start with a dot. \
                All secret files are located in the same directory as secrets.nix.",
                name
            );
        }

        Ok(Self {
            name: secret_name.to_string(),
        })
    }

    /// Get the secret name (without .age suffix).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the secret file path (with .age suffix).
    pub fn secret_file(&self) -> String {
        format!("{}.age", self.name)
    }

    /// Get the public file path (with .pub suffix).
    pub fn public_file(&self) -> String {
        format!("{}.pub", self.name)
    }

    /// Check if this secret name matches another.
    ///
    /// This performs simple equality check on the names. However, for backwards
    /// compatibility with tests and internal filtering logic, it also supports
    /// matching by basename when one side might be a path (from Nix evaluation).
    ///
    /// Note: User input is validated to NOT be paths via `validate_and_create()`,
    /// but Nix evaluation may still return paths in some contexts.
    pub fn matches(&self, other: &SecretName) -> bool {
        if self.name == other.name {
            return true;
        }

        // Support matching by basename for internal filtering
        // (Nix evaluation may return paths in some contexts)
        if let Some(basename) = self.name.rsplit('/').next() {
            if basename == other.name {
                return true;
            }
        }

        if let Some(basename) = other.name.rsplit('/').next() {
            if self.name == basename {
                return true;
            }
        }

        false
    }
}

impl std::fmt::Display for SecretName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&str> for SecretName {
    fn from(s: &str) -> Self {
        SecretName::new(s)
    }
}

impl From<String> for SecretName {
    fn from(s: String) -> Self {
        SecretName::new(&s)
    }
}

impl AsRef<str> for SecretName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // BASIC FUNCTIONALITY TESTS
    // ========================================

    #[test]
    fn test_secret_name_without_suffix() {
        let name = SecretName::new("cool_key_ed25519");
        assert_eq!(name.name(), "cool_key_ed25519");
        assert_eq!(name.secret_file(), "cool_key_ed25519.age");
        assert_eq!(name.public_file(), "cool_key_ed25519.pub");
    }

    #[test]
    fn test_secret_name_with_age_suffix() {
        // For backwards compatibility, strip .age if provided
        let name = SecretName::new("cool_key_ed25519.age");
        assert_eq!(name.name(), "cool_key_ed25519");
        assert_eq!(name.secret_file(), "cool_key_ed25519.age");
        assert_eq!(name.public_file(), "cool_key_ed25519.pub");
    }

    #[test]
    fn test_secret_name_matches() {
        let name1 = SecretName::new("cool_key_ed25519");
        let name2 = SecretName::new("cool_key_ed25519.age");
        let name3 = SecretName::new("other_key");

        assert!(name1.matches(&name2));
        assert!(name2.matches(&name1));
        assert!(!name1.matches(&name3));
    }

    #[test]
    fn test_secret_name_display() {
        let name = SecretName::new("my_secret");
        assert_eq!(name.to_string(), "my_secret");
    }

    // ========================================
    // VALIDATION TESTS - VALID NAMES
    // ========================================

    #[test]
    fn test_validate_simple_name() {
        let name = SecretName::validate_and_create("my_secret").unwrap();
        assert_eq!(name.name(), "my_secret");
    }

    #[test]
    fn test_validate_name_with_age_suffix() {
        let name = SecretName::validate_and_create("my_secret.age").unwrap();
        assert_eq!(name.name(), "my_secret");
    }

    #[test]
    fn test_validate_name_with_underscores() {
        let name = SecretName::validate_and_create("my_secret_key").unwrap();
        assert_eq!(name.name(), "my_secret_key");
    }

    #[test]
    fn test_validate_name_with_hyphens() {
        let name = SecretName::validate_and_create("my-secret-key").unwrap();
        assert_eq!(name.name(), "my-secret-key");
    }

    #[test]
    fn test_validate_name_with_numbers() {
        let name = SecretName::validate_and_create("secret123").unwrap();
        assert_eq!(name.name(), "secret123");
    }

    #[test]
    fn test_validate_name_with_dots_in_middle() {
        // Dots in the middle are OK (e.g., "my.secret")
        let name = SecretName::validate_and_create("my.secret").unwrap();
        assert_eq!(name.name(), "my.secret");
    }

    // ========================================
    // VALIDATION TESTS - INVALID PATHS
    // (should fail - this is the main requirement)
    // ========================================

    #[test]
    fn test_validate_rejects_relative_path_dot_slash() {
        let result = SecretName::validate_and_create("./cool_key_ed25519");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path separators"));
        assert!(err.contains("simple names"));
    }

    #[test]
    fn test_validate_rejects_relative_path_dot_slash_with_age() {
        let result = SecretName::validate_and_create("./cool_key_ed25519.age");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path separators"));
    }

    #[test]
    fn test_validate_rejects_absolute_path() {
        let result = SecretName::validate_and_create("/path/to/secret");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path separators"));
    }

    #[test]
    fn test_validate_rejects_absolute_path_with_age() {
        let result = SecretName::validate_and_create("/path/to/secret.age");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_parent_directory_path() {
        let result = SecretName::validate_and_create("../secret");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path separators"));
    }

    #[test]
    fn test_validate_rejects_nested_path() {
        let result = SecretName::validate_and_create("secrets/mykey");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_deep_nested_path() {
        let result = SecretName::validate_and_create("a/b/c/secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_windows_path() {
        let result = SecretName::validate_and_create("C:\\secrets\\mykey");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path separators"));
    }

    #[test]
    fn test_validate_rejects_windows_relative_path() {
        let result = SecretName::validate_and_create(".\\secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_mixed_slashes() {
        let result = SecretName::validate_and_create("path\\to/secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_trailing_slash() {
        let result = SecretName::validate_and_create("secret/");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_leading_slash() {
        let result = SecretName::validate_and_create("/secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_path_in_middle() {
        let result = SecretName::validate_and_create("my/secret/key");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_home_directory_tilde_slash() {
        let result = SecretName::validate_and_create("~/secrets/mykey");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_current_directory_dot_slash_multiple() {
        let result = SecretName::validate_and_create("./path/./secret");
        assert!(result.is_err());
    }

    // ========================================
    // DOT PREFIX VALIDATION
    // ========================================

    #[test]
    fn test_validate_rejects_dot_prefix() {
        let result = SecretName::validate_and_create(".secret");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("starts with '.'"));
    }

    #[test]
    fn test_validate_rejects_double_dot_prefix() {
        let result = SecretName::validate_and_create("..secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_dot_prefix_with_age() {
        let result = SecretName::validate_and_create(".secret.age");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("starts with '.'"));
    }

    #[test]
    fn test_validate_rejects_just_dot() {
        let result = SecretName::validate_and_create(".");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_just_double_dot() {
        let result = SecretName::validate_and_create("..");
        assert!(result.is_err());
    }

    // ========================================
    // EMPTY NAME VALIDATION
    // ========================================

    #[test]
    fn test_validate_rejects_empty_string() {
        let result = SecretName::validate_and_create("");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn test_validate_rejects_only_age_suffix() {
        let result = SecretName::validate_and_create(".age");
        assert!(result.is_err());
        // This should fail because after stripping .age, it's empty
    }

    // ========================================
    // EDGE CASES
    // ========================================

    #[test]
    fn test_validate_with_multiple_dots() {
        // Multiple dots in the name are OK
        let name = SecretName::validate_and_create("my.secret.key").unwrap();
        assert_eq!(name.name(), "my.secret.key");
    }

    #[test]
    fn test_validate_ending_with_age_in_name() {
        // If "age" is part of the name but not the suffix, it's OK
        let name = SecretName::validate_and_create("storage").unwrap();
        assert_eq!(name.name(), "storage");
    }

    #[test]
    fn test_validate_with_unicode() {
        // Unicode characters are allowed in names
        let name = SecretName::validate_and_create("secret_café").unwrap();
        assert_eq!(name.name(), "secret_café");
    }

    #[test]
    fn test_validate_with_spaces() {
        // Spaces are technically allowed (though not recommended)
        let name = SecretName::validate_and_create("my secret").unwrap();
        assert_eq!(name.name(), "my secret");
    }
}
