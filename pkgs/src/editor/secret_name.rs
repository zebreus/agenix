//! Secret name normalization and handling.
//!
//! This module provides a `SecretName` newtype that encapsulates the various
//! forms a secret name can take (full path, basename, with/without .age suffix)
//! and provides consistent normalization.

use std::path::Path;

/// A normalized secret name that provides consistent comparison and formatting.
///
/// Secret names can appear in various forms:
/// - Full path: `/path/to/secret.age`
/// - Relative path: `secrets/secret.age`
/// - Basename: `secret.age`
/// - Without suffix: `secret`
///
/// `SecretName` normalizes these to enable consistent matching and comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretName {
    /// The original name as provided
    original: String,
    /// The basename without path (e.g., "secret.age")
    basename: String,
    /// The normalized name without .age suffix (e.g., "secret")
    normalized: String,
}

impl SecretName {
    /// Create a new SecretName from any string representation.
    pub fn new(name: &str) -> Self {
        let basename = Path::new(name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(name)
            .to_string();

        let normalized = basename
            .strip_suffix(".age")
            .unwrap_or(&basename)
            .to_string();

        Self {
            original: name.to_string(),
            basename,
            normalized,
        }
    }

    /// Get the original name as provided.
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Get the basename (filename without path).
    pub fn basename(&self) -> &str {
        &self.basename
    }

    /// Get the normalized name (basename without .age suffix).
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// Get the name with .age suffix guaranteed.
    pub fn with_age_suffix(&self) -> String {
        if self.basename.ends_with(".age") {
            self.basename.clone()
        } else {
            format!("{}.age", self.basename)
        }
    }

    /// Check if this secret name matches another (using normalized comparison).
    pub fn matches(&self, other: &SecretName) -> bool {
        self.normalized == other.normalized
    }

    /// Check if this secret name matches a string (using normalized comparison).
    pub fn matches_str(&self, other: &str) -> bool {
        let other_name = SecretName::new(other);
        self.matches(&other_name)
    }

    /// Strip .age suffix from a string if present.
    ///
    /// This is a convenience method for stripping .age suffix without creating
    /// a full SecretName instance.
    #[inline]
    pub fn strip_age_suffix(name: &str) -> &str {
        name.strip_suffix(".age").unwrap_or(name)
    }
}

impl std::fmt::Display for SecretName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.original)
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
        &self.original
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_name_full_path() {
        let name = SecretName::new("/path/to/secret.age");
        assert_eq!(name.original(), "/path/to/secret.age");
        assert_eq!(name.basename(), "secret.age");
        assert_eq!(name.normalized(), "secret");
    }

    #[test]
    fn test_secret_name_basename_only() {
        let name = SecretName::new("secret.age");
        assert_eq!(name.original(), "secret.age");
        assert_eq!(name.basename(), "secret.age");
        assert_eq!(name.normalized(), "secret");
    }

    #[test]
    fn test_secret_name_without_suffix() {
        let name = SecretName::new("secret");
        assert_eq!(name.original(), "secret");
        assert_eq!(name.basename(), "secret");
        assert_eq!(name.normalized(), "secret");
    }

    #[test]
    fn test_secret_name_matches() {
        let name1 = SecretName::new("/path/to/secret.age");
        let name2 = SecretName::new("secret.age");
        let name3 = SecretName::new("secret");

        assert!(name1.matches(&name2));
        assert!(name1.matches(&name3));
        assert!(name2.matches(&name3));
    }

    #[test]
    fn test_secret_name_with_age_suffix() {
        let name1 = SecretName::new("secret");
        let name2 = SecretName::new("secret.age");

        assert_eq!(name1.with_age_suffix(), "secret.age");
        assert_eq!(name2.with_age_suffix(), "secret.age");
    }

    #[test]
    fn test_secret_name_matches_str() {
        let name = SecretName::new("/path/to/secret.age");

        assert!(name.matches_str("secret"));
        assert!(name.matches_str("secret.age"));
        assert!(name.matches_str("/other/path/secret.age"));
        assert!(!name.matches_str("other-secret"));
    }
}
