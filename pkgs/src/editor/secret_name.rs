//! Secret name normalization and handling.
//!
//! This module provides a `SecretName` newtype that handles secret names
//! which are used in secrets.nix (without .age suffix) and provides
//! methods to construct file paths.

/// A secret name from secrets.nix that can be used to construct file paths.
///
/// Secret names appear in secrets.nix without .age suffix:
/// - In secrets.nix: `cool_key_ed25519`
/// - Secret file path: `cool_key_ed25519.age`
/// - Public file path: `cool_key_ed25519.pub`
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
    pub fn new(name: &str) -> Self {
        // Strip .age suffix if present to get the actual secret name
        let secret_name = name.strip_suffix(".age").unwrap_or(name).to_string();

        Self { name: secret_name }
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
    /// This supports matching by basename, so "/path/to/secret1" matches "secret1".
    pub fn matches(&self, other: &SecretName) -> bool {
        if self.name == other.name {
            return true;
        }

        // Try matching by basename (handles paths like "/path/to/secret1")
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
}
