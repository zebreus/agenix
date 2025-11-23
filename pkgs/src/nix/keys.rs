use anyhow::{Context, Result};
use std::path::Path;

/// Resolve a potential secret reference to a public key
/// If the key_str looks like a public key (starts with ssh-, age1, etc.), return it as-is
/// If it looks like a secret name, try to read the corresponding .pub file
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn resolve_public_key(rules_dir: &Path, key_str: &str) -> Result<String> {
    // Check if this looks like an actual public key
    if key_str.starts_with("ssh-") || key_str.starts_with("age1") || key_str.starts_with("sk-") {
        return Ok(key_str.to_string());
    }

    // Try to resolve as a secret reference
    // Remove .age suffix if present to get the base secret name
    let secret_name = if key_str.ends_with(".age") {
        &key_str[..key_str.len() - 4]
    } else {
        key_str
    };

    // Try both with and without .age suffix for the pub file
    let pub_file_paths = [
        rules_dir.join(format!("{}.age.pub", secret_name)),
        rules_dir.join(format!("{}.pub", secret_name)),
    ];

    for pub_file_path in &pub_file_paths {
        if pub_file_path.exists() {
            let public_key = std::fs::read_to_string(pub_file_path)
                .with_context(|| {
                    format!(
                        "Failed to read public key file: {}",
                        pub_file_path.display()
                    )
                })?
                .trim()
                .to_string();
            return Ok(public_key);
        }
    }

    // If no .pub file found, return the original string (might be a public key we don't recognize)
    Ok(key_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_resolve_public_key_actual_ssh_key() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8";
        let result = resolve_public_key(rules_dir, ssh_key)?;

        // Should return the key unchanged
        assert_eq!(result, ssh_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_actual_age_key() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        let age_key = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let result = resolve_public_key(rules_dir, age_key)?;

        // Should return the key unchanged
        assert_eq!(result, age_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_secret_reference_with_age_suffix() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        // Create a .pub file for the secret
        let pub_file = rules_dir.join("my-ssh-key.age.pub");
        let public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8";
        std::fs::write(&pub_file, format!("{}\n", public_key))?;

        // Reference with .age suffix
        let result = resolve_public_key(rules_dir, "my-ssh-key.age")?;

        // Should resolve to the public key
        assert_eq!(result, public_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_secret_reference_without_age_suffix() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        // Create a .pub file for the secret
        let pub_file = rules_dir.join("my-ssh-key.age.pub");
        let public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8";
        std::fs::write(&pub_file, format!("{}\n", public_key))?;

        // Reference without .age suffix
        let result = resolve_public_key(rules_dir, "my-ssh-key")?;

        // Should resolve to the public key
        assert_eq!(result, public_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_nonexistent_reference() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        // Reference to a non-existent secret
        let result = resolve_public_key(rules_dir, "nonexistent-key")?;

        // Should return the original string
        assert_eq!(result, "nonexistent-key");
        Ok(())
    }
}
