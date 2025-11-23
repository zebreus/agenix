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
