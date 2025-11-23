use age::{Identity, IdentityFile};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Load identities from a file (supports both age and SSH formats)
pub(crate) fn load_identities_from_file(path: &str) -> Result<Vec<Box<dyn Identity>>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read identity file {path}"))?;

    // Try to parse as SSH identity first
    if content.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || content.contains("-----BEGIN RSA PRIVATE KEY-----")
        || content.contains("-----BEGIN EC PRIVATE KEY-----")
    {
        let ssh_identity =
            age::ssh::Identity::from_buffer(std::io::Cursor::new(content), Some(path.to_string()))
                .map_err(|e| anyhow::anyhow!("Failed to parse SSH identity from {path}: {e}"))?;
        return Ok(vec![Box::new(ssh_identity)]);
    }

    // Fall back to age identity file format
    let id_file = IdentityFile::from_file(path.to_string())
        .with_context(|| format!("Failed to parse identity file {path}"))?;
    id_file
        .into_identities()
        .context("Failed to convert identity file into identities")
}

/// Get default SSH identity files
pub fn get_default_identities() -> Vec<String> {
    std::env::var("HOME")
        .map(|home| {
            ["id_rsa", "id_ed25519"]
                .iter()
                .map(|key_type| format!("{home}/.ssh/{key_type}"))
                .filter(|path| Path::new(path).exists())
                .collect()
        })
        .unwrap_or_default()
}
