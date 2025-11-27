//! List and status operations for secrets.
//!
//! This module provides functions for listing secrets defined in the rules file
//! and displaying their status.

use anyhow::Result;
use std::path::Path;

use crate::crypto;
use crate::nix::{generate_secret_with_public, get_all_files, get_public_keys, should_armor};

use super::filter_files;
use super::secret_name::SecretName;
use super::validate_secrets_exist;

/// Status of a secret file
#[derive(Debug, Clone, PartialEq)]
pub enum SecretStatus {
    /// Secret file exists and can be decrypted
    Ok,
    /// Secret file exists but cannot be decrypted
    CannotDecrypt(String),
    /// Secret file does not exist
    Missing,
}

impl std::fmt::Display for SecretStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretStatus::Ok => write!(f, "ok"),
            SecretStatus::CannotDecrypt(_) => write!(f, "cannot decrypt"),
            SecretStatus::Missing => write!(f, "missing"),
        }
    }
}

/// Information about a secret
#[derive(Debug)]
pub struct SecretInfo {
    pub name: String,
    pub status: SecretStatus,
    pub has_generator: bool,
    pub has_public_key_file: bool,
    pub recipient_count: usize,
    pub armored: bool,
}

/// Get the status of a secret file
fn get_secret_status(
    file: &str,
    identities: &[String],
    no_system_identities: bool,
) -> SecretStatus {
    if !Path::new(file).exists() {
        return SecretStatus::Missing;
    }

    match crypto::can_decrypt(file, identities, no_system_identities) {
        Ok(()) => SecretStatus::Ok,
        Err(e) => SecretStatus::CannotDecrypt(format!("{e:#}")),
    }
}

/// Get information about a secret
fn get_secret_info(
    rules_path: &str,
    file: &str,
    identities: &[String],
    no_system_identities: bool,
) -> Result<SecretInfo> {
    let status = get_secret_status(file, identities, no_system_identities);
    let recipient_count = get_public_keys(rules_path, file)
        .map(|k| k.len())
        .unwrap_or(0);
    let armored = should_armor(rules_path, file).unwrap_or(false);
    let has_generator = generate_secret_with_public(rules_path, file)
        .map(|g| g.is_some())
        .unwrap_or(false);

    // Check for .pub file
    let pub_file = format!("{}.pub", file);
    let has_public_key_file = Path::new(&pub_file).exists();

    let name = SecretName::new(file);

    Ok(SecretInfo {
        name: name.normalized().to_string(),
        status,
        has_generator,
        has_public_key_file,
        recipient_count,
        armored,
    })
}

/// List secrets from the rules file with their status
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `detailed` - Show detailed information about each secret
/// * `identities` - Identity files for decryption verification
/// * `no_system_identities` - If true, don't use default system identities
pub fn list_secrets(
    rules_path: &str,
    detailed: bool,
    identities: &[String],
    no_system_identities: bool,
) -> Result<()> {
    let all_files = get_all_files(rules_path)?;

    if all_files.is_empty() {
        eprintln!("No secrets defined in {}", rules_path);
        return Ok(());
    }

    // Collect info about all secrets
    let mut secrets: Vec<SecretInfo> = Vec::new();
    for file in &all_files {
        let info = get_secret_info(rules_path, file, identities, no_system_identities)?;
        secrets.push(info);
    }

    // Sort by name
    secrets.sort_by(|a, b| a.name.cmp(&b.name));

    // Calculate column widths for detailed view
    let max_name_len = secrets.iter().map(|s| s.name.len()).max().unwrap_or(0);

    // Print header
    if detailed {
        println!(
            "{:<width$}  {:^15}  {:^9}  {:^6}  {:^7}  {:^4}",
            "SECRET",
            "STATUS",
            "GENERATOR",
            "PUBKEY",
            "RECIPS",
            "ARMOR",
            width = max_name_len
        );
        println!(
            "{:-<width$}  {:-^15}  {:-^9}  {:-^6}  {:-^7}  {:-^5}",
            "",
            "",
            "",
            "",
            "",
            "",
            width = max_name_len
        );
    }

    // Count statistics
    let mut ok_count = 0;
    let mut missing_count = 0;
    let mut error_count = 0;

    for secret in &secrets {
        match &secret.status {
            SecretStatus::Ok => ok_count += 1,
            SecretStatus::Missing => missing_count += 1,
            SecretStatus::CannotDecrypt(_) => error_count += 1,
        }

        if detailed {
            let status_str = match &secret.status {
                SecretStatus::Ok => "✓ ok".to_string(),
                SecretStatus::Missing => "○ missing".to_string(),
                SecretStatus::CannotDecrypt(_) => "✗ cannot decrypt".to_string(),
            };
            let generator_str = if secret.has_generator { "yes" } else { "no" };
            let pubkey_str = if secret.has_public_key_file {
                "yes"
            } else {
                "no"
            };
            let armor_str = if secret.armored { "yes" } else { "no" };

            println!(
                "{:<width$}  {:^15}  {:^9}  {:^6}  {:^7}  {:^5}",
                secret.name,
                status_str,
                generator_str,
                pubkey_str,
                secret.recipient_count,
                armor_str,
                width = max_name_len
            );
        } else {
            let status_symbol = match &secret.status {
                SecretStatus::Ok => "✓",
                SecretStatus::Missing => "○",
                SecretStatus::CannotDecrypt(_) => "✗",
            };
            println!("{} {}", status_symbol, secret.name);
        }
    }

    // Print summary
    println!();
    println!(
        "Total: {} secrets ({} ok, {} missing, {} errors)",
        secrets.len(),
        ok_count,
        missing_count,
        error_count
    );

    Ok(())
}

/// Check that secrets can be decrypted
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `secrets` - Secrets to check (if empty, checks all)
/// * `identities` - Identity files for decryption
/// * `no_system_identities` - If true, don't use default system identities
///
/// # Returns
/// Ok(()) if all specified secrets can be decrypted, Err otherwise
pub fn check_secrets(
    rules_path: &str,
    secrets: &[String],
    identities: &[String],
    no_system_identities: bool,
) -> Result<()> {
    let all_files = get_all_files(rules_path)?;
    let files = filter_files(&all_files, secrets);

    validate_secrets_exist(&files, secrets)?;

    // Filter to only existing files
    let existing_files: Vec<_> = files.iter().filter(|f| Path::new(f).exists()).collect();

    if existing_files.is_empty() {
        if files.is_empty() {
            eprintln!("No secrets defined in {}", rules_path);
        } else {
            eprintln!("No existing secret files to check");
        }
        return Ok(());
    }

    let mut all_ok = true;
    let mut checked = 0;
    let mut failed = 0;

    eprintln!("Checking {} secrets...", existing_files.len());

    for file in &existing_files {
        let name = SecretName::new(file);
        match crypto::can_decrypt(file, identities, no_system_identities) {
            Ok(()) => {
                eprintln!("✓ {}", name.normalized());
                checked += 1;
            }
            Err(e) => {
                eprintln!("✗ {}: {}", name.normalized(), e);
                all_ok = false;
                failed += 1;
            }
        }
    }

    eprintln!();
    if all_ok {
        eprintln!("All {} secrets verified successfully.", checked);
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Verification failed: {} of {} secrets could not be decrypted",
            failed,
            checked + failed
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_list_empty_rules() {
        let rules_content = "{ }";
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{}", rules_content).unwrap();
        temp_file.flush().unwrap();

        let result = list_secrets(temp_file.path().to_str().unwrap(), false, &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_with_secrets() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_detailed() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/detailed.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    armor = true;
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        let result = list_secrets(temp_rules.path().to_str().unwrap(), true, &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_nonexistent_secrets() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/nonexistent.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Should succeed but report no existing files
        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_invalid_secret() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/invalid.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Create invalid secret file
        let secret_path = temp_dir.path().join("invalid.age");
        fs::write(&secret_path, "not-a-valid-age-file").unwrap();

        // Should fail because secret cannot be decrypted
        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_specific_secrets() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/secret1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/secret2.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Only check secret1
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["secret1".to_string()],
            &[],
            false,
        );
        // Should succeed because secret doesn't exist (nothing to check)
        assert!(result.is_ok());
    }

    #[test]
    fn test_secret_status_display() {
        assert_eq!(format!("{}", SecretStatus::Ok), "ok");
        assert_eq!(format!("{}", SecretStatus::Missing), "missing");
        assert_eq!(
            format!("{}", SecretStatus::CannotDecrypt("error".to_string())),
            "cannot decrypt"
        );
    }
}
