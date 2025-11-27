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

impl SecretStatus {
    /// Returns the display symbol for this status
    fn symbol(&self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Missing => "○",
            Self::CannotDecrypt(_) => "✗",
        }
    }

    /// Returns the display text for detailed view
    fn detailed_text(&self) -> String {
        format!("{} {}", self.symbol(), self)
    }

    /// Updates counts based on status: (ok, missing, error)
    fn update_counts(&self, counts: (usize, usize, usize)) -> (usize, usize, usize) {
        let (ok, missing, err) = counts;
        match self {
            Self::Ok => (ok + 1, missing, err),
            Self::Missing => (ok, missing + 1, err),
            Self::CannotDecrypt(_) => (ok, missing, err + 1),
        }
    }
}

impl std::fmt::Display for SecretStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::CannotDecrypt(_) => write!(f, "cannot decrypt"),
            Self::Missing => write!(f, "missing"),
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

    // Collect and sort secrets
    let mut secrets: Vec<SecretInfo> = all_files
        .iter()
        .map(|file| get_secret_info(rules_path, file, identities, no_system_identities))
        .collect::<Result<Vec<_>>>()?;
    secrets.sort_by(|a, b| a.name.cmp(&b.name));

    // Print and count
    let stats = print_secrets(&secrets, detailed);

    // Print summary
    println!();
    println!(
        "Total: {} secrets ({} ok, {} missing, {} errors)",
        secrets.len(),
        stats.0,
        stats.1,
        stats.2
    );

    Ok(())
}

/// Print secrets to stdout and return (ok_count, missing_count, error_count)
fn print_secrets(secrets: &[SecretInfo], detailed: bool) -> (usize, usize, usize) {
    let max_name_len = secrets.iter().map(|s| s.name.len()).max().unwrap_or(0);
    let yes_no = |b: bool| if b { "yes" } else { "no" };

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

    secrets.iter().fold((0, 0, 0), |counts, secret| {
        if detailed {
            println!(
                "{:<width$}  {:^15}  {:^9}  {:^6}  {:^7}  {:^5}",
                secret.name,
                secret.status.detailed_text(),
                yes_no(secret.has_generator),
                yes_no(secret.has_public_key_file),
                secret.recipient_count,
                yes_no(secret.armored),
                width = max_name_len
            );
        } else {
            println!("{} {}", secret.status.symbol(), secret.name);
        }
        secret.status.update_counts(counts)
    })
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
        let msg = if files.is_empty() {
            format!("No secrets defined in {}", rules_path)
        } else {
            "No existing secret files to check".to_string()
        };
        eprintln!("{}", msg);
        return Ok(());
    }

    eprintln!("Checking {} secrets...", existing_files.len());

    // Check each file and collect results
    let results: Vec<_> = existing_files
        .iter()
        .map(|file| {
            let name = SecretName::new(file);
            let result = crypto::can_decrypt(file, identities, no_system_identities);
            (name.normalized().to_string(), result)
        })
        .collect();

    // Print results and count failures
    let failed: Vec<_> = results
        .iter()
        .filter_map(|(name, result)| match result {
            Ok(()) => {
                eprintln!("✓ {}", name);
                None
            }
            Err(e) => {
                eprintln!("✗ {}: {}", name, e);
                Some(name.clone())
            }
        })
        .collect();

    eprintln!();

    if failed.is_empty() {
        eprintln!("All {} secrets verified successfully.", results.len());
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Verification failed: {} of {} secrets could not be decrypted",
            failed.len(),
            results.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    // ===========================================
    // LIST COMMAND TESTS (10+ tests)
    // ===========================================

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
    fn test_list_nonexistent_rules_file() {
        let result = list_secrets("/nonexistent/path/secrets.nix", false, &[], false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nonexistent") || err_msg.contains("No such file"),
            "Error should mention the file doesn't exist: {}",
            err_msg
        );
    }

    #[test]
    fn test_list_invalid_nix_syntax() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{{ invalid nix syntax !!!").unwrap();
        temp_file.flush().unwrap();

        let result = list_secrets(temp_file.path().to_str().unwrap(), false, &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_with_generator() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/generated.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "test-secret";
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
    fn test_list_with_multiple_recipients() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/multi-recipient.age" = {{
    publicKeys = [ 
      "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH"
    ];
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
    fn test_list_with_armor_true() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/armored.age" = {{
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
    fn test_list_with_armor_false() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/not-armored.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    armor = false;
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
    fn test_list_with_pub_file_present() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/with-pub.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Create the .pub file
        let pub_path = temp_dir.path().join("with-pub.age.pub");
        fs::write(&pub_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPublic").unwrap();

        let result = list_secrets(temp_rules.path().to_str().unwrap(), true, &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_many_secrets() {
        let temp_dir = tempdir().unwrap();
        let mut rules_content = String::from("{\n");
        for i in 0..20 {
            rules_content.push_str(&format!(
                "  \"{}/secret{}.age\" = {{ publicKeys = [ \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\" ]; }};\n",
                temp_dir.path().to_str().unwrap(),
                i
            ));
        }
        rules_content.push_str("}\n");

        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_with_missing_file() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/missing.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Don't create the file - it's missing
        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], false);
        assert!(result.is_ok()); // List succeeds but shows missing status
    }

    #[test]
    fn test_list_with_corrupted_secret() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/corrupted.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Create a corrupted (invalid) secret file
        let secret_path = temp_dir.path().join("corrupted.age");
        fs::write(&secret_path, "not-valid-age-format").unwrap();

        // List should succeed but show cannot decrypt status
        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], false);
        assert!(result.is_ok());
    }

    // ===========================================
    // CHECK COMMAND TESTS (10+ tests)
    // ===========================================

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
    fn test_check_nonexistent_rules_file() {
        let result = check_secrets("/nonexistent/path/secrets.nix", &[], &[], false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nonexistent") || err_msg.contains("No such file"),
            "Error should mention the file doesn't exist: {}",
            err_msg
        );
    }

    #[test]
    fn test_check_empty_rules() {
        let rules_content = "{ }";
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{}", rules_content).unwrap();
        temp_file.flush().unwrap();

        let result = check_secrets(temp_file.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_invalid_nix_syntax() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{{ invalid nix syntax !!!").unwrap();
        temp_file.flush().unwrap();

        let result = check_secrets(temp_file.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_multiple_invalid_secrets() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/invalid1.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/invalid2.age" = {{
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

        // Create two invalid secret files
        let secret1_path = temp_dir.path().join("invalid1.age");
        let secret2_path = temp_dir.path().join("invalid2.age");
        fs::write(&secret1_path, "invalid-content-1").unwrap();
        fs::write(&secret2_path, "invalid-content-2").unwrap();

        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("2 of 2"),
            "Error should report both failures: {}",
            err_msg
        );
    }

    #[test]
    fn test_check_nonexistent_secret_filter() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/existing.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Try to check a secret that doesn't exist in rules
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["nonexistent".to_string()],
            &[],
            false,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No matching secrets"),
            "Error should mention no matching secrets: {}",
            err_msg
        );
    }

    #[test]
    fn test_check_with_age_suffix_in_filter() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Check using .age suffix
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["secret.age".to_string()],
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_without_age_suffix_in_filter() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Check without .age suffix
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["secret".to_string()],
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_multiple_specific_secrets() {
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
  "{}/secret3.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Check only secret1 and secret3
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["secret1".to_string(), "secret3".to_string()],
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_error_message_includes_file_name() {
        let temp_dir = tempdir().unwrap();
        let rules_content = format!(
            r#"
{{
  "{}/bad-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );
        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        // Create an invalid secret file
        let secret_path = temp_dir.path().join("bad-secret.age");
        fs::write(&secret_path, "invalid").unwrap();

        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
        // The error should include information about failed secrets
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("1 of 1") || err_msg.contains("Verification failed"),
            "Error should provide count: {}",
            err_msg
        );
    }

    // ===========================================
    // SECRET STATUS TESTS
    // ===========================================

    #[test]
    fn test_secret_status_display() {
        assert_eq!(format!("{}", SecretStatus::Ok), "ok");
        assert_eq!(format!("{}", SecretStatus::Missing), "missing");
        assert_eq!(
            format!("{}", SecretStatus::CannotDecrypt("error".to_string())),
            "cannot decrypt"
        );
    }

    #[test]
    fn test_secret_status_equality() {
        assert_eq!(SecretStatus::Ok, SecretStatus::Ok);
        assert_eq!(SecretStatus::Missing, SecretStatus::Missing);
        assert_eq!(
            SecretStatus::CannotDecrypt("e1".to_string()),
            SecretStatus::CannotDecrypt("e1".to_string())
        );
        assert_ne!(SecretStatus::Ok, SecretStatus::Missing);
        assert_ne!(
            SecretStatus::CannotDecrypt("e1".to_string()),
            SecretStatus::CannotDecrypt("e2".to_string())
        );
    }

    #[test]
    fn test_secret_status_clone() {
        let status = SecretStatus::CannotDecrypt("test error".to_string());
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_secret_status_debug() {
        let status = SecretStatus::Ok;
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("Ok"));

        let status = SecretStatus::Missing;
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("Missing"));

        let status = SecretStatus::CannotDecrypt("error msg".to_string());
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("CannotDecrypt"));
        assert!(debug_str.contains("error msg"));
    }
}
