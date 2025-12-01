//! List and status operations for secrets.
//!
//! This module provides functions for listing secrets defined in the rules file
//! and displaying their status.

use anyhow::Result;
use std::path::Path;

use crate::crypto;
use crate::log;
use crate::nix::{get_all_files, get_secret_output_info};
use crate::output::{is_quiet, pluralize_secret};

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
    /// Public-only secret (no .age file expected, only .pub)
    PublicOnly,
    /// Public-only secret but .pub file is missing
    PublicOnlyMissing,
}

impl SecretStatus {
    /// Returns the short code for this status (script-friendly)
    fn code(&self) -> &'static str {
        match self {
            Self::Ok => "EXISTS",
            Self::Missing => "MISSING",
            Self::CannotDecrypt(_) => "NO_DECRYPT",
            Self::PublicOnly => "PUBLIC_ONLY",
            Self::PublicOnlyMissing => "PUB_MISSING",
        }
    }

    /// Updates counts based on status: (ok, missing, error, public_only)
    fn update_counts(&self, counts: (usize, usize, usize, usize)) -> (usize, usize, usize, usize) {
        let (ok, missing, err, public) = counts;
        match self {
            Self::Ok => (ok + 1, missing, err, public),
            Self::Missing => (ok, missing + 1, err, public),
            Self::CannotDecrypt(_) => (ok, missing, err + 1, public),
            Self::PublicOnly => (ok, missing, err, public + 1),
            Self::PublicOnlyMissing => (ok, missing + 1, err, public),
        }
    }
}

impl std::fmt::Display for SecretStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::CannotDecrypt(_) => write!(f, "cannot decrypt"),
            Self::Missing => write!(f, "missing"),
            Self::PublicOnly => write!(f, "public-only"),
            Self::PublicOnlyMissing => write!(f, "public missing"),
        }
    }
}

/// Information about a secret
#[derive(Debug)]
pub struct SecretInfo {
    pub name: String,
    pub status: SecretStatus,
}

/// Get the status of a secret file, considering public-only secrets
fn get_secret_status(
    rules_path: &str,
    file: &str,
    identities: &[String],
    no_system_identities: bool,
) -> SecretStatus {
    // Check if this is a public-only secret
    if let Ok(output_info) = get_secret_output_info(rules_path, file)
        && !output_info.has_secret
        && output_info.has_public
    {
        // This is a public-only secret - check if .pub file exists
        let file_basename = file.strip_suffix(".age").unwrap_or(file);
        let rules_path_obj = std::path::Path::new(rules_path);
        let rules_dir = rules_path_obj
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));

        let pub_paths = [
            rules_dir.join(format!("{}.age.pub", file_basename)),
            rules_dir.join(format!("{}.pub", file_basename)),
        ];

        if pub_paths.iter().any(|p| p.exists()) {
            return SecretStatus::PublicOnly;
        } else {
            return SecretStatus::PublicOnlyMissing;
        }
    }

    // Normal secret - check for .age file
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
) -> SecretInfo {
    SecretInfo {
        name: SecretName::new(file).normalized().to_string(),
        status: get_secret_status(rules_path, file, identities, no_system_identities),
    }
}

/// List secrets from the rules file
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `show_status` - Show status of each secret (ok/missing/cannot decrypt with available identities)
/// * `secrets` - Secrets to list (if empty, lists all)
/// * `identities` - Identity files for decryption verification
/// * `no_system_identities` - If true, don't use default system identities
pub fn list_secrets(
    rules_path: &str,
    show_status: bool,
    secrets: &[String],
    identities: &[String],
    no_system_identities: bool,
) -> Result<()> {
    let all_files = get_all_files(rules_path)?;
    let files = filter_files(&all_files, secrets);
    validate_secrets_exist(&files, secrets)?;

    if files.is_empty() {
        log!("No secrets defined in {}", rules_path);
        return Ok(());
    }

    // Simple list mode: just output secret names (one per line)
    if !show_status {
        let mut names: Vec<_> = files
            .iter()
            .map(|f| SecretName::new(f).normalized().to_string())
            .collect();
        names.sort();
        for name in names {
            println!("{}", name);
        }
        return Ok(());
    }

    // Status mode: collect full info and print with status
    let mut secret_infos: Vec<SecretInfo> = files
        .iter()
        .map(|file| get_secret_info(rules_path, file, identities, no_system_identities))
        .collect();
    secret_infos.sort_by(|a, b| a.name.cmp(&b.name));

    let (ok, missing, errors, public_only) = print_secrets_with_status(&secret_infos);

    if !is_quiet() {
        if public_only > 0 {
            eprintln!(
                "Total: {} {} ({} exists, {} missing, {} no decrypt, {} public-only)",
                secret_infos.len(),
                pluralize_secret(secret_infos.len()),
                ok,
                missing,
                errors,
                public_only
            );
        } else {
            eprintln!(
                "Total: {} {} ({} exists, {} missing, {} no decrypt)",
                secret_infos.len(),
                pluralize_secret(secret_infos.len()),
                ok,
                missing,
                errors
            );
        }
    }

    Ok(())
}

/// Print secrets with status to stdout and return (ok_count, missing_count, error_count, public_only_count)
fn print_secrets_with_status(secrets: &[SecretInfo]) -> (usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0);

    for s in secrets {
        println!("{}\t{}", s.status.code(), s.name);
        counts = s.status.update_counts(counts);
    }

    counts
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

    let existing: Vec<_> = files.iter().filter(|f| Path::new(f).exists()).collect();

    if existing.is_empty() {
        if files.is_empty() {
            log!("No secrets defined in {}", rules_path);
        } else {
            log!("No existing secret files to check");
        }
        return Ok(());
    }

    log!(
        "Checking {} {}...",
        existing.len(),
        pluralize_secret(existing.len())
    );

    let mut failed = 0;
    for file in &existing {
        let name = SecretName::new(file).normalized().to_string();
        match crypto::can_decrypt(file, identities, no_system_identities) {
            Ok(()) => log!("OK: {}", name),
            Err(e) => {
                log!("ERROR: {}: {}", name, e);
                failed += 1;
            }
        }
    }

    log!("");

    if failed == 0 {
        log!(
            "All {} {} verified successfully.",
            existing.len(),
            pluralize_secret(existing.len())
        );
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Verification failed: {} of {} {} could not be decrypted",
            failed,
            existing.len(),
            pluralize_secret(existing.len())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    /// Default age public key for testing
    const TEST_PUBKEY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

    /// Create a temporary rules file with the given content
    fn create_rules_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{}", content).unwrap();
        temp_file.flush().unwrap();
        temp_file
    }

    /// Create a rules file with a single secret at the given path
    fn single_secret_rules(secret_path: &str, extra_attrs: &str) -> String {
        format!(
            r#"{{ "{}" = {{ publicKeys = [ "{}" ]; {} }}; }}"#,
            secret_path, TEST_PUBKEY, extra_attrs
        )
    }

    // ===========================================
    // LIST COMMAND TESTS (10+ tests)
    // ===========================================

    #[test]
    fn test_list_empty_rules() {
        let temp_file = create_rules_file("{ }");
        let result = list_secrets(temp_file.path().to_str().unwrap(), false, &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_with_secrets() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap();
        let rules = format!(
            r#"{{ "{}/s1.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s2.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            path, TEST_PUBKEY, path, TEST_PUBKEY
        );
        let temp_rules = create_rules_file(&rules);
        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_nonexistent_rules_file() {
        let result = list_secrets("/nonexistent/path/secrets.nix", false, &[], &[], false);
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
        let temp_file = create_rules_file("{ invalid nix syntax !!!");
        let result = list_secrets(temp_file.path().to_str().unwrap(), false, &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_many_secrets() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap();
        let entries: String = (0..20)
            .map(|i| {
                format!(
                    r#""{}/secret{}.age" = {{ publicKeys = [ "{}" ]; }};"#,
                    path, i, TEST_PUBKEY
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let rules = format!("{{ {} }}", entries);
        let temp_rules = create_rules_file(&rules);
        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_with_missing_file() {
        let temp_dir = tempdir().unwrap();
        let rules = single_secret_rules(
            &format!("{}/missing.age", temp_dir.path().to_str().unwrap()),
            "",
        );
        let temp_rules = create_rules_file(&rules);
        // Don't create the file - it's missing
        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], &[], false);
        assert!(result.is_ok()); // List succeeds but shows missing status
    }

    #[test]
    fn test_list_with_corrupted_secret() {
        let temp_dir = tempdir().unwrap();
        let secret_path = format!("{}/corrupted.age", temp_dir.path().to_str().unwrap());
        let rules = single_secret_rules(&secret_path, "");
        let temp_rules = create_rules_file(&rules);

        // Create a corrupted (invalid) secret file
        fs::write(&secret_path, "not-valid-age-format").unwrap();

        // List should succeed but show cannot decrypt status
        let result = list_secrets(temp_rules.path().to_str().unwrap(), false, &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_with_status() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap();
        let rules = format!(
            r#"{{ "{}/s1.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            path, TEST_PUBKEY
        );
        let temp_rules = create_rules_file(&rules);
        let result = list_secrets(temp_rules.path().to_str().unwrap(), true, &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_specific_secrets() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap();
        let rules = format!(
            r#"{{ "{}/s1.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s2.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s3.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            path, TEST_PUBKEY, path, TEST_PUBKEY, path, TEST_PUBKEY
        );
        let temp_rules = create_rules_file(&rules);
        let secrets = vec!["s1".to_string(), "s2".to_string()];
        let result = list_secrets(
            temp_rules.path().to_str().unwrap(),
            false,
            &secrets,
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_nonexistent_secret_filter() {
        let temp_dir = tempdir().unwrap();
        let rules = single_secret_rules(
            &format!("{}/existing.age", temp_dir.path().to_str().unwrap()),
            "",
        );
        let temp_rules = create_rules_file(&rules);

        // Try to list a secret that doesn't exist in rules
        let secrets = vec!["nonexistent".to_string()];
        let result = list_secrets(
            temp_rules.path().to_str().unwrap(),
            false,
            &secrets,
            &[],
            false,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No matching secrets")
        );
    }

    // ===========================================
    // CHECK COMMAND TESTS (10+ tests)
    // ===========================================

    #[test]
    fn test_check_nonexistent_secrets() {
        let temp_dir = tempdir().unwrap();
        let rules = single_secret_rules(
            &format!("{}/nonexistent.age", temp_dir.path().to_str().unwrap()),
            "",
        );
        let temp_rules = create_rules_file(&rules);
        // Should succeed but report no existing files
        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_invalid_secret() {
        let temp_dir = tempdir().unwrap();
        let secret_path = format!("{}/invalid.age", temp_dir.path().to_str().unwrap());
        let rules = single_secret_rules(&secret_path, "");
        let temp_rules = create_rules_file(&rules);

        // Create invalid secret file
        fs::write(&secret_path, "not-a-valid-age-file").unwrap();

        // Should fail because secret cannot be decrypted
        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_specific_secrets() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap();
        let rules = format!(
            r#"{{ "{}/s1.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s2.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            path, TEST_PUBKEY, path, TEST_PUBKEY
        );
        let temp_rules = create_rules_file(&rules);

        // Only check secret1 - should succeed because file doesn't exist
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["s1".to_string()],
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_nonexistent_rules_file() {
        let result = check_secrets("/nonexistent/path/secrets.nix", &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_empty_rules() {
        let temp_file = create_rules_file("{ }");
        let result = check_secrets(temp_file.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_invalid_nix_syntax() {
        let temp_file = create_rules_file("{ invalid nix syntax !!!");
        let result = check_secrets(temp_file.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_multiple_invalid_secrets() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap();
        let rules = format!(
            r#"{{ "{}/inv1.age" = {{ publicKeys = [ "{}" ]; }}; "{}/inv2.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            path, TEST_PUBKEY, path, TEST_PUBKEY
        );
        let temp_rules = create_rules_file(&rules);

        // Create two invalid secret files
        fs::write(format!("{}/inv1.age", path), "invalid1").unwrap();
        fs::write(format!("{}/inv2.age", path), "invalid2").unwrap();

        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("2 of 2"));
    }

    #[test]
    fn test_check_nonexistent_secret_filter() {
        let temp_dir = tempdir().unwrap();
        let rules = single_secret_rules(
            &format!("{}/existing.age", temp_dir.path().to_str().unwrap()),
            "",
        );
        let temp_rules = create_rules_file(&rules);

        // Try to check a secret that doesn't exist in rules
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["nonexistent".to_string()],
            &[],
            false,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No matching secrets")
        );
    }

    #[test]
    fn test_check_with_age_suffix_in_filter() {
        let temp_dir = tempdir().unwrap();
        let rules = single_secret_rules(
            &format!("{}/secret.age", temp_dir.path().to_str().unwrap()),
            "",
        );
        let temp_rules = create_rules_file(&rules);

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
        let rules = single_secret_rules(
            &format!("{}/secret.age", temp_dir.path().to_str().unwrap()),
            "",
        );
        let temp_rules = create_rules_file(&rules);

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
        let path = temp_dir.path().to_str().unwrap();
        let rules = format!(
            r#"{{ "{}/s1.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s2.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s3.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            path, TEST_PUBKEY, path, TEST_PUBKEY, path, TEST_PUBKEY
        );
        let temp_rules = create_rules_file(&rules);

        // Check only s1 and s3
        let result = check_secrets(
            temp_rules.path().to_str().unwrap(),
            &["s1".to_string(), "s3".to_string()],
            &[],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_error_message_includes_file_name() {
        let temp_dir = tempdir().unwrap();
        let secret_path = format!("{}/bad-secret.age", temp_dir.path().to_str().unwrap());
        let rules = single_secret_rules(&secret_path, "");
        let temp_rules = create_rules_file(&rules);

        // Create an invalid secret file
        fs::write(&secret_path, "invalid").unwrap();

        let result = check_secrets(temp_rules.path().to_str().unwrap(), &[], &[], false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("1 of 1"));
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
        assert_eq!(format!("{}", SecretStatus::PublicOnly), "public-only");
        assert_eq!(
            format!("{}", SecretStatus::PublicOnlyMissing),
            "public missing"
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
        assert_eq!(SecretStatus::PublicOnly, SecretStatus::PublicOnly);
        assert_ne!(SecretStatus::PublicOnly, SecretStatus::PublicOnlyMissing);
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

    // ===========================================
    // STATUS CODE TESTS
    // ===========================================

    #[test]
    fn test_status_code_ok() {
        assert_eq!(SecretStatus::Ok.code(), "EXISTS");
    }

    #[test]
    fn test_status_code_missing() {
        assert_eq!(SecretStatus::Missing.code(), "MISSING");
    }

    #[test]
    fn test_status_code_error() {
        assert_eq!(
            SecretStatus::CannotDecrypt("any error".to_string()).code(),
            "NO_DECRYPT"
        );
    }

    #[test]
    fn test_status_code_public_only() {
        assert_eq!(SecretStatus::PublicOnly.code(), "PUBLIC_ONLY");
    }

    #[test]
    fn test_status_code_public_only_missing() {
        assert_eq!(SecretStatus::PublicOnlyMissing.code(), "PUB_MISSING");
    }

    #[test]
    fn test_status_update_counts_ok() {
        let (ok, missing, err, public) = SecretStatus::Ok.update_counts((0, 0, 0, 0));
        assert_eq!((ok, missing, err, public), (1, 0, 0, 0));
    }

    #[test]
    fn test_status_update_counts_missing() {
        let (ok, missing, err, public) = SecretStatus::Missing.update_counts((0, 0, 0, 0));
        assert_eq!((ok, missing, err, public), (0, 1, 0, 0));
    }

    #[test]
    fn test_status_update_counts_error() {
        let (ok, missing, err, public) =
            SecretStatus::CannotDecrypt("err".to_string()).update_counts((0, 0, 0, 0));
        assert_eq!((ok, missing, err, public), (0, 0, 1, 0));
    }

    #[test]
    fn test_status_update_counts_cumulative() {
        let counts = (5, 3, 2, 1);
        let (ok, missing, err, public) = SecretStatus::Ok.update_counts(counts);
        assert_eq!((ok, missing, err, public), (6, 3, 2, 1));

        let (ok, missing, err, public) = SecretStatus::Missing.update_counts(counts);
        assert_eq!((ok, missing, err, public), (5, 4, 2, 1));

        let (ok, missing, err, public) =
            SecretStatus::CannotDecrypt("err".to_string()).update_counts(counts);
        assert_eq!((ok, missing, err, public), (5, 3, 3, 1));

        let (ok, missing, err, public) = SecretStatus::PublicOnly.update_counts(counts);
        assert_eq!((ok, missing, err, public), (5, 3, 2, 2));
    }

    // ===========================================
    // SECRET INFO TESTS
    // ===========================================

    #[test]
    fn test_get_secret_status_missing_file() {
        // Create a minimal rules file
        let temp_rules =
            create_rules_file(r#"{ "nonexistent.age" = { publicKeys = ["age1..."]; }; }"#);
        let status = get_secret_status(
            temp_rules.path().to_str().unwrap(),
            "/nonexistent/file.age",
            &[],
            false,
        );
        assert_eq!(status, SecretStatus::Missing);
    }

    #[test]
    fn test_get_secret_status_invalid_file() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("invalid.age");
        fs::write(&path, "not-valid-age-content").unwrap();

        // Create a minimal rules file
        let temp_rules = create_rules_file(&format!(
            r#"{{ "{}" = {{ publicKeys = ["age1..."]; }}; }}"#,
            path.to_str().unwrap()
        ));

        let status = get_secret_status(
            temp_rules.path().to_str().unwrap(),
            path.to_str().unwrap(),
            &[],
            false,
        );
        assert!(matches!(status, SecretStatus::CannotDecrypt(_)));
    }
}
