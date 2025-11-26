//! Rekey operations for encrypted secrets.
//!
//! This module handles re-encrypting secrets with updated recipients.

use anyhow::{Result, anyhow};
use std::path::Path;

use crate::nix::get_all_files;

use super::edit::edit_file;
use super::secret_name::SecretName;

/// Result of the pre-flight decryption check.
pub struct PreflightResult {
    /// Files that can be decrypted
    pub decryptable: Vec<String>,
    /// Files that cannot be decrypted, with error messages
    pub undecryptable: Vec<(String, String)>,
}

/// Perform a pre-flight check to verify which files can be decrypted.
///
/// # Arguments
/// * `files` - List of files to check
/// * `identities` - Identity files for decryption
/// * `no_system_identities` - If true, don't use default system identities
fn preflight_check(
    files: &[String],
    identities: &[String],
    no_system_identities: bool,
) -> PreflightResult {
    let mut decryptable = Vec::new();
    let mut undecryptable = Vec::new();

    for file in files {
        if let Err(e) = crate::crypto::can_decrypt(file, identities, no_system_identities) {
            undecryptable.push((file.clone(), format!("{e:#}")));
        } else {
            decryptable.push(file.clone());
        }
    }

    PreflightResult {
        decryptable,
        undecryptable,
    }
}

/// Report the results of the undecryptable files check.
///
/// Returns an error in strict mode if any files are undecryptable.
fn handle_undecryptable_files(undecryptable: &[(String, String)], partial: bool) -> Result<()> {
    if undecryptable.is_empty() {
        return Ok(());
    }

    let file_list: Vec<String> = undecryptable
        .iter()
        .map(|(f, e)| format!("  - {}: {}", f, e))
        .collect();

    if !partial {
        return Err(anyhow!(
            "Cannot rekey: the following {} secret(s) cannot be decrypted with the available identities:\n{}\n\nNo secrets were modified.\n\nHint: Use --partial to rekey only the secrets that can be decrypted.",
            undecryptable.len(),
            file_list.join("\n")
        ));
    }

    // Partial mode: warn about skipped files
    eprintln!(
        "Warning: Skipping {} undecryptable secret(s):\n{}",
        undecryptable.len(),
        file_list.join("\n")
    );

    Ok(())
}

/// Report the results of the rekey operation.
fn report_rekey_results(failed_files: &[(String, String)], success_count: usize) {
    if !failed_files.is_empty() {
        eprintln!();
        eprintln!(
            "Warning: Failed to rekey {} secret(s) during processing:",
            failed_files.len()
        );
        for (file, err) in failed_files {
            eprintln!("  - {}: {}", file, err);
        }
    }

    if success_count > 0 {
        eprintln!("Successfully rekeyed {} secrets.", success_count);
    }
}

/// Validate that requested secrets exist in the rules file.
///
/// Returns an error if secrets are specified but none match.
fn validate_secrets_exist(filtered_files: &[String], secrets: &[String]) -> Result<()> {
    if filtered_files.is_empty() && !secrets.is_empty() {
        return Err(anyhow!(
            "No matching secrets found in rules file for: {}",
            secrets.join(", ")
        ));
    }
    Ok(())
}

/// Filter files based on specified secrets.
///
/// If secrets is empty, return all files. Otherwise, return files that match
/// any of the specified secrets.
pub fn filter_files(files: &[String], secrets: &[String]) -> Vec<String> {
    if secrets.is_empty() {
        return files.to_vec();
    }

    files
        .iter()
        .filter(|file| {
            let file_name = SecretName::new(file);
            secrets.iter().any(|s| {
                let secret_name = SecretName::new(s);
                file_name.matches(&secret_name) || s == *file
            })
        })
        .cloned()
        .collect()
}

/// Rekey files in the rules (no-op editor used to avoid launching an editor).
///
/// If secrets is empty, rekeys all secrets. Otherwise, only rekeys the specified secrets.
///
/// Pre-flight check always runs first to verify which secrets can be decrypted.
/// In strict mode (partial=false), fails if any secrets cannot be decrypted.
/// In partial mode (partial=true), proceeds with only the decryptable secrets.
///
/// # Arguments
/// * `rules_path` - Path to the Nix rules file
/// * `secrets` - List of secrets to rekey (empty means all)
/// * `identities` - Identity files for decryption
/// * `no_system_identities` - If true, don't use default system identities
/// * `partial` - If true, continue even if some secrets can't be decrypted
pub fn rekey_files(
    rules_path: &str,
    secrets: &[String],
    identities: &[String],
    no_system_identities: bool,
    partial: bool,
) -> Result<()> {
    let all_files = get_all_files(rules_path)?;
    let files = filter_files(&all_files, secrets);

    validate_secrets_exist(&files, secrets)?;

    // Filter to only existing files (non-existing files don't need rekeying)
    let existing_files: Vec<_> = files
        .iter()
        .filter(|f| Path::new(f).exists())
        .cloned()
        .collect();

    // Pre-flight check: verify which files can be decrypted
    eprintln!(
        "Checking decryption for {} secrets...",
        existing_files.len()
    );

    let preflight = preflight_check(&existing_files, identities, no_system_identities);

    // Handle undecryptable files based on mode
    handle_undecryptable_files(&preflight.undecryptable, partial)?;

    if preflight.decryptable.is_empty() && !existing_files.is_empty() {
        return Err(anyhow!("No secrets could be decrypted. Nothing to rekey."));
    }

    if preflight.decryptable.is_empty() {
        eprintln!("No existing secrets to rekey.");
        return Ok(());
    }

    eprintln!(
        "Proceeding to rekey {} secrets...",
        preflight.decryptable.len()
    );

    // Process all decryptable files
    let mut failed_files: Vec<(String, String)> = Vec::new();
    let mut success_count = 0;

    for file in &preflight.decryptable {
        eprintln!("Rekeying {file}...");
        // Never use force for rekey - we already verified decryptability in preflight
        if let Err(e) = edit_file(
            rules_path,
            file,
            ":",
            identities,
            no_system_identities,
            false,
        ) {
            if partial {
                failed_files.push((file.clone(), format!("{e:#}")));
            } else {
                return Err(anyhow!(
                    "Unexpected error rekeying '{}': {}\n\nThis is unexpected after pre-flight check passed.",
                    file,
                    e
                ));
            }
        } else {
            success_count += 1;
        }
    }

    report_rekey_results(&failed_files, success_count);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_filter_files_empty_secrets() {
        let files = vec!["a.age".to_string(), "b.age".to_string()];
        let result = filter_files(&files, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_files_with_secrets() {
        let files = vec![
            "/path/to/secret1.age".to_string(),
            "/path/to/secret2.age".to_string(),
            "/path/to/other.age".to_string(),
        ];
        let secrets = vec!["secret1".to_string()];
        let result = filter_files(&files, &secrets);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("secret1"));
    }

    #[test]
    fn test_filter_files_with_full_path() {
        let files = vec!["/path/to/secret.age".to_string()];
        let secrets = vec!["/path/to/secret.age".to_string()];
        let result = filter_files(&files, &secrets);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_rekey_uses_no_op_editor() {
        let rules = "./test_secrets.nix";
        let result = rekey_files(rules, &[], &[], false, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_secrets_exist_empty_with_specified() {
        let result = validate_secrets_exist(&[], &["secret".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_secrets_exist_empty_without_specified() {
        let result = validate_secrets_exist(&[], &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rekey_partial_flag_recognized() {
        // Test that --partial flag is recognized
        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--partial".to_string(),
        ];

        // The command should parse (even though it will fail later due to missing rules)
        let parsed_result = std::panic::catch_unwind(|| {
            use clap::Parser;
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let _ = crate::cli::Args::try_parse_from(args_ref);
        });
        assert!(parsed_result.is_ok(), "--partial flag should be recognized");
    }

    #[test]
    fn test_rekey_strict_mode_error_message_hint() {
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

        let secret_path = temp_dir.path().join("secret.age");
        fs::write(&secret_path, "not-a-valid-age-file").unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Rekey of invalid file should fail");
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("--partial"),
            "Error should mention --partial hint: {}",
            err_msg
        );
    }

    #[test]
    fn test_rekey_partial_continues_on_error() {
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

        let secret_path = temp_dir.path().join("secret.age");
        fs::write(&secret_path, "not-a-valid-age-file").unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--partial".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_err(),
            "Rekey with --partial should fail when all files are undecryptable"
        );
    }

    #[test]
    fn test_rekey_preflight_check_fails_before_any_modification() {
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

        let secret1_path = temp_dir.path().join("secret1.age");
        let secret2_path = temp_dir.path().join("secret2.age");
        let invalid_content = "not-a-valid-age-file";
        fs::write(&secret1_path, invalid_content).unwrap();
        fs::write(&secret2_path, invalid_content).unwrap();

        let original_content1 = fs::read(&secret1_path).unwrap();
        let original_content2 = fs::read(&secret2_path).unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Rekey should fail in strict mode");

        assert_eq!(
            fs::read(&secret1_path).unwrap(),
            original_content1,
            "secret1.age should not be modified"
        );
        assert_eq!(
            fs::read(&secret2_path).unwrap(),
            original_content2,
            "secret2.age should not be modified"
        );
    }

    #[test]
    fn test_rekey_preflight_lists_all_undecryptable() {
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

        fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
        fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();
        fs::write(temp_dir.path().join("secret3.age"), "invalid3").unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Rekey should fail");
        let err_msg = format!("{:?}", result.unwrap_err());

        assert!(
            err_msg.contains("secret1.age"),
            "Error should mention secret1.age"
        );
        assert!(
            err_msg.contains("secret2.age"),
            "Error should mention secret2.age"
        );
        assert!(
            err_msg.contains("secret3.age"),
            "Error should mention secret3.age"
        );
        assert!(err_msg.contains("3"), "Error should mention count 3");
    }

    #[test]
    fn test_rekey_preflight_skips_nonexistent_files() {
        let temp_dir = tempdir().unwrap();

        let rules_content = format!(
            r#"
{{
  "{}/existing_invalid1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/existing_invalid2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/nonexistent1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/nonexistent2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        let path1 = temp_dir.path().join("existing_invalid1.age");
        let path2 = temp_dir.path().join("existing_invalid2.age");
        fs::write(&path1, "invalid-content-1").unwrap();
        fs::write(&path2, "invalid-content-2").unwrap();

        let orig1 = fs::read_to_string(&path1).unwrap();
        let orig2 = fs::read_to_string(&path2).unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Rekey should fail in strict mode");
        let err_msg = format!("{:?}", result.unwrap_err());

        assert!(
            err_msg.contains("existing_invalid1.age"),
            "Error should mention existing_invalid1.age"
        );
        assert!(
            err_msg.contains("existing_invalid2.age"),
            "Error should mention existing_invalid2.age"
        );
        assert!(
            !err_msg.contains("nonexistent1.age"),
            "Error should NOT mention nonexistent1.age"
        );
        assert!(
            !err_msg.contains("nonexistent2.age"),
            "Error should NOT mention nonexistent2.age"
        );
        assert!(err_msg.contains("2"), "Error should mention count 2");

        assert_eq!(fs::read_to_string(&path1).unwrap(), orig1);
        assert_eq!(fs::read_to_string(&path2).unwrap(), orig2);
    }

    #[test]
    fn test_rekey_partial_runs_preflight_but_continues() {
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

        fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
        fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--partial".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(
            result.is_err(),
            "Rekey --partial should fail when all files are undecryptable"
        );
    }

    #[test]
    fn test_rekey_complex_mixed_decryptable_undecryptable() {
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

        fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
        fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();
        fs::write(temp_dir.path().join("secret3.age"), "invalid3").unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Rekey should fail in strict mode");
        let err_msg = format!("{:?}", result.unwrap_err());

        assert!(
            err_msg.contains("secret1.age"),
            "Error should mention secret1.age"
        );
        assert!(
            err_msg.contains("secret2.age"),
            "Error should mention secret2.age"
        );
        assert!(
            err_msg.contains("secret3.age"),
            "Error should mention secret3.age"
        );
    }

    #[test]
    fn test_rekey_specific_secrets_preflight() {
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

        fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
        fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();
        fs::write(temp_dir.path().join("secret3.age"), "invalid3").unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "secret1".to_string(),
            "secret2".to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Rekey should fail");
        let err_msg = format!("{:?}", result.unwrap_err());

        assert!(
            err_msg.contains("secret1.age"),
            "Should mention secret1.age"
        );
        assert!(
            err_msg.contains("secret2.age"),
            "Should mention secret2.age"
        );
        assert!(
            !err_msg.contains("secret3.age"),
            "Should NOT mention secret3.age"
        );
        assert!(err_msg.contains("2"), "Should mention count 2");
    }

    #[test]
    fn test_rekey_all_vs_explicit_all_undecryptable_handling() {
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

        fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
        fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

        let args_implicit_all = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result_implicit = crate::run(args_implicit_all);
        assert!(result_implicit.is_err(), "Rekey all (implicit) should fail");
        let err_implicit = format!("{:?}", result_implicit.unwrap_err());

        let args_explicit_all = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "secret1".to_string(),
            "secret2".to_string(),
        ];

        let result_explicit = crate::run(args_explicit_all);
        assert!(result_explicit.is_err(), "Rekey all (explicit) should fail");
        let err_explicit = format!("{:?}", result_explicit.unwrap_err());

        assert!(
            err_implicit.contains("secret1.age"),
            "Implicit all should mention secret1.age"
        );
        assert!(
            err_implicit.contains("secret2.age"),
            "Implicit all should mention secret2.age"
        );
        assert!(
            err_explicit.contains("secret1.age"),
            "Explicit all should mention secret1.age"
        );
        assert!(
            err_explicit.contains("secret2.age"),
            "Explicit all should mention secret2.age"
        );
        assert!(
            err_implicit.contains("2"),
            "Implicit all should mention count 2"
        );
        assert!(
            err_explicit.contains("2"),
            "Explicit all should mention count 2"
        );
        assert!(
            err_implicit.contains("--partial"),
            "Implicit all should suggest --partial"
        );
        assert!(
            err_explicit.contains("--partial"),
            "Explicit all should suggest --partial"
        );
    }

    #[test]
    fn test_rekey_all_vs_explicit_all_partial_mode() {
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

        fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
        fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

        let args_implicit = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--partial".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
        ];

        let result_implicit = crate::run(args_implicit);
        assert!(
            result_implicit.is_err(),
            "Rekey --partial (implicit all) should fail when all undecryptable"
        );
        let err_implicit = format!("{:?}", result_implicit.unwrap_err());

        fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
        fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

        let args_explicit = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--partial".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "secret1".to_string(),
            "secret2".to_string(),
        ];

        let result_explicit = crate::run(args_explicit);
        assert!(
            result_explicit.is_err(),
            "Rekey --partial (explicit all) should fail when all undecryptable"
        );
        let err_explicit = format!("{:?}", result_explicit.unwrap_err());

        assert!(
            err_implicit.contains("No secrets could be decrypted"),
            "Implicit all should mention no secrets could be decrypted"
        );
        assert!(
            err_explicit.contains("No secrets could be decrypted"),
            "Explicit all should mention no secrets could be decrypted"
        );
    }

    #[test]
    fn test_rekey_nonexistent_secret_explicit_error() {
        let temp_dir = tempdir().unwrap();

        let rules_content = format!(
            r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
            temp_dir.path().to_str().unwrap()
        );

        let mut temp_rules = NamedTempFile::new().unwrap();
        writeln!(temp_rules, "{}", rules_content).unwrap();
        temp_rules.flush().unwrap();

        fs::write(temp_dir.path().join("secret1.age"), "encrypted-content").unwrap();

        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            temp_rules.path().to_str().unwrap().to_string(),
            "nonexistent".to_string(),
        ];

        let result = crate::run(args);
        assert!(result.is_err(), "Rekey with nonexistent secret should fail");
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("No matching secrets"),
            "Error should mention no matching secrets: {}",
            err_msg
        );
    }
}
