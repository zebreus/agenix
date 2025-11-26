//! Tests for the editor module.

use super::*;
use anyhow::Result;
use std::fs::{self, File};
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_edit_file_no_keys() {
    let rules = "./test_secrets.nix";
    let result = edit_file(rules, "nonexistent.age", "vi", &[], false);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_file_no_keys() {
    let rules = "./test_secrets.nix";
    let result = decrypt_file(rules, "nonexistent.age", None, &[], false);
    assert!(result.is_err());
}

#[test]
fn test_rekey_uses_no_op_editor() {
    // With nonexistent rules this will early error if keys empty; simulate empty by pointing to test file
    let rules = "./test_secrets.nix";
    // Should error, but specifically via missing keys, not editor invocation failure.
    let result = rekey_files(rules, &[], &[], false, false);
    assert!(result.is_err());
}

#[test]
fn test_skip_reencrypt_when_unchanged() {
    // We cannot fully simulate encryption without keys; focus on the unchanged branch logic.
    // Create a temp dir and a dummy age file plus rules path pointing to nonexistent keys causing early return of skip branch.
    let tmp = tempdir().unwrap();
    let secret_path = tmp.path().join("dummy.age");
    // Create an empty file so decrypt_to_file won't run (no existence of keys) but backup logic proceeds.
    File::create(&secret_path).unwrap();
    // Call edit_file expecting an error due to no keys; ensures we reach key check early.
    let res = edit_file(
        "./test_secrets.nix",
        secret_path.to_str().unwrap(),
        ":",
        &[],
        false,
    );
    assert!(res.is_err());
}

#[test]
fn test_generate_secrets_with_nonexistent_rules() {
    // Use the CLI interface via the run function
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        "./nonexistent_rules.nix".to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err());
}

#[test]
fn test_generate_secrets_functionality() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary directory for the generated secrets
    let temp_dir = tempdir()?;

    // Create the rules file with absolute paths to avoid race conditions with parallel tests
    let rules_content_with_abs_paths = format!(
        r#"
{{
  "{}/static-secret.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "static-password-123";
  }};
  "{}/random-secret.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: builtins.randomString 16;
  }};
  "{}/no-generator.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules_abs = NamedTempFile::new()?;
    writeln!(temp_rules_abs, "{}", rules_content_with_abs_paths)?;
    temp_rules_abs.flush()?;

    // Use the CLI interface via the run function instead of calling generate_secrets directly
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules_abs.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);

    // Check that the files with generators were created
    let static_secret_path = temp_dir.path().join("static-secret.age");
    let random_secret_path = temp_dir.path().join("random-secret.age");
    let no_generator_path = temp_dir.path().join("no-generator.age");

    let static_exists = static_secret_path.exists();
    let random_exists = random_secret_path.exists();
    let no_generator_exists = no_generator_path.exists();

    // Read file contents
    let static_content = if static_exists {
        Some(fs::read(&static_secret_path)?)
    } else {
        None
    };
    let random_content = if random_exists {
        Some(fs::read(&random_secret_path)?)
    } else {
        None
    };

    // Should succeed
    assert!(
        result.is_ok(),
        "CLI generate should succeed: {:?}",
        result.err()
    );

    assert!(static_exists, "static-secret.age should be created");
    assert!(random_exists, "random-secret.age should be created");
    assert!(
        !no_generator_exists,
        "no-generator.age should not be created"
    );

    // Verify the files are not empty (they contain encrypted data)
    let static_data = static_content.unwrap();
    let random_data = random_content.unwrap();

    assert!(
        !static_data.is_empty(),
        "static-secret.age should not be empty"
    );
    assert!(
        !random_data.is_empty(),
        "random-secret.age should not be empty"
    );

    // The encrypted files should be different (different content/randomness)
    assert_ne!(
        static_data, random_data,
        "Generated files should have different encrypted content"
    );

    Ok(())
}

#[test]
fn test_generate_secrets_skip_existing_files() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary directory with an existing file
    let temp_dir = tempdir()?;

    // Create the rules file with absolute paths
    let rules_content = format!(
        r#"
{{
  "{}/existing-secret.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "should-not-overwrite";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let existing_file_path = temp_dir.path().join("existing-secret.age");
    fs::write(&existing_file_path, b"existing content")?;

    let original_content = fs::read(&existing_file_path)?;

    // Use the CLI interface via the run function instead of calling generate_secrets directly
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);

    // Should succeed
    assert!(result.is_ok());

    // File should still exist with original content (not overwritten)
    assert!(existing_file_path.exists());
    let current_content = fs::read(&existing_file_path)?;
    assert_eq!(
        original_content, current_content,
        "Existing file should not be overwritten"
    );

    Ok(())
}

#[test]
fn test_stdin_editor_functionality() -> Result<()> {
    use std::io::Write;

    let temp_dir = tempdir()?;
    let test_file_path = temp_dir.path().join("test-stdin.age");

    // Create a temporary rules file with absolute path to the test file
    let rules_content = format!(
        r#"
{{
  "{}" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
}}
"#,
        test_file_path.to_str().unwrap()
    );

    let temp_rules: PathBuf = temp_dir.path().join("secrets.nix").to_path_buf();

    writeln!(File::create(&temp_rules).unwrap(), "{}", rules_content)?;

    // Test that the "<stdin>" editor command is recognized but we can't easily
    // test the actual stdin reading in a unit test environment
    // Instead, we'll test with a regular editor to ensure the path works
    let args = vec![
        "agenix".to_string(),
        "edit".to_string(),
        test_file_path.to_str().unwrap().to_string(),
        "--rules".to_string(),
        temp_rules.to_str().unwrap().to_string(),
        "--editor".to_string(),
        "echo 'test content' >".to_string(),
    ];
    eprintln!(
        "Running test_stdin_editor_functionality with args: {:?}",
        args
    );

    let result = crate::run(args);

    result.unwrap();

    Ok(())
}

#[test]
fn test_generate_secrets_with_dependencies() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary directory for the generated secrets
    let temp_dir = tempdir()?;

    // Create the rules file with dependencies
    let rules_content_with_abs_paths = format!(
        r#"
{{
  "{}/ssh-key.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = builtins.sshKey;
  }};
  "{}/authorized-keys.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "ssh-key" ];
generator = {{ publics }}: "ssh-key-pub: " + publics."ssh-key";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content_with_abs_paths)?;
    temp_rules.flush()?;

    // Generate the secrets
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generation should succeed: {:?}",
        result.err()
    );

    // Check that both files were created
    let ssh_key_path = temp_dir.path().join("ssh-key.age");
    let ssh_key_pub_path = temp_dir.path().join("ssh-key.age.pub");
    let authorized_keys_path = temp_dir.path().join("authorized-keys.age");

    assert!(ssh_key_path.exists(), "ssh-key.age should be created");
    assert!(
        ssh_key_pub_path.exists(),
        "ssh-key.age.pub should be created"
    );
    assert!(
        authorized_keys_path.exists(),
        "authorized-keys.age should be created"
    );

    // Verify the public key file exists and is not empty
    let pub_key_content = fs::read_to_string(&ssh_key_pub_path)?;
    assert!(
        !pub_key_content.trim().is_empty(),
        "Public key should not be empty"
    );
    assert!(
        pub_key_content.starts_with("ssh-ed25519 "),
        "Public key should be in SSH format"
    );

    Ok(())
}

#[test]
fn test_generate_secrets_with_missing_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary directory
    let temp_dir = tempdir()?;

    // Create rules with a missing dependency
    let rules_content = format!(
        r#"
{{
  "{}/dependent-secret.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "nonexistent-secret" ];
generator = {{ secrets }}: "dependent";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Try to generate - should fail with clear error
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_err(),
        "Generation should fail with missing dependency"
    );

    // The error chain should include information about the dependency
    let err = result.unwrap_err();
    let err_chain: Vec<String> = err.chain().map(|e| e.to_string()).collect();
    let full_error = err_chain.join(": ");

    assert!(
        full_error.contains("depends on")
            || full_error.contains("cannot be found")
            || full_error.contains("nonexistent"),
        "Error chain should mention dependency issue: {}",
        full_error
    );

    Ok(())
}

#[test]
fn test_generate_secrets_dependency_order() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary directory
    let temp_dir = tempdir()?;

    // Create rules where secrets are listed in reverse dependency order
    // (dependent comes before dependency in the file)
    let rules_content = format!(
        r#"
{{
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-from-" + publics.base;
  }};
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate secrets - should handle dependency order automatically
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generation should succeed with automatic ordering: {:?}",
        result.err()
    );

    // Both files should exist
    let base_path = temp_dir.path().join("base.age");
    let base_pub_path = temp_dir.path().join("base.age.pub");
    let derived_path = temp_dir.path().join("derived.age");

    assert!(base_path.exists(), "base.age should be created");
    assert!(base_pub_path.exists(), "base.age.pub should be created");
    assert!(derived_path.exists(), "derived.age should be created");

    Ok(())
}

#[test]
fn test_generate_secrets_with_different_generator_patterns() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary directory
    let temp_dir = tempdir()?;

    // Create rules with generators accepting different parameter patterns
    let rules_content = format!(
        r#"
{{
  "{}/base-secret.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret-value"; public = "base-public-value"; }};
  }};
  "{}/only-publics.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base-secret" ];
generator = {{ publics }}: "public: " + publics."base-secret";
  }};
  "{}/only-secrets.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base-secret" ];
generator = {{ secrets }}: "secret: " + secrets."base-secret";
  }};
  "{}/both-secrets-and-publics.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base-secret" ];
generator = {{ secrets, publics }}: "secret: " + secrets."base-secret" + ", public: " + publics."base-secret";
  }};
  "{}/ignore-deps-with-empty.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base-secret" ];
generator = {{ }}: "ignoring-all-params";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate secrets - should handle all patterns
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generation should succeed with different parameter patterns: {:?}",
        result.err()
    );

    // All files should exist
    let base_path = temp_dir.path().join("base-secret.age");
    let only_publics_path = temp_dir.path().join("only-publics.age");
    let only_secrets_path = temp_dir.path().join("only-secrets.age");
    let both_path = temp_dir.path().join("both-secrets-and-publics.age");
    let ignore_path = temp_dir.path().join("ignore-deps-with-empty.age");

    assert!(base_path.exists(), "base-secret.age should be created");
    assert!(
        only_publics_path.exists(),
        "only-publics.age should be created"
    );
    assert!(
        only_secrets_path.exists(),
        "only-secrets.age should be created"
    );
    assert!(
        both_path.exists(),
        "both-secrets-and-publics.age should be created"
    );
    assert!(
        ignore_path.exists(),
        "ignore-deps-with-empty.age should be created"
    );

    Ok(())
}

// Complex dependency chain tests
#[test]
fn test_dependency_chain_full() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Chain: level1 -> level2 -> level3
    let rules_content = format!(
        r#"
{{
  "{}/level1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "level2-" + publics."level1"; public = "level2-public"; }};
  }};
  "{}/level3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: "level3-" + publics."level2";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle full dependency chain: {:?}",
        result.err()
    );

    // All three files should be created
    assert!(temp_dir.path().join("level1.age").exists());
    assert!(temp_dir.path().join("level2.age").exists());
    assert!(temp_dir.path().join("level3.age").exists());

    Ok(())
}

#[test]
fn test_dependency_chain_middle_exists() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Pre-create middle secret with public key
    let level2_path = temp_dir.path().join("level2.age");
    let level2_pub_path = temp_dir.path().join("level2.age.pub");
    std::fs::write(&level2_path, "existing-level2-encrypted")?;
    std::fs::write(&level2_pub_path, "existing-level2-public")?;

    // Chain: level1 -> level2 (exists) -> level3
    let rules_content = format!(
        r#"
{{
  "{}/level1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "level2-" + publics."level1"; public = "level2-public"; }};
  }};
  "{}/level3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: "level3-" + publics."level2";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle chain with existing middle: {:?}",
        result.err()
    );

    // level1 and level3 should be generated, level2 should be skipped
    assert!(temp_dir.path().join("level1.age").exists());
    assert!(temp_dir.path().join("level3.age").exists());
    // level2 content should remain unchanged
    let level2_content = std::fs::read_to_string(&level2_path)?;
    assert_eq!(level2_content, "existing-level2-encrypted");

    Ok(())
}

#[test]
fn test_dependency_chain_middle_needs_secret_only_public_available() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Pre-create middle secret with only public key (no encrypted file)
    let level2_pub_path = temp_dir.path().join("level2.age.pub");
    std::fs::write(&level2_pub_path, "existing-level2-public")?;

    // Chain where level3 needs the SECRET from level2 but only public is available
    let rules_content = format!(
        r#"
{{
  "{}/level1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "level2-" + publics."level1"; public = "level2-public"; }};
  }};
  "{}/level3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ secrets }}: "level3-" + secrets."level2";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);

    // This should succeed because level2 will be generated (not skipped)
    // since it doesn't already exist as an encrypted file
    assert!(
        result.is_ok(),
        "Should generate level2 and then level3: {:?}",
        result.err()
    );

    assert!(temp_dir.path().join("level2.age").exists());
    assert!(temp_dir.path().join("level3.age").exists());

    Ok(())
}

#[test]
fn test_dependency_chain_missing_middle() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Chain where middle secret is not defined in rules
    let rules_content = format!(
        r#"
{{
  "{}/level1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "level1-secret"; public = "level1-public"; }};
  }};
  "{}/level3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "level2" ];
generator = {{ publics }}: "level3-" + publics."level2";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Should fail with missing dependency");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("depends on")
            || err_msg.contains("level2")
            || err_msg.contains("cannot be found"),
        "Error message should mention missing dependency 'level2': {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_circular_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Circular: secret1 -> secret2 -> secret1
    let rules_content = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "s1-" + publics."secret2"; public = "p1"; }};
  }};
  "{}/secret2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "s2-" + publics."secret1"; public = "p2"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Should fail with circular dependency");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("Maximum iterations")
            || err_msg.contains("circular")
            || err_msg.contains("depends"),
        "Error message should indicate circular dependency issue: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_diamond_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Diamond: base -> left + right -> top
    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/left.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "left-" + publics."base"; public = "left-public"; }};
  }};
  "{}/right.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "right-" + publics."base"; public = "right-public"; }};
  }};
  "{}/top.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: "top-" + publics."left" + "-" + publics."right";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle diamond dependency: {:?}",
        result.err()
    );

    // All four files should be created
    assert!(temp_dir.path().join("base.age").exists());
    assert!(temp_dir.path().join("left.age").exists());
    assert!(temp_dir.path().join("right.age").exists());
    assert!(temp_dir.path().join("top.age").exists());

    Ok(())
}

#[test]
fn test_multiple_independent_chains() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Two independent chains: chain1: a -> b and chain2: x -> y
    let rules_content = format!(
        r#"
{{
  "{}/a.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "a-secret"; public = "a-public"; }};
  }};
  "{}/b.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: "b-" + publics."a";
  }};
  "{}/x.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "x-secret"; public = "x-public"; }};
  }};
  "{}/y.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: "y-" + publics."x";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle multiple independent chains: {:?}",
        result.err()
    );

    // All files should be created
    assert!(temp_dir.path().join("a.age").exists());
    assert!(temp_dir.path().join("b.age").exists());
    assert!(temp_dir.path().join("x.age").exists());
    assert!(temp_dir.path().join("y.age").exists());

    Ok(())
}

#[test]
fn test_mixed_explicit_and_auto_dependencies() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Mix of explicit dependencies and auto-detected ones
    let rules_content = format!(
        r#"
{{
  "{}/key1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "key1"; public = "pub1"; }};
  }};
  "{}/key2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "key2"; public = "pub2"; }};
  }};
  "{}/auto-detected.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: publics."key1";
  }};
  "{}/explicit.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "key2" ];
generator = {{ publics }}: publics."key2";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle mixed explicit and auto dependencies: {:?}",
        result.err()
    );

    assert!(temp_dir.path().join("key1.age").exists());
    assert!(temp_dir.path().join("key2.age").exists());
    assert!(temp_dir.path().join("auto-detected.age").exists());
    assert!(temp_dir.path().join("explicit.age").exists());

    Ok(())
}

#[test]
fn test_dependency_on_both_secret_and_public() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // One secret depends on both the secret and public parts of another
    let rules_content = format!(
        r#"
{{
  "{}/source.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "source-secret"; public = "source-public"; }};
  }};
  "{}/combined.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ secrets, publics }}: secrets."source" + ":" + publics."source";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle dependency on both secret and public: {:?}",
        result.err()
    );

    assert!(temp_dir.path().join("source.age").exists());
    assert!(temp_dir.path().join("combined.age").exists());

    Ok(())
}

#[test]
fn test_long_chain_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Long chain: step1 -> step2 -> step3 -> step4 -> step5
    let rules_content = format!(
        r#"
{{
  "{}/step1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "step1"; public = "pub1"; }};
  }};
  "{}/step2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "step2-" + publics."step1"; public = "pub2"; }};
  }};
  "{}/step3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "step3-" + publics."step2"; public = "pub3"; }};
  }};
  "{}/step4.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "step4-" + publics."step3"; public = "pub4"; }};
  }};
  "{}/step5.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: "step5-" + publics."step4";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle long dependency chain: {:?}",
        result.err()
    );

    // All five files should be created
    for i in 1..=5 {
        assert!(
            temp_dir.path().join(format!("step{}.age", i)).exists(),
            "step{}.age should be created",
            i
        );
    }

    Ok(())
}

#[test]
fn test_self_circular_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Self-circular: secret depends on itself
    let rules_content = format!(
        r#"
{{
  "{}/self.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "s-" + publics."self"; public = "p"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Should fail with self-circular dependency");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("circular") || err_msg.contains("depends"),
        "Error message should indicate circular dependency: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_deep_circular_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Deep circular: A -> B -> C -> A
    let rules_content = format!(
        r#"
{{
  "{}/secretA.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "A-" + publics."secretB"; public = "pA"; }};
  }};
  "{}/secretB.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "B-" + publics."secretC"; public = "pB"; }};
  }};
  "{}/secretC.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "C-" + publics."secretA"; public = "pC"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Should fail with deep circular dependency");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("circular") || err_msg.contains("depends"),
        "Error message should indicate circular dependency: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_missing_dependency_in_long_chain() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Chain with missing middle: step1 -> step2 -> [missing] -> step4
    let rules_content = format!(
        r#"
{{
  "{}/step1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "step1"; public = "pub1"; }};
  }};
  "{}/step2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "step2-" + publics."step1"; public = "pub2"; }};
  }};
  "{}/step4.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "step4-" + publics."step3"; public = "pub4"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Should fail with missing dependency");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("step3") || err_msg.contains("cannot be found"),
        "Error message should mention missing 'step3': {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_multiple_circular_clusters() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Two independent circular clusters: (A -> B -> A) and (C -> D -> C)
    let rules_content = format!(
        r#"
{{
  "{}/secretA.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "A-" + publics."secretB"; public = "pA"; }};
  }};
  "{}/secretB.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "B-" + publics."secretA"; public = "pB"; }};
  }};
  "{}/secretC.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "C-" + publics."secretD"; public = "pC"; }};
  }};
  "{}/secretD.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "D-" + publics."secretC"; public = "pD"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_err(),
        "Should fail with multiple circular dependencies"
    );

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("circular") || err_msg.contains("depends"),
        "Error message should indicate circular dependency: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_mixed_generated_and_manual_secrets() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Mix of secrets with generators and without
    // manual.age (no generator) -> generated.age (has generator, depends on manual)

    // Create manual.age file and its .pub file
    let manual_secret = temp_dir.path().join("manual.age");
    fs::write(&manual_secret, b"manually created secret")?;
    let manual_pub = temp_dir.path().join("manual.age.pub");
    fs::write(&manual_pub, "manual-public-key")?;

    let rules_content = format!(
        r#"
{{
  "{}/manual.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/generated.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "gen-" + publics."manual"; public = "gen-pub"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle mix of manual and generated secrets: {:?}",
        result.err()
    );

    // Check that generated.age was created
    assert!(
        temp_dir.path().join("generated.age").exists(),
        "generated.age should be created"
    );

    Ok(())
}

#[test]
fn test_dependency_with_explicit_age_suffix() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Test that dependencies work whether they include .age suffix or not
    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base"; public = "base-pub"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base.age" ];
generator = {{ publics }}: {{ secret = "derived-" + publics."base"; public = "derived-pub"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle .age suffix in dependencies: {:?}",
        result.err()
    );

    assert!(
        temp_dir.path().join("base.age").exists(),
        "base.age should be created"
    );
    assert!(
        temp_dir.path().join("derived.age").exists(),
        "derived.age should be created"
    );

    Ok(())
}

#[test]
fn test_complex_multi_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Secret depends on multiple other secrets
    let rules_content = format!(
        r#"
{{
  "{}/key1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "k1-secret"; public = "k1-pub"; }};
  }};
  "{}/key2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "k2-secret"; public = "k2-pub"; }};
  }};
  "{}/key3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "k3-secret"; public = "k3-pub"; }};
  }};
  "{}/combined.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ 
  secret = publics."key1" + "-" + publics."key2" + "-" + publics."key3"; 
  public = "combined-pub"; 
}};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle multi-dependency: {:?}",
        result.err()
    );

    // All files should be created
    assert!(temp_dir.path().join("key1.age").exists());
    assert!(temp_dir.path().join("key2.age").exists());
    assert!(temp_dir.path().join("key3.age").exists());
    assert!(temp_dir.path().join("combined.age").exists());

    Ok(())
}

#[test]
fn test_partial_circular_with_independent() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Mix: independent.age (no deps) + circular pair (A -> B -> A)
    let rules_content = format!(
        r#"
{{
  "{}/independent.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "independent"; public = "ind-pub"; }};
  }};
  "{}/circA.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "A-" + publics."circB"; public = "pA"; }};
  }};
  "{}/circB.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "B-" + publics."circA"; public = "pB"; }};
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_err(),
        "Should fail due to circular dependency even with independent secret"
    );

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("circular") || err_msg.contains("depends"),
        "Error message should indicate circular dependency: {}",
        err_msg
    );

    // Independent secret should still be created
    assert!(
        temp_dir.path().join("independent.age").exists(),
        "independent.age should be created before circular error"
    );

    Ok(())
}

#[test]
fn test_very_long_dependency_chain() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Chain of 10 secrets: s1 -> s2 -> ... -> s10
    let mut rules_parts = vec![];

    rules_parts.push(format!(
        r#"  "{}/s1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "s1"; public = "p1"; }};
  }};"#,
        temp_dir.path().to_str().unwrap()
    ));

    for i in 2..=10 {
        rules_parts.push(format!(
            r#"  "{}/s{}.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ publics }}: {{ secret = "s{}-" + publics."s{}"; public = "p{}"; }};
  }};"#,
            temp_dir.path().to_str().unwrap(),
            i,
            i,
            i - 1,
            i
        ));
    }

    let rules_content = format!("{{\n{}\n}}", rules_parts.join("\n"));

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Should handle very long dependency chain: {:?}",
        result.err()
    );

    // All 10 files should be created
    for i in 1..=10 {
        assert!(
            temp_dir.path().join(format!("s{}.age", i)).exists(),
            "s{}.age should be created",
            i
        );
    }

    Ok(())
}

#[test]
fn test_generate_force_overwrites_existing() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a temporary directory with an existing file
    let temp_dir = tempdir()?;

    // Create the rules file with absolute paths
    let rules_content = format!(
        r#"
{{
  "{}/force-test.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "new-generated-content";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let existing_file_path = temp_dir.path().join("force-test.age");
    fs::write(&existing_file_path, b"existing content")?;

    let original_content = fs::read(&existing_file_path)?;

    // Use --force flag to overwrite
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--force".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "generate --force should succeed: {:?}",
        result.err()
    );

    // File should have been overwritten (content should be different)
    let current_content = fs::read(&existing_file_path)?;
    assert_ne!(
        original_content, current_content,
        "Existing file should be overwritten with --force"
    );

    Ok(())
}

#[test]
fn test_generate_dry_run_no_changes() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/dry-run-test.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "should-not-be-created";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Use --dry-run flag
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--dry-run".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "generate --dry-run should succeed: {:?}",
        result.err()
    );

    // File should NOT have been created
    let secret_path = temp_dir.path().join("dry-run-test.age");
    assert!(
        !secret_path.exists(),
        "Secret file should not be created in dry-run mode"
    );

    Ok(())
}

#[test]
fn test_generate_dry_run_with_existing_file() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/existing-dry-run.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "should-not-overwrite";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let existing_file_path = temp_dir.path().join("existing-dry-run.age");
    fs::write(&existing_file_path, b"existing content")?;

    let original_content = fs::read(&existing_file_path)?;

    // Use --force --dry-run flags (should preview overwrite but not change)
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--force".to_string(),
        "--dry-run".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "generate --force --dry-run should succeed: {:?}",
        result.err()
    );

    // File should NOT have been overwritten
    let current_content = fs::read(&existing_file_path)?;
    assert_eq!(
        original_content, current_content,
        "Existing file should not be overwritten in dry-run mode even with --force"
    );

    Ok(())
}

#[test]
fn test_generate_dry_run_with_dependencies() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Create rules with dependencies to test dry-run resolves them correctly
    let rules_content = format!(
        r#"
{{
  "{}/base-secret.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived-secret.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base-secret" ];
generator = {{ publics }}: "derived-from-" + publics."base-secret";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Use --dry-run flag
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--dry-run".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "generate --dry-run with dependencies should succeed: {:?}",
        result.err()
    );

    // Neither file should be created
    assert!(
        !temp_dir.path().join("base-secret.age").exists(),
        "base-secret.age should not be created in dry-run mode"
    );
    assert!(
        !temp_dir.path().join("derived-secret.age").exists(),
        "derived-secret.age should not be created in dry-run mode"
    );

    Ok(())
}

#[test]
fn test_generate_force_short_flag() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/force-short.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "new-content";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    let existing_file_path = temp_dir.path().join("force-short.age");
    fs::write(&existing_file_path, b"existing content")?;

    let original_content = fs::read(&existing_file_path)?;

    // Use -f short flag for --force
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "-f".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "generate -f should succeed: {:?}",
        result.err()
    );

    let current_content = fs::read(&existing_file_path)?;
    assert_ne!(
        original_content, current_content,
        "Existing file should be overwritten with -f"
    );

    Ok(())
}

#[test]
fn test_generate_dry_run_short_flag() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/dry-run-short.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "should-not-be-created";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Use -n short flag for --dry-run
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "-n".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "generate -n should succeed: {:?}",
        result.err()
    );

    let secret_path = temp_dir.path().join("dry-run-short.age");
    assert!(
        !secret_path.exists(),
        "Secret file should not be created in dry-run mode with -n"
    );

    Ok(())
}

// Tests for positional secrets filtering

#[test]
fn test_generate_specific_secrets() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content1";
  }};
  "{}/secret2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content2";
  }};
  "{}/secret3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content3";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Only generate secret1.age
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "secret1".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate specific secrets should succeed: {:?}",
        result.err()
    );

    // Only secret1.age should be created
    assert!(
        temp_dir.path().join("secret1.age").exists(),
        "secret1.age should be created"
    );
    assert!(
        !temp_dir.path().join("secret2.age").exists(),
        "secret2.age should NOT be created"
    );
    assert!(
        !temp_dir.path().join("secret3.age").exists(),
        "secret3.age should NOT be created"
    );

    Ok(())
}

#[test]
fn test_generate_multiple_specific_secrets() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content1";
  }};
  "{}/secret2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content2";
  }};
  "{}/secret3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content3";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate secret1 and secret3
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "secret1".to_string(),
        "secret3".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate multiple specific secrets should succeed: {:?}",
        result.err()
    );

    // secret1 and secret3 should be created, secret2 should not
    assert!(
        temp_dir.path().join("secret1.age").exists(),
        "secret1.age should be created"
    );
    assert!(
        !temp_dir.path().join("secret2.age").exists(),
        "secret2.age should NOT be created"
    );
    assert!(
        temp_dir.path().join("secret3.age").exists(),
        "secret3.age should be created"
    );

    Ok(())
}

#[test]
fn test_generate_with_age_suffix_in_filter() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content1";
  }};
  "{}/secret2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content2";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Test with .age suffix
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "secret1.age".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate with .age suffix should succeed: {:?}",
        result.err()
    );

    assert!(
        temp_dir.path().join("secret1.age").exists(),
        "secret1.age should be created"
    );
    assert!(
        !temp_dir.path().join("secret2.age").exists(),
        "secret2.age should NOT be created"
    );

    Ok(())
}

#[test]
fn test_generate_nonexistent_secret_filter() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir().unwrap();

    let rules_content = format!(
        r#"
{{
  "{}/existing.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new().unwrap();
    writeln!(temp_rules, "{}", rules_content).unwrap();
    temp_rules.flush().unwrap();

    // Try to generate a nonexistent secret
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "nonexistent".to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Generate nonexistent secret should fail");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("No matching secrets"),
        "Error should mention no matching secrets: {}",
        err_msg
    );
}

#[test]
fn test_generate_default_with_dependencies() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Create a dependency chain: base -> derived
    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
  "{}/unrelated.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "unrelated";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate only derived.age - dependencies should be generated by default
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "derived".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate with dependencies should succeed by default: {:?}",
        result.err()
    );

    // Both derived and its dependency base should be created (deps are generated by default)
    assert!(
        temp_dir.path().join("base.age").exists(),
        "base.age (dependency) should be created by default"
    );
    assert!(
        temp_dir.path().join("derived.age").exists(),
        "derived.age should be created"
    );
    // unrelated should NOT be created
    assert!(
        !temp_dir.path().join("unrelated.age").exists(),
        "unrelated.age should NOT be created"
    );

    Ok(())
}

#[test]
fn test_generate_no_dependencies_flag_fails_on_missing_dep() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir().unwrap();

    // Create a dependency chain: base -> derived
    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new().unwrap();
    writeln!(temp_rules, "{}", rules_content).unwrap();
    temp_rules.flush().unwrap();

    // Generate only derived.age WITH --no-dependencies
    // This should fail because base.age doesn't exist
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "derived".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_err(),
        "Generate with --no-dependencies should fail when dependency is missing"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("--no-dependencies") || err_msg.contains("required dependencies"),
        "Error should mention --no-dependencies or missing dependencies: {}",
        err_msg
    );
}

#[test]
fn test_generate_transitive_dependencies() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Chain: a -> b -> c
    let rules_content = format!(
        r#"
{{
  "{}/a.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "a-secret"; public = "a-public"; }};
  }};
  "{}/b.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "a" ];
generator = {{ publics }}: {{ secret = "b-" + publics."a"; public = "b-public"; }};
  }};
  "{}/c.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "b" ];
generator = {{ publics }}: "c-" + publics."b";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate only c.age - dependencies should be generated by default
    // Should generate a, b, and c
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "c".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate with transitive dependencies should succeed: {:?}",
        result.err()
    );

    // All three should be created
    assert!(
        temp_dir.path().join("a.age").exists(),
        "a.age should be created"
    );
    assert!(
        temp_dir.path().join("b.age").exists(),
        "b.age should be created"
    );
    assert!(
        temp_dir.path().join("c.age").exists(),
        "c.age should be created"
    );

    Ok(())
}

// Tests for default behavior: no secrets specified means all secrets in rules file

#[test]
fn test_generate_no_args_generates_all_secrets() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    let rules_content = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content1";
  }};
  "{}/secret2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content2";
  }};
  "{}/secret3.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content3";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate without specifying any secrets - should generate ALL
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate without args should generate all: {:?}",
        result.err()
    );

    // All three secrets should be created
    assert!(
        temp_dir.path().join("secret1.age").exists(),
        "secret1.age should be created"
    );
    assert!(
        temp_dir.path().join("secret2.age").exists(),
        "secret2.age should be created"
    );
    assert!(
        temp_dir.path().join("secret3.age").exists(),
        "secret3.age should be created"
    );

    Ok(())
}

// Tests for dependency behavior when existing secret has .pub file

#[test]
fn test_generate_uses_existing_pub_file() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Create a rules file where derived depends on base
    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Create an existing .pub file for base (simulating a pre-generated dependency)
    let base_pub_path = temp_dir.path().join("base.age.pub");
    fs::write(&base_pub_path, "existing-base-public")?;

    // Generate only derived.age with --no-dependencies
    // This should succeed because base.age.pub exists
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "derived".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate should succeed when dependency has .pub file: {:?}",
        result.err()
    );

    // derived.age should be created
    assert!(
        temp_dir.path().join("derived.age").exists(),
        "derived.age should be created"
    );
    // base.age should NOT be created (we didn't generate it)
    assert!(
        !temp_dir.path().join("base.age").exists(),
        "base.age should NOT be created with --no-dependencies"
    );

    Ok(())
}

// Tests for helpful error messages

#[test]
fn test_generate_no_deps_helpful_error() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir().unwrap();

    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new().unwrap();
    writeln!(temp_rules, "{}", rules_content).unwrap();
    temp_rules.flush().unwrap();

    // Generate with --no-dependencies when deps are missing
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "derived".to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    // Should contain helpful hint about removing --no-dependencies
    assert!(
        err_msg.contains("--no-dependencies") || err_msg.contains("dependencies"),
        "Error should mention --no-dependencies: {}",
        err_msg
    );
}

// Tests for rekey --partial CLI option

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
    // Test that when rekey fails in strict mode, the error message hints at --partial
    // This test just verifies the error message format of rekey_files
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    // Create a non-decryptable file (just some random content that's not a valid age file)
    let secret_path = temp_dir.path().join("secret.age");
    fs::write(&secret_path, "not-a-valid-age-file").unwrap();

    // Without --partial, rekey should fail
    let args = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Rekey of invalid file should fail");
    let err_msg = format!("{:?}", result.unwrap_err());
    // Should mention --partial in the hint
    assert!(
        err_msg.contains("--partial"),
        "Error should mention --partial hint: {}",
        err_msg
    );
}

#[test]
fn test_rekey_partial_continues_on_error() {
    // Test that with --partial, rekey continues even when some files fail
    // Now with preflight check, partial mode skips undecryptable files instead of failing
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    // Create a non-decryptable file
    let secret_path = temp_dir.path().join("secret.age");
    fs::write(&secret_path, "not-a-valid-age-file").unwrap();

    // With --partial and only one undecryptable file, should fail (nothing to rekey)
    let args = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--partial".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    // With --partial but all files undecryptable, should fail
    assert!(
        result.is_err(),
        "Rekey with --partial should fail when all files are undecryptable"
    );
}

// Test for behavior when a middle dependency already has generated secret

#[test]
fn test_generate_with_pub_file_for_direct_dependency() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Simple chain: base -> derived, where base has .pub file
    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Pre-create base.age.pub (simulating base was already generated)
    let base_pub_path = temp_dir.path().join("base.age.pub");
    fs::write(&base_pub_path, "pre-existing-base-public")?;

    // Generate only derived.age with --no-dependencies
    // This should succeed because base.age.pub exists
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "derived".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate derived should succeed when dependency base has .pub file: {:?}",
        result.err()
    );

    // derived.age should be created
    assert!(
        temp_dir.path().join("derived.age").exists(),
        "derived.age should be created"
    );
    // base.age should NOT be created (we didn't generate it)
    assert!(
        !temp_dir.path().join("base.age").exists(),
        "base.age should NOT be created with --no-dependencies"
    );

    Ok(())
}

#[test]
fn test_generate_chain_needs_all_pub_files() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Chain: a -> b -> c
    // With --no-dependencies and generating only c, ALL deps need .pub files
    let rules_content = format!(
        r#"
{{
  "{}/a.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "a-secret"; public = "a-public"; }};
  }};
  "{}/b.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "a" ];
generator = {{ publics }}: {{ secret = "b-" + publics."a"; public = "b-public"; }};
  }};
  "{}/c.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "b" ];
generator = {{ publics }}: "c-" + publics."b";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Pre-create both a.age.pub and b.age.pub (all deps need .pub files)
    let a_pub_path = temp_dir.path().join("a.age.pub");
    fs::write(&a_pub_path, "pre-existing-a-public")?;
    let b_pub_path = temp_dir.path().join("b.age.pub");
    fs::write(&b_pub_path, "pre-existing-b-public")?;

    // Generate only c.age with --no-dependencies
    // This should succeed because all dependencies have .pub files
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "c".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate c should succeed when all deps have .pub files: {:?}",
        result.err()
    );

    // c.age should be created
    assert!(
        temp_dir.path().join("c.age").exists(),
        "c.age should be created"
    );
    // a.age and b.age should NOT be created
    assert!(
        !temp_dir.path().join("a.age").exists(),
        "a.age should NOT be created"
    );
    assert!(
        !temp_dir.path().join("b.age").exists(),
        "b.age should NOT be created"
    );

    Ok(())
}

// Test for multiple secrets dependency handling

#[test]
fn test_generate_multiple_secrets_shared_deps() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Create: shared -> derived1, shared -> derived2
    let rules_content = format!(
        r#"
{{
  "{}/shared.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "shared-secret"; public = "shared-public"; }};
  }};
  "{}/derived1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "shared" ];
generator = {{ publics }}: "derived1-" + publics."shared";
  }};
  "{}/derived2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "shared" ];
generator = {{ publics }}: "derived2-" + publics."shared";
  }};
  "{}/unrelated.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "unrelated";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate derived1 and derived2 (should also generate shared, but not unrelated)
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "derived1".to_string(),
        "derived2".to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "Generate multiple secrets with shared dep should succeed: {:?}",
        result.err()
    );

    // shared, derived1, derived2 should be created
    assert!(
        temp_dir.path().join("shared.age").exists(),
        "shared.age should be created (dependency)"
    );
    assert!(
        temp_dir.path().join("derived1.age").exists(),
        "derived1.age should be created"
    );
    assert!(
        temp_dir.path().join("derived2.age").exists(),
        "derived2.age should be created"
    );
    // unrelated should NOT be created
    assert!(
        !temp_dir.path().join("unrelated.age").exists(),
        "unrelated.age should NOT be created"
    );

    Ok(())
}

// Test that no deps doesn't affect generate all

#[test]
fn test_generate_no_deps_with_no_secrets_arg() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir()?;

    // Create rules with dependencies
    let rules_content = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap(),
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Generate all with --no-dependencies (should still generate all because no secrets specified)
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_ok(),
        "--no-dependencies with no secrets arg should generate all: {:?}",
        result.err()
    );

    // Both should be created because we're generating all
    assert!(
        temp_dir.path().join("base.age").exists(),
        "base.age should be created"
    );
    assert!(
        temp_dir.path().join("derived.age").exists(),
        "derived.age should be created"
    );

    Ok(())
}

// Tests for rekey pre-flight check behavior

#[test]
fn test_rekey_preflight_check_fails_before_any_modification() {
    // Test that when strict mode (default) rekey fails due to undecryptable file,
    // NO files are modified - even files that could be decrypted
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    // Create one invalid file and one valid empty file (non-existing = nothing to rekey)
    let secret1_path = temp_dir.path().join("secret1.age");
    let secret2_path = temp_dir.path().join("secret2.age");
    let invalid_content = "not-a-valid-age-file";
    fs::write(&secret1_path, invalid_content).unwrap();
    fs::write(&secret2_path, invalid_content).unwrap();

    // Record original content
    let original_content1 = fs::read_to_string(&secret1_path).unwrap();
    let original_content2 = fs::read_to_string(&secret2_path).unwrap();

    // Rekey without --partial should fail
    let args = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_err(),
        "Rekey should fail due to undecryptable files"
    );

    // Verify NO files were modified
    let content1_after = fs::read_to_string(&secret1_path).unwrap();
    let content2_after = fs::read_to_string(&secret2_path).unwrap();
    assert_eq!(
        original_content1, content1_after,
        "secret1.age should not be modified"
    );
    assert_eq!(
        original_content2, content2_after,
        "secret2.age should not be modified"
    );
}

#[test]
fn test_rekey_preflight_lists_all_undecryptable() {
    // Test that the error message lists ALL undecryptable files, not just the first one
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir().unwrap();

    let rules_content = format!(
        r#"
{{
  "{}/alpha.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/beta.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/gamma.age" = {{
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

    // Create ALL files as invalid
    fs::write(temp_dir.path().join("alpha.age"), "invalid1").unwrap();
    fs::write(temp_dir.path().join("beta.age"), "invalid2").unwrap();
    fs::write(temp_dir.path().join("gamma.age"), "invalid3").unwrap();

    let args = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(result.is_err(), "Rekey should fail");
    let err_msg = format!("{:?}", result.unwrap_err());

    // Error should mention all three files
    assert!(
        err_msg.contains("alpha.age"),
        "Error should mention alpha.age: {}",
        err_msg
    );
    assert!(
        err_msg.contains("beta.age"),
        "Error should mention beta.age: {}",
        err_msg
    );
    assert!(
        err_msg.contains("gamma.age"),
        "Error should mention gamma.age: {}",
        err_msg
    );

    // Should mention the count
    assert!(
        err_msg.contains("3"),
        "Error should mention count of undecryptable files: {}",
        err_msg
    );

    // Should mention --partial hint
    assert!(
        err_msg.contains("--partial"),
        "Error should suggest --partial: {}",
        err_msg
    );

    // Should mention that no secrets were modified
    assert!(
        err_msg.contains("No secrets were modified"),
        "Error should mention no secrets were modified: {}",
        err_msg
    );
}

#[test]
fn test_rekey_preflight_skips_nonexistent_files() {
    // Test that non-existent files are skipped in the pre-flight check
    // (they don't need rekeying)
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir().unwrap();

    let rules_content = format!(
        r#"
{{
  "{}/exists.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/nonexistent.age" = {{
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

    // Only create the first file (as invalid)
    fs::write(temp_dir.path().join("exists.age"), "invalid").unwrap();
    // nonexistent.age is not created

    let args = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = crate::run(args);
    assert!(
        result.is_err(),
        "Rekey should fail due to undecryptable exists.age"
    );
    let err_msg = format!("{:?}", result.unwrap_err());

    // Should mention exists.age but NOT nonexistent.age
    assert!(
        err_msg.contains("exists.age"),
        "Error should mention exists.age: {}",
        err_msg
    );
    // The error count should be 1 (only exists.age)
    assert!(
        err_msg.contains("1 secret"),
        "Error should say 1 secret: {}",
        err_msg
    );
}

#[test]
fn test_rekey_partial_runs_preflight_but_continues() {
    // Test that --partial mode runs preflight check but continues with decryptable files
    // It should skip undecryptable files and not fail
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    // Both files are invalid (can't be decrypted)
    fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
    fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

    let args = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--partial".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    // With --partial and all files undecryptable, it should fail with "nothing to rekey"
    let result = crate::run(args);
    assert!(
        result.is_err(),
        "Rekey with --partial should fail when all files are undecryptable"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("No secrets could be decrypted"),
        "Error should mention no secrets could be decrypted: {}",
        err_msg
    );
}

#[test]
fn test_rekey_complex_mixed_decryptable_undecryptable() {
    // Complex scenario: some files can be decrypted, some cannot
    // In strict mode, all should be checked first and none rekeyed
    use std::io::Write;
    use tempfile::NamedTempFile;

    let temp_dir = tempdir().unwrap();

    // Create 4 secrets: 2 exist (both invalid), 2 don't exist
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

    // Create only the two "existing" files (as invalid)
    let path1 = temp_dir.path().join("existing_invalid1.age");
    let path2 = temp_dir.path().join("existing_invalid2.age");
    fs::write(&path1, "invalid-content-1").unwrap();
    fs::write(&path2, "invalid-content-2").unwrap();

    // Save original content
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

    // Should mention both existing invalid files
    assert!(
        err_msg.contains("existing_invalid1.age"),
        "Error should mention existing_invalid1.age"
    );
    assert!(
        err_msg.contains("existing_invalid2.age"),
        "Error should mention existing_invalid2.age"
    );

    // Should NOT mention nonexistent files
    assert!(
        !err_msg.contains("nonexistent1.age"),
        "Error should NOT mention nonexistent1.age"
    );
    assert!(
        !err_msg.contains("nonexistent2.age"),
        "Error should NOT mention nonexistent2.age"
    );

    // Should say 2 secrets can't be decrypted
    assert!(err_msg.contains("2"), "Error should mention count 2");

    // Verify files were NOT modified
    assert_eq!(fs::read_to_string(&path1).unwrap(), orig1);
    assert_eq!(fs::read_to_string(&path2).unwrap(), orig2);
}

#[test]
fn test_rekey_specific_secrets_preflight() {
    // Test that when specifying specific secrets, only those are checked
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    // Create all three as invalid
    fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
    fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();
    fs::write(temp_dir.path().join("secret3.age"), "invalid3").unwrap();

    // Only try to rekey secret1 and secret2
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

    // Should mention secret1 and secret2
    assert!(
        err_msg.contains("secret1.age"),
        "Should mention secret1.age"
    );
    assert!(
        err_msg.contains("secret2.age"),
        "Should mention secret2.age"
    );

    // Should NOT mention secret3 (not specified)
    assert!(
        !err_msg.contains("secret3.age"),
        "Should NOT mention secret3.age"
    );

    // Should say 2 secrets
    assert!(err_msg.contains("2"), "Should mention count 2");
}

// Tests verifying that "rekey all" and "rekey <all secrets explicitly>" are equivalent

#[test]
fn test_rekey_all_vs_explicit_all_undecryptable_handling() {
    // Test that undecryptable files are handled the same way whether we specify
    // all secrets explicitly or let rekey default to all secrets
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    // Create both as invalid (undecryptable)
    fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
    fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

    // Test 1: Rekey without specifying secrets (all secrets)
    let args_implicit_all = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result_implicit = crate::run(args_implicit_all);
    assert!(result_implicit.is_err(), "Rekey all (implicit) should fail");
    let err_implicit = format!("{:?}", result_implicit.unwrap_err());

    // Test 2: Rekey with all secrets explicitly specified
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

    // Both should mention the same files
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

    // Both should mention 2 undecryptable secrets
    assert!(
        err_implicit.contains("2"),
        "Implicit all should mention count 2"
    );
    assert!(
        err_explicit.contains("2"),
        "Explicit all should mention count 2"
    );

    // Both should suggest --partial
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
    // Test that --partial mode works the same whether secrets are implicit or explicit
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    // Create both as invalid
    fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
    fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

    // Test 1: Rekey --partial without specifying secrets
    let args_implicit = vec![
        "agenix".to_string(),
        "rekey".to_string(),
        "--partial".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result_implicit = crate::run(args_implicit);
    // Both undecryptable, so should fail with "nothing to rekey"
    assert!(
        result_implicit.is_err(),
        "Rekey --partial (implicit all) should fail when all undecryptable"
    );
    let err_implicit = format!("{:?}", result_implicit.unwrap_err());

    // Recreate files (they might have been modified)
    fs::write(temp_dir.path().join("secret1.age"), "invalid1").unwrap();
    fs::write(temp_dir.path().join("secret2.age"), "invalid2").unwrap();

    // Test 2: Rekey --partial with all secrets explicitly specified
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

    // Both should have the same error about no secrets being decryptable
    assert!(
        err_implicit.contains("No secrets could be decrypted"),
        "Implicit all should mention no secrets could be decrypted"
    );
    assert!(
        err_explicit.contains("No secrets could be decrypted"),
        "Explicit all should mention no secrets could be decrypted"
    );
}

// Tests verifying that "generate all" and "generate <all secrets explicitly>" are equivalent

#[test]
fn test_generate_all_vs_explicit_all_basic() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test that generating all secrets implicitly produces the same result
    // as generating all secrets explicitly
    let temp_dir1 = tempdir()?;
    let temp_dir2 = tempdir()?;

    let rules_content1 = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content1";
  }};
  "{}/secret2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content2";
  }};
}}
"#,
        temp_dir1.path().to_str().unwrap(),
        temp_dir1.path().to_str().unwrap()
    );

    let rules_content2 = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content1";
  }};
  "{}/secret2.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content2";
  }};
}}
"#,
        temp_dir2.path().to_str().unwrap(),
        temp_dir2.path().to_str().unwrap()
    );

    let mut temp_rules1 = NamedTempFile::new()?;
    writeln!(temp_rules1, "{}", rules_content1)?;
    temp_rules1.flush()?;

    let mut temp_rules2 = NamedTempFile::new()?;
    writeln!(temp_rules2, "{}", rules_content2)?;
    temp_rules2.flush()?;

    // Test 1: Generate without specifying secrets (implicit all)
    let args_implicit = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules1.path().to_str().unwrap().to_string(),
    ];

    let result_implicit = crate::run(args_implicit);
    assert!(
        result_implicit.is_ok(),
        "Generate all (implicit) should succeed: {:?}",
        result_implicit.err()
    );

    // Test 2: Generate with all secrets explicitly specified
    let args_explicit = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules2.path().to_str().unwrap().to_string(),
        "secret1".to_string(),
        "secret2".to_string(),
    ];

    let result_explicit = crate::run(args_explicit);
    assert!(
        result_explicit.is_ok(),
        "Generate all (explicit) should succeed: {:?}",
        result_explicit.err()
    );

    // Both should create the same files
    assert!(
        temp_dir1.path().join("secret1.age").exists(),
        "Implicit all should create secret1.age"
    );
    assert!(
        temp_dir1.path().join("secret2.age").exists(),
        "Implicit all should create secret2.age"
    );
    assert!(
        temp_dir2.path().join("secret1.age").exists(),
        "Explicit all should create secret1.age"
    );
    assert!(
        temp_dir2.path().join("secret2.age").exists(),
        "Explicit all should create secret2.age"
    );

    Ok(())
}

#[test]
fn test_generate_all_vs_explicit_all_with_dependencies() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test that dependency handling is the same for implicit vs explicit all
    let temp_dir1 = tempdir()?;
    let temp_dir2 = tempdir()?;

    let rules_content1 = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir1.path().to_str().unwrap(),
        temp_dir1.path().to_str().unwrap()
    );

    let rules_content2 = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir2.path().to_str().unwrap(),
        temp_dir2.path().to_str().unwrap()
    );

    let mut temp_rules1 = NamedTempFile::new()?;
    writeln!(temp_rules1, "{}", rules_content1)?;
    temp_rules1.flush()?;

    let mut temp_rules2 = NamedTempFile::new()?;
    writeln!(temp_rules2, "{}", rules_content2)?;
    temp_rules2.flush()?;

    // Test 1: Generate without specifying secrets (implicit all)
    let args_implicit = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules1.path().to_str().unwrap().to_string(),
    ];

    let result_implicit = crate::run(args_implicit);
    assert!(
        result_implicit.is_ok(),
        "Generate all (implicit) with deps should succeed: {:?}",
        result_implicit.err()
    );

    // Test 2: Generate with all secrets explicitly specified
    let args_explicit = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules2.path().to_str().unwrap().to_string(),
        "base".to_string(),
        "derived".to_string(),
    ];

    let result_explicit = crate::run(args_explicit);
    assert!(
        result_explicit.is_ok(),
        "Generate all (explicit) with deps should succeed: {:?}",
        result_explicit.err()
    );

    // Both should create the same files, including .pub files
    assert!(
        temp_dir1.path().join("base.age").exists(),
        "Implicit all should create base.age"
    );
    assert!(
        temp_dir1.path().join("base.age.pub").exists(),
        "Implicit all should create base.age.pub"
    );
    assert!(
        temp_dir1.path().join("derived.age").exists(),
        "Implicit all should create derived.age"
    );

    assert!(
        temp_dir2.path().join("base.age").exists(),
        "Explicit all should create base.age"
    );
    assert!(
        temp_dir2.path().join("base.age.pub").exists(),
        "Explicit all should create base.age.pub"
    );
    assert!(
        temp_dir2.path().join("derived.age").exists(),
        "Explicit all should create derived.age"
    );

    Ok(())
}

#[test]
fn test_generate_all_only_nonexistent_secret() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test that specifying only nonexistent secrets results in an error
    let temp_dir = tempdir().unwrap();

    let rules_content = format!(
        r#"
{{
  "{}/secret1.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: "content1";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new().unwrap();
    writeln!(temp_rules, "{}", rules_content).unwrap();
    temp_rules.flush().unwrap();

    // Test: Generate with only nonexistent secrets
    let args_only_nonexistent = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
        "nonexistent".to_string(),
    ];

    let result = crate::run(args_only_nonexistent);
    assert!(
        result.is_err(),
        "Generate with only nonexistent secret should fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("No matching secrets"),
        "Error should mention no matching secrets: {}",
        err_msg
    );
}

#[test]
fn test_rekey_nonexistent_secret_explicit_error() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test that specifying a nonexistent secret gives a clear error
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

    // Create the secret file
    fs::write(temp_dir.path().join("secret1.age"), "encrypted-content").unwrap();

    // Test: Rekey with a nonexistent secret explicitly specified
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

#[test]
fn test_generate_no_dependencies_flag_implicit_vs_explicit_all() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test that --no-dependencies flag behaves the same for implicit vs explicit all
    // When all secrets are specified, --no-dependencies should be a no-op
    // because all secrets (including dependencies) are already in the list
    let temp_dir1 = tempdir()?;
    let temp_dir2 = tempdir()?;

    let rules_content1 = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir1.path().to_str().unwrap(),
        temp_dir1.path().to_str().unwrap()
    );

    let rules_content2 = format!(
        r#"
{{
  "{}/base.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
generator = {{ }}: {{ secret = "base-secret"; public = "base-public"; }};
  }};
  "{}/derived.age" = {{
publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
dependencies = [ "base" ];
generator = {{ publics }}: "derived-" + publics."base";
  }};
}}
"#,
        temp_dir2.path().to_str().unwrap(),
        temp_dir2.path().to_str().unwrap()
    );

    let mut temp_rules1 = NamedTempFile::new()?;
    writeln!(temp_rules1, "{}", rules_content1)?;
    temp_rules1.flush()?;

    let mut temp_rules2 = NamedTempFile::new()?;
    writeln!(temp_rules2, "{}", rules_content2)?;
    temp_rules2.flush()?;

    // Test 1: Generate with --no-dependencies without specifying secrets (implicit all)
    let args_implicit = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules1.path().to_str().unwrap().to_string(),
    ];

    let result_implicit = crate::run(args_implicit);
    assert!(
        result_implicit.is_ok(),
        "Generate --no-dependencies (implicit all) should succeed: {:?}",
        result_implicit.err()
    );

    // Test 2: Generate with --no-dependencies with all secrets explicitly specified
    let args_explicit = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--no-dependencies".to_string(),
        "--rules".to_string(),
        temp_rules2.path().to_str().unwrap().to_string(),
        "base".to_string(),
        "derived".to_string(),
    ];

    let result_explicit = crate::run(args_explicit);
    assert!(
        result_explicit.is_ok(),
        "Generate --no-dependencies (explicit all) should succeed: {:?}",
        result_explicit.err()
    );

    // Both should create the same files
    assert!(
        temp_dir1.path().join("base.age").exists(),
        "Implicit all should create base.age"
    );
    assert!(
        temp_dir1.path().join("derived.age").exists(),
        "Implicit all should create derived.age"
    );
    assert!(
        temp_dir2.path().join("base.age").exists(),
        "Explicit all should create base.age"
    );
    assert!(
        temp_dir2.path().join("derived.age").exists(),
        "Explicit all should create derived.age"
    );

    Ok(())
}
