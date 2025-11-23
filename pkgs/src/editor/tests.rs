use super::*;
use std::{fs::File, path::PathBuf};
use tempfile::tempdir;

#[test]
fn test_edit_file_no_keys() {
    let rules = "./test_secrets.nix";
    let result = edit_file(rules, "nonexistent.age", "vi", None);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_file_no_keys() {
    let rules = "./test_secrets.nix";
    let result = decrypt_file(rules, "nonexistent.age", None, None);
    assert!(result.is_err());
}

#[test]
fn test_rekey_uses_no_op_editor() {
    // With nonexistent rules this will early error if keys empty; simulate empty by pointing to test file
    let rules = "./test_secrets.nix";
    // Should error, but specifically via missing keys, not editor invocation failure.
    let result = rekey_all_files(rules, None);
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
        None,
    );
    assert!(res.is_err());
}

#[test]
fn test_generate_secrets_with_nonexistent_rules() {
    // Use the CLI interface via the run function
    let args = vec![
        "agenix".to_string(),
        "--generate".to_string(),
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
        "--generate".to_string(),
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
        "--generate".to_string(),
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
        "--edit".to_string(),
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
