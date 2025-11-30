use anyhow::Result;
use std::fs;
use std::io::Write;
use tempfile::{NamedTempFile, tempdir};

#[test]
fn test_simple_generate() -> Result<()> {
    // Create a temporary directory for the generated secrets
    let temp_dir = tempdir()?;

    // Create a secrets.nix with absolute paths to avoid race conditions
    let rules_content = format!(
        r#"
{{
  "{}/test-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "simple-test";
  }};
}}
"#,
        temp_dir.path().to_str().unwrap()
    );

    let mut temp_rules = NamedTempFile::new()?;
    writeln!(temp_rules, "{}", rules_content)?;
    temp_rules.flush()?;

    // Use the CLI interface via the run function with subcommand
    let args = vec![
        "agenix".to_string(),
        "generate".to_string(),
        "--secrets-nix".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = agenix::run(args);

    // Should succeed
    assert!(
        result.is_ok(),
        "CLI generate should succeed: {:?}",
        result.err()
    );

    // Check that the file was created
    let test_secret_path = temp_dir.path().join("test-secret.age");
    assert!(
        test_secret_path.exists(),
        "test-secret.age should be created"
    );

    // Verify the file is not empty (it contains encrypted data)
    let content = fs::read(&test_secret_path)?;
    assert!(!content.is_empty(), "test-secret.age should not be empty");

    Ok(())
}
