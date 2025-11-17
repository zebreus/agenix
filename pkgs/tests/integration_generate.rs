use anyhow::Result;
use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::{NamedTempFile, tempdir};

fn have(bin: &str) -> bool {
    Command::new(bin).arg("--version").output().is_ok()
}

#[test]
fn test_generate_cli_flag_parsing() {
    // Test that the generate flag is parsed correctly (should error due to missing rules)
    let args = vec![
        "agenix".to_string(),
        "--generate".to_string(),
        "--rules".to_string(),
        "./nonexistent.nix".to_string(),
    ];

    let result = agenix::run(args);
    // Should error because the rules file doesn't exist, but the flag should be parsed correctly
    assert!(result.is_err());

    // Also test short flag
    let args = vec![
        "agenix".to_string(),
        "-g".to_string(),
        "--rules".to_string(),
        "./nonexistent.nix".to_string(),
    ];

    let result = agenix::run(args);
    assert!(result.is_err());
}

#[test]
fn test_generate_creates_files_with_correct_content() -> Result<()> {
    // Skip if nix-instantiate is not available
    if !have("nix-instantiate") {
        eprintln!("skipping integration test: missing nix-instantiate");
        return Ok(());
    }

    // Create a temporary directory for the generated secrets
    let temp_dir = tempdir()?;

    // Create a temporary rules file with different types of generators using absolute paths
    let rules_content = format!(
        r#"
{{
  "{}/fixed-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "fixed-password-123";
  }};
  "{}/random-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: builtins.randomString 32;
  }};
  "{}/no-generator.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
  }};
  "{}/both-types-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "prefix-" + builtins.randomString 8 + "-suffix";
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

    // Test the CLI interface without changing directories (thread-safe)
    let args = vec![
        "agenix".to_string(),
        "--generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = agenix::run(args.clone());

    // Check files exist using absolute paths
    let fixed_secret_path = temp_dir.path().join("fixed-secret.age");
    let random_secret_path = temp_dir.path().join("random-secret.age");
    let no_generator_path = temp_dir.path().join("no-generator.age");
    let both_types_path = temp_dir.path().join("both-types-secret.age");

    let fixed_exists = fixed_secret_path.exists();
    let random_exists = random_secret_path.exists();
    let no_generator_exists = no_generator_path.exists();
    let both_exists = both_types_path.exists();

    // Should succeed
    assert!(
        result.is_ok(),
        "CLI generate should succeed: {:?}",
        result.err()
    );

    // Check that the files with generators were created
    assert!(fixed_exists, "fixed-secret.age should be created");
    assert!(random_exists, "random-secret.age should be created");
    assert!(
        !no_generator_exists,
        "no-generator.age should not be created"
    );
    assert!(both_exists, "both-types-secret.age should be created");

    // The file paths are already set above

    // Verify the files are not empty (they contain encrypted data)
    let fixed_content = fs::read(&fixed_secret_path)?;
    let random_content = fs::read(&random_secret_path)?;
    let both_content = fs::read(&both_types_path)?;

    assert!(
        !fixed_content.is_empty(),
        "fixed-secret.age should not be empty"
    );
    assert!(
        !random_content.is_empty(),
        "random-secret.age should not be empty"
    );
    assert!(
        !both_content.is_empty(),
        "both-types-secret.age should not be empty"
    );

    // All encrypted files should be different (different content/randomness/nonce)
    assert_ne!(
        fixed_content, random_content,
        "Generated files should have different encrypted content"
    );
    assert_ne!(
        fixed_content, both_content,
        "Generated files should have different encrypted content"
    );
    assert_ne!(
        random_content, both_content,
        "Generated files should have different encrypted content"
    );

    // Test that running generate again doesn't overwrite existing files
    let original_fixed_content = fs::read(&fixed_secret_path)?;

    let result2 = agenix::run(args);
    assert!(result2.is_ok(), "Second generate should succeed");

    let after_fixed_content = fs::read(&fixed_secret_path)?;
    assert_eq!(
        original_fixed_content, after_fixed_content,
        "Existing files should not be overwritten"
    );

    Ok(())
}

#[test]
fn test_generate_with_armor_setting() -> Result<()> {
    // Skip if nix-instantiate is not available
    if !have("nix-instantiate") {
        eprintln!("skipping integration test: missing nix-instantiate");
        return Ok(());
    }

    let temp_dir = tempdir()?;

    // Create a temporary rules file with armor settings using absolute paths
    let rules_content = format!(
        r#"
{{
  "{}/armored-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "armored-content";
    armor = true;
  }};
  "{}/binary-secret.age" = {{
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {{ }}: "binary-content";
    armor = false;
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
        "--generate".to_string(),
        "--rules".to_string(),
        temp_rules.path().to_str().unwrap().to_string(),
    ];

    let result = agenix::run(args);

    let armored_path = temp_dir.path().join("armored-secret.age");
    let binary_path = temp_dir.path().join("binary-secret.age");

    assert!(
        result.is_ok(),
        "Generate with armor should succeed: {:?}",
        result.err()
    );

    // Check that files were created
    assert!(
        armored_path.exists(),
        "armored-secret.age should be created"
    );
    assert!(binary_path.exists(), "binary-secret.age should be created");

    // Check that armored file contains ASCII armor markers
    let armored_content = fs::read_to_string(&armored_path)?;
    assert!(
        armored_content.contains("-----BEGIN AGE ENCRYPTED FILE-----"),
        "Armored file should contain age armor header"
    );
    assert!(
        armored_content.contains("-----END AGE ENCRYPTED FILE-----"),
        "Armored file should contain age armor footer"
    );

    // Check that binary file doesn't contain ASCII armor (is binary)
    let binary_content = fs::read(&binary_path)?;
    let binary_str = String::from_utf8_lossy(&binary_content);
    assert!(
        !binary_str.contains("-----BEGIN AGE ENCRYPTED FILE-----"),
        "Binary file should not contain armor headers"
    );

    Ok(())
}
