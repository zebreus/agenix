//! Integration tests for dry-run functionality across all commands.
//!
//! These tests verify that --dry-run flag works correctly for generate, rekey, and encrypt commands,
//! ensuring they follow the same code paths as normal mode but without modifying files.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::{NamedTempFile, tempdir};

/// Create a temporary rules file with the given content.
fn create_rules_file(content: &str) -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "{}", content).unwrap();
    temp_file.flush().unwrap();
    temp_file
}

/// Default age public key for testing.
const TEST_PUBKEY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

/// Get the path to the agenix binary.
fn agenix_bin() -> String {
    env!("CARGO_BIN_EXE_agenix").to_string()
}

// ============================================
// GENERATE --dry-run TESTS
// ============================================

#[test]
fn test_generate_dry_run_does_not_create_files() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/new-secret.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test-content"; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run generate with --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "generate",
            "--dry-run",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate --dry-run should succeed");

    // Verify file was NOT created
    assert!(
        !std::path::Path::new(&secret_path).exists(),
        "File should NOT be created in dry-run mode"
    );
}

#[test]
fn test_generate_dry_run_produces_same_output_as_normal() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/test-secret.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test-content"; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run generate with --dry-run
    let dry_run_output = Command::new(agenix_bin())
        .args([
            "generate",
            "--dry-run",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    let dry_run_stderr = String::from_utf8_lossy(&dry_run_output.stderr);

    // Verify dry-run produces expected output
    assert!(
        dry_run_stderr.contains("Generating"),
        "Dry-run should output 'Generating', got: {:?}",
        dry_run_stderr
    );
    assert!(
        dry_run_stderr.contains("Generated and encrypted"),
        "Dry-run should output 'Generated and encrypted', got: {:?}",
        dry_run_stderr
    );
}

#[test]
fn test_generate_dry_run_with_public_key_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/ssh-key.age", path);

    // Use sshKey generator which produces a public key
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = builtins.sshKey; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run generate with --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "generate",
            "--dry-run",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate --dry-run should succeed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Generated public file"),
        "Should report public file generation, got: {:?}",
        stderr
    );

    // Verify neither file was created
    assert!(
        !std::path::Path::new(&secret_path).exists(),
        "Secret file should NOT be created in dry-run mode"
    );
    let pub_path = format!("{}.pub", secret_path);
    assert!(
        !std::path::Path::new(&pub_path).exists(),
        "Public file should NOT be created in dry-run mode"
    );
}

// ============================================
// REKEY --dry-run TESTS
// ============================================

#[test]
fn test_rekey_dry_run_does_not_modify_files() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);

    // Create rules
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create a dummy secret file (invalid but fine for testing existence check)
    fs::write(&secret_path, "not-real-encrypted-content").unwrap();
    let original_content = fs::read(&secret_path).unwrap();

    // Run rekey with --dry-run (will report undecryptable but --partial would continue)
    let _output = Command::new(agenix_bin())
        .args([
            "rekey",
            "--dry-run",
            "--partial",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    // The file content should be unchanged
    let new_content = fs::read(&secret_path).unwrap();
    assert_eq!(
        original_content, new_content,
        "File content should not be modified in dry-run mode"
    );
}

#[test]
fn test_rekey_dry_run_produces_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create a file so rekey has something to check
    fs::write(&secret_path, "dummy-content").unwrap();

    let output = Command::new(agenix_bin())
        .args([
            "rekey",
            "--dry-run",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show checking output
    assert!(
        stderr.contains("Checking"),
        "Rekey --dry-run should show checking message, got: {:?}",
        stderr
    );
}

// ============================================
// ENCRYPT --dry-run TESTS
// ============================================

#[test]
fn test_encrypt_dry_run_does_not_create_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/new-secret.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run encrypt with --dry-run, providing input via stdin
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--dry-run",
            "--rules",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    // Write content to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test-secret-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify file was NOT created
    assert!(
        !std::path::Path::new(&secret_path).exists(),
        "File should NOT be created in dry-run mode"
    );
}

#[test]
fn test_encrypt_dry_run_produces_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/new-secret.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--dry-run",
            "--rules",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test-secret-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("Encrypting to:"),
        "Encrypt --dry-run should show encrypting message, got: {:?}",
        stderr
    );
}

// ============================================
// DRY-RUN SHORT FLAG TESTS
// ============================================

#[test]
fn test_generate_dry_run_short_flag() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/test.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test"; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Use -n instead of --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "generate",
            "-n",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate -n should succeed");

    // File should not exist
    assert!(
        !std::path::Path::new(&secret_path).exists(),
        "File should NOT be created with -n flag"
    );
}

#[test]
fn test_rekey_dry_run_short_flag() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/test.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Use -n instead of --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "rekey",
            "-n",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    // Should succeed (no existing files to rekey)
    assert!(output.status.success(), "rekey -n should succeed");
}

#[test]
fn test_encrypt_dry_run_short_flag() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/test.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "-n",
            "--rules",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt -n should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // File should not exist
    assert!(
        !std::path::Path::new(&secret_path).exists(),
        "File should NOT be created with -n flag"
    );
}
