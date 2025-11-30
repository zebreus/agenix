//! Integration tests for --public flag functionality across edit, encrypt, and decrypt commands.
//!
//! These tests verify that the -p/--public flag works correctly for managing
//! the .pub files associated with secrets.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::{NamedTempFile, tempdir};

/// Create a temporary secrets.nix with the given content.
fn create_rules_file(content: &str) -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content.as_bytes()).unwrap();
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
// DECRYPT --public TESTS (5+ tests)
// ============================================

#[test]
fn test_decrypt_public_reads_pub_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create the public file
    let pub_content = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPublicKey";
    fs::write(&pub_path, pub_content).unwrap();

    // Run decrypt with --public
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "decrypt --public should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the output contains the public key content
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        pub_content,
        "Should output public file content"
    );
}

#[test]
fn test_decrypt_public_short_flag() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create the public file
    let pub_content = "test-public-key-content";
    fs::write(&pub_path, pub_content).unwrap();

    // Run decrypt with -p (short flag)
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "-p",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "decrypt -p should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), pub_content.trim());
}

#[test]
fn test_decrypt_public_to_output_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);
    let output_path = format!("{}/output.txt", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create the public file
    let pub_content = "public-key-for-output-test";
    fs::write(&pub_path, pub_content).unwrap();

    // Run decrypt with --public -o output
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "--public",
            "-o",
            &output_path,
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "decrypt --public -o should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the output file was created with correct content
    let file_content = fs::read_to_string(&output_path).unwrap();
    assert_eq!(file_content.trim(), pub_content.trim());
}

#[test]
fn test_decrypt_public_fails_when_pub_file_missing() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Note: We do NOT create the .pub file

    // Run decrypt with --public
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        !output.status.success(),
        "decrypt --public should fail when .pub file is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("Public file"),
        "Error should mention missing public file, got: {:?}",
        stderr
    );
}

#[test]
fn test_decrypt_public_fails_for_nonexistent_secret() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/nonexistent.age", path);

    let rules = format!(
        r#"{{ "{}/other.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run decrypt with --public for a secret not in rules
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        !output.status.success(),
        "decrypt --public should fail for nonexistent secret in rules"
    );
}

// ============================================
// ENCRYPT --public TESTS (5+ tests)
// ============================================

#[test]
fn test_encrypt_public_writes_pub_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let pub_content = "new-public-key-content";

    // Run encrypt with --public, providing input via stdin
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--public",
            "--secrets-nix",
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
        stdin.write_all(pub_content.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt --public should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the public file was created with correct content
    assert!(
        std::path::Path::new(&pub_path).exists(),
        ".pub file should be created"
    );
    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, pub_content);
}

#[test]
fn test_encrypt_public_short_flag() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let pub_content = "short-flag-public-key";

    // Run encrypt with -p (short flag)
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "-p",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(pub_content.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt -p should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, pub_content);
}

#[test]
fn test_encrypt_public_fails_without_force_when_exists() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create existing public file
    fs::write(&pub_path, "existing-content").unwrap();

    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"new-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        !output.status.success(),
        "encrypt --public should fail when file exists without --force"
    );

    // Verify original content is unchanged
    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, "existing-content");
}

#[test]
fn test_encrypt_public_with_force_overwrites() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create existing public file
    fs::write(&pub_path, "existing-content").unwrap();

    let new_content = "overwritten-public-key";

    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--public",
            "--force",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(new_content.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt --public --force should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify content was overwritten
    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, new_content);
}

#[test]
fn test_encrypt_public_dry_run_does_not_create_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let mut child = Command::new(agenix_bin())
        .args([
            "--dry-run",
            "encrypt",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"dry-run-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt --public --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify file was NOT created
    assert!(
        !std::path::Path::new(&pub_path).exists(),
        ".pub file should NOT be created in dry-run mode"
    );
}

#[test]
fn test_encrypt_public_with_input_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);
    let input_path = format!("{}/input.txt", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create input file
    let pub_content = "input-file-public-key";
    fs::write(&input_path, pub_content).unwrap();

    let output = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--public",
            "--input",
            &input_path,
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "encrypt --public --input should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, pub_content);
}

// ============================================
// EDIT --public TESTS (5+ tests)
// ============================================

#[test]
fn test_edit_public_creates_new_file_with_force() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let pub_content = "new-public-key-via-edit";

    // Run edit with --public --force, providing input via stdin (non-TTY mode)
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--public",
            "--force",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(pub_content.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --public --force should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the public file was created with correct content
    assert!(
        std::path::Path::new(&pub_path).exists(),
        ".pub file should be created"
    );
    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, pub_content);
}

#[test]
fn test_edit_public_modifies_existing_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create existing public file
    fs::write(&pub_path, "original-content").unwrap();

    let new_content = "modified-public-key";

    // Run edit with --public
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(new_content.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --public should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify content was modified
    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, new_content);
}

#[test]
fn test_edit_public_short_flag() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create existing public file
    fs::write(&pub_path, "original").unwrap();

    let new_content = "short-flag-edit";

    // Run edit with -p (short flag)
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "-p",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(new_content.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit -p should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(file_content, new_content);
}

#[test]
fn test_edit_public_dry_run_does_not_modify_file() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create existing public file
    let original_content = "original-dry-run-content";
    fs::write(&pub_path, original_content).unwrap();

    let mut child = Command::new(agenix_bin())
        .args([
            "--dry-run",
            "edit",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"new-content-should-not-save").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --public --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify content was NOT modified
    let file_content = fs::read_to_string(&pub_path).unwrap();
    assert_eq!(
        file_content, original_content,
        "File should not be modified in dry-run mode"
    );
}

#[test]
fn test_edit_public_fails_when_pub_file_missing_without_force() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Note: We do NOT create the .pub file

    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"new-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        !output.status.success(),
        "edit --public should fail when .pub file is missing without --force"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("Public file"),
        "Error should mention missing public file, got: {:?}",
        stderr
    );
}

#[test]
fn test_edit_public_produces_dry_run_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    let secret_path = format!("{}/secret.age", path);
    let pub_path = format!("{}/secret.age.pub", path);

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create existing public file
    fs::write(&pub_path, "original").unwrap();

    let mut child = Command::new(agenix_bin())
        .args([
            "--dry-run",
            "edit",
            "--public",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            &secret_path,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"new-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Dry-run") || stderr.contains("dry-run"),
        "Should show dry-run message, got: {:?}",
        stderr
    );
}
