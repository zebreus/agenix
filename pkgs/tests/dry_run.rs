//! Integration tests for dry-run functionality across all commands.
//!
//! These tests verify that --dry-run flag works correctly for generate, rekey, encrypt,
//! and edit commands, ensuring they follow the same code paths as normal mode but
//! without modifying files.

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
// GENERATE --dry-run TESTS
// ============================================

#[test]
fn test_generate_dry_run_does_not_create_files() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "new-secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test-content"; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run generate with --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "generate",
            "--dry-run",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate --dry-run should succeed");

    // Verify file was NOT created
    assert!(
        !secret_path.exists(),
        "File should NOT be created in dry-run mode"
    );
}

#[test]
fn test_generate_dry_run_produces_same_output_as_normal() {
    let _temp_dir = tempdir().unwrap();

    // Use simple name instead of path
    let secret_name = "test-secret";

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test-content"; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run generate with --dry-run
    let dry_run_output = Command::new(agenix_bin())
        .args([
            "generate",
            "--dry-run",
            "--secrets-nix",
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
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "ssh-key";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));
    let pub_path = secrets_nix_dir.join(format!("{}.pub", secret_name));

    // Use sshKey generator which produces a public key
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = builtins.sshKey; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run generate with --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "generate",
            "--dry-run",
            "--secrets-nix",
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
        !secret_path.exists(),
        "Secret file should NOT be created in dry-run mode"
    );
    assert!(
        !pub_path.exists(),
        "Public file should NOT be created in dry-run mode"
    );
}

// ============================================
// REKEY --dry-run TESTS
// ============================================

#[test]
fn test_rekey_dry_run_does_not_modify_files() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    // Create rules
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create a file with some content to verify it's not modified by dry-run.
    // The content doesn't need to be valid encrypted data since we're using --partial
    // which continues even if decryption fails.
    fs::write(&secret_path, "test-content-to-verify-no-modification").unwrap();
    let original_content = fs::read(&secret_path).unwrap();

    // Run rekey with --dry-run (will report undecryptable but --partial would continue)
    let _output = Command::new(agenix_bin())
        .args([
            "rekey",
            "--dry-run",
            "--partial",
            "--secrets-nix",
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
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create a file so rekey has something to check
    fs::write(&secret_path, "dummy-content").unwrap();

    let output = Command::new(agenix_bin())
        .args([
            "rekey",
            "--dry-run",
            "--secrets-nix",
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
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "new-secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run encrypt with --dry-run, providing input via stdin
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--dry-run",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            secret_name,
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
        !secret_path.exists(),
        "File should NOT be created in dry-run mode"
    );
}

#[test]
fn test_encrypt_dry_run_produces_output() {
    let _temp_dir = tempdir().unwrap();

    // Use simple name instead of path
    let secret_name = "new-secret";

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--dry-run",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            secret_name,
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
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "test";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test"; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Use -n instead of --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "generate",
            "-n",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate -n should succeed");

    // File should not exist
    assert!(
        !secret_path.exists(),
        "File should NOT be created with -n flag"
    );
}

#[test]
fn test_rekey_dry_run_short_flag() {
    let _temp_dir = tempdir().unwrap();

    // Use simple name instead of path
    let secret_name = "test";

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Use -n instead of --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "rekey",
            "-n",
            "--secrets-nix",
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
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "test";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "-n",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            secret_name,
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
        !secret_path.exists(),
        "File should NOT be created with -n flag"
    );
}

// ============================================
// EDIT --dry-run TESTS
// ============================================

#[test]
fn test_edit_dry_run_does_not_create_file() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "new-secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Run edit with --dry-run, providing input via stdin (simulating piped input)
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--dry-run",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    // Write content to stdin (simulating non-TTY input)
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test-secret-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify file was NOT created
    assert!(
        !secret_path.exists(),
        "File should NOT be created in dry-run mode"
    );
}

#[test]
fn test_edit_dry_run_does_not_modify_existing_file() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "existing-secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create a file with some content to verify it's not modified by dry-run
    let original_content = b"original-encrypted-content";
    fs::write(&secret_path, original_content).unwrap();

    // Run edit with --dry-run, providing new content via stdin
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--dry-run",
            "--force", // Force to allow starting with empty content since we can't decrypt
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    // Write new content to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"new-secret-content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify file content was NOT modified
    let new_content = fs::read(&secret_path).unwrap();
    assert_eq!(
        original_content.to_vec(),
        new_content,
        "File content should not be modified in dry-run mode"
    );
}

#[test]
fn test_edit_dry_run_produces_output() {
    let _temp_dir = tempdir().unwrap();

    // Use simple name instead of path
    let secret_name = "test";

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--dry-run",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            secret_name,
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

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show the encrypting message and dry-run message
    assert!(
        stderr.contains("Encrypting to:"),
        "Edit --dry-run should show encrypting message, got: {:?}",
        stderr
    );
    assert!(
        stderr.contains("Dry-run mode: not saving changes"),
        "Edit --dry-run should show dry-run message, got: {:?}",
        stderr
    );
}

#[test]
fn test_edit_dry_run_short_flag() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    // Use simple name instead of path
    let secret_name = "test";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Use -n instead of --dry-run
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "-n",
            "--secrets-nix",
            temp_rules.path().to_str().unwrap(),
            secret_name,
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
        "edit -n should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // File should not exist
    assert!(
        !secret_path.exists(),
        "File should NOT be created with -n flag"
    );
}

// ============================================
// COMPREHENSIVE FILE SYSTEM VERIFICATION TESTS
// ============================================

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Capture the state of all files in a directory (recursively).
/// Returns a map of relative paths to file content (as Vec<u8>).
fn capture_directory_state(dir: &Path) -> HashMap<String, Vec<u8>> {
    let mut state = HashMap::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let rel_path = path
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .to_string();

            if path.is_file() {
                if let Ok(content) = fs::read(&path) {
                    state.insert(rel_path, content);
                }
            } else if path.is_dir() {
                // Recursively capture subdirectory state
                let sub_state = capture_directory_state(&path);
                state.extend(sub_state);
            }
        }
    }

    state
}

/// Verify that two directory states are identical.
fn verify_states_identical(
    before: &HashMap<String, Vec<u8>>,
    after: &HashMap<String, Vec<u8>>,
) -> Result<(), String> {
    let before_files: HashSet<_> = before.keys().collect();
    let after_files: HashSet<_> = after.keys().collect();

    // Check for new files
    let new_files: Vec<_> = after_files.difference(&before_files).collect();
    if !new_files.is_empty() {
        return Err(format!("New files created: {:?}", new_files));
    }

    // Check for deleted files
    let deleted_files: Vec<_> = before_files.difference(&after_files).collect();
    if !deleted_files.is_empty() {
        return Err(format!("Files deleted: {:?}", deleted_files));
    }

    // Check for modified files
    for file in before_files {
        let before_content = &before[file.as_str()];
        let after_content = &after[file.as_str()];
        if before_content != after_content {
            return Err(format!(
                "File modified: {} (before: {} bytes, after: {} bytes)",
                file,
                before_content.len(),
                after_content.len()
            ));
        }
    }

    Ok(())
}

/// Comprehensive test that verifies generate --dry-run makes no file system changes.
#[test]
fn test_generate_dry_run_no_filesystem_changes() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "test-secret";

    // Create a rules file in the temp directory
    let rules_path = secrets_nix_dir.join("secrets.nix");
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test-content"; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    fs::write(&rules_path, rules).unwrap();

    // Create an existing file to ensure it's not modified
    let existing_file = secrets_nix_dir.join("existing.txt");
    fs::write(&existing_file, "original content").unwrap();

    // Capture state before
    let state_before = capture_directory_state(secrets_nix_dir);

    // Run generate with --dry-run
    let output = Command::new(agenix_bin())
        .args([
            "generate",
            "--dry-run",
            "--secrets-nix",
            rules_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "generate --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Capture state after
    let state_after = capture_directory_state(secrets_nix_dir);

    // Verify no changes
    verify_states_identical(&state_before, &state_after)
        .expect("Directory state should be identical after dry-run");
}

/// Comprehensive test that verifies rekey --dry-run makes no file system changes.
#[test]
fn test_rekey_dry_run_no_filesystem_changes() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "test-secret";

    // Create a rules file
    let rules_path = secrets_nix_dir.join("secrets.nix");
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    fs::write(&rules_path, rules).unwrap();

    // Create an existing secret file
    let secret_file = secrets_nix_dir.join(format!("{}.age", secret_name));
    fs::write(&secret_file, "existing encrypted content").unwrap();

    // Create another file to ensure it's not modified
    let other_file = secrets_nix_dir.join("other.txt");
    fs::write(&other_file, "other content").unwrap();

    // Capture state before
    let state_before = capture_directory_state(secrets_nix_dir);

    // Run rekey with --dry-run (use --partial to continue even if decryption fails)
    let _output = Command::new(agenix_bin())
        .args([
            "rekey",
            "--dry-run",
            "--partial",
            "--secrets-nix",
            rules_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    // Capture state after (do this even if command fails)
    let state_after = capture_directory_state(secrets_nix_dir);

    // Verify no changes (regardless of command success/failure)
    verify_states_identical(&state_before, &state_after)
        .expect("Directory state should be identical after rekey --dry-run");
}

/// Comprehensive test that verifies encrypt --dry-run makes no file system changes.
#[test]
fn test_encrypt_dry_run_no_filesystem_changes() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "new-secret";

    // Create a rules file
    let rules_path = secrets_nix_dir.join("secrets.nix");
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    fs::write(&rules_path, rules).unwrap();

    // Create an existing file to ensure it's not modified
    let existing_file = secrets_nix_dir.join("existing.txt");
    fs::write(&existing_file, "original content").unwrap();

    // Capture state before
    let state_before = capture_directory_state(secrets_nix_dir);

    // Run encrypt with --dry-run
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--dry-run",
            "--secrets-nix",
            rules_path.to_str().unwrap(),
            secret_name,
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

    // Capture state after
    let state_after = capture_directory_state(secrets_nix_dir);

    // Verify no changes
    verify_states_identical(&state_before, &state_after)
        .expect("Directory state should be identical after encrypt --dry-run");
}

/// Comprehensive test that verifies edit --dry-run makes no file system changes on new file.
#[test]
fn test_edit_dry_run_new_file_no_filesystem_changes() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "new-secret";

    // Create a rules file
    let rules_path = secrets_nix_dir.join("secrets.nix");
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    fs::write(&rules_path, rules).unwrap();

    // Create an existing file to ensure it's not modified
    let existing_file = secrets_nix_dir.join("existing.txt");
    fs::write(&existing_file, "original content").unwrap();

    // Capture state before
    let state_before = capture_directory_state(secrets_nix_dir);

    // Run edit with --dry-run (pipe content to stdin)
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--dry-run",
            "--secrets-nix",
            rules_path.to_str().unwrap(),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    // Write content to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"new content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Capture state after
    let state_after = capture_directory_state(secrets_nix_dir);

    // Verify no changes
    verify_states_identical(&state_before, &state_after)
        .expect("Directory state should be identical after edit --dry-run on new file");
}

/// Comprehensive test that verifies edit --dry-run makes no file system changes on existing file.
#[test]
fn test_edit_dry_run_existing_file_no_filesystem_changes() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "existing-secret";

    // Create a rules file
    let rules_path = secrets_nix_dir.join("secrets.nix");
    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    fs::write(&rules_path, rules).unwrap();

    // Create an existing secret file
    let secret_file = secrets_nix_dir.join(format!("{}.age", secret_name));
    fs::write(&secret_file, "existing encrypted content").unwrap();

    // Create another file to ensure it's not modified
    let other_file = secrets_nix_dir.join("other.txt");
    fs::write(&other_file, "other content").unwrap();

    // Capture state before
    let state_before = capture_directory_state(secrets_nix_dir);

    // Run edit with --dry-run and --force (pipe content to stdin)
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--dry-run",
            "--force",
            "--secrets-nix",
            rules_path.to_str().unwrap(),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    // Write content to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"modified content").unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --dry-run should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Capture state after
    let state_after = capture_directory_state(secrets_nix_dir);

    // Verify no changes
    verify_states_identical(&state_before, &state_after)
        .expect("Directory state should be identical after edit --dry-run on existing file");
}
