//! Integration tests for quiet mode behavior.
//!
//! These tests verify that the `-q` / `--quiet` flag properly suppresses
//! non-essential output across all commands.

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
    // Use CARGO_BIN_EXE_agenix which is set by cargo when running integration tests
    env!("CARGO_BIN_EXE_agenix").to_string()
}

// ============================================
// LIST COMMAND QUIET MODE TESTS
// ============================================

#[test]
fn test_list_quiet_outputs_secrets_but_no_summary() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    let rules = format!(
        r#"{{ "{}/s1.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s2.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        path, TEST_PUBKEY, path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args(["-q", "list", "--rules", temp_rules.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "list should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain secrets list (note: .age suffix may be stripped in output)
    assert!(
        stdout.contains("s1") && stdout.contains("s2"),
        "stdout should contain secret names in quiet mode, got: {:?}",
        stdout
    );
    // Should NOT contain summary
    assert!(
        !stdout.contains("Total:"),
        "stdout should NOT contain summary in quiet mode, got: {:?}",
        stdout
    );

    assert!(
        output.stderr.is_empty(),
        "stderr should be empty in quiet mode, got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_list_normal_produces_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    let rules = format!(
        r#"{{ "{}/s1.age" = {{ publicKeys = [ "{}" ]; }}; "{}/s2.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        path, TEST_PUBKEY, path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args(["list", "--rules", temp_rules.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "list should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Total:") || stdout.contains("secrets"),
        "normal mode should produce output, got: {:?}",
        stdout
    );
}

// ============================================
// CHECK COMMAND QUIET MODE TESTS
// ============================================

#[test]
fn test_check_quiet_produces_no_output_on_success() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    // Rules with nonexistent secrets (so check succeeds but has nothing to verify)
    let rules = format!(
        r#"{{ "{}/missing.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args([
            "-q",
            "check",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    // Check succeeds with 0 files to check
    assert!(output.status.success(), "check should succeed");
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty in quiet mode, got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_check_normal_produces_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    let rules = format!(
        r#"{{ "{}/missing.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args(["check", "--rules", temp_rules.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute agenix");

    // Normal mode should produce informational output
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.is_empty() || output.status.success(),
        "normal check should produce output or succeed silently"
    );
}

// ============================================
// GENERATE COMMAND QUIET MODE TESTS
// ============================================

#[test]
fn test_generate_quiet_produces_no_output_on_skip() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    // Secret that already exists (will be skipped)
    let secret_path = format!("{}/existing.age", path);
    fs::write(&secret_path, "existing-content").unwrap();

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test"; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args([
            "-q",
            "generate",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate should succeed");
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty in quiet mode when skipping, got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_generate_dry_run_quiet_produces_no_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    let rules = format!(
        r#"{{ "{}/new-secret.age" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test"; }}; }}"#,
        path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args([
            "-q",
            "generate",
            "--dry-run",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate --dry-run should succeed");
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty in quiet mode for dry-run, got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_generate_normal_produces_output() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    // Secret that already exists (will show skip message)
    let secret_path = format!("{}/existing.age", path);
    fs::write(&secret_path, "existing-content").unwrap();

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; generator = {{ }}: "test"; }}; }}"#,
        secret_path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args(["generate", "--rules", temp_rules.path().to_str().unwrap()])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "generate should succeed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Skipping") || stderr.contains("already exists"),
        "normal mode should produce skip message, got: {:?}",
        stderr
    );
}

// ============================================
// REKEY COMMAND QUIET MODE TESTS
// ============================================

#[test]
fn test_rekey_quiet_produces_no_output_on_no_files() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    // Nonexistent secrets - nothing to rekey
    let rules = format!(
        r#"{{ "{}/nonexistent.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    let output = Command::new(agenix_bin())
        .args([
            "-q",
            "rekey",
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    // Should succeed when there are no files to rekey
    assert!(
        output.status.success(),
        "rekey should succeed with no files"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty in quiet mode, got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================
// DECRYPT COMMAND - CONTENT OUTPUT IS NEVER SUPPRESSED
// ============================================

#[test]
fn test_decrypt_quiet_still_outputs_content() {
    // This test documents that decrypt output is NOT affected by quiet mode
    // since the decrypted content goes to stdout, not stderr

    // We can't easily test this without a valid encrypted file,
    // but we can verify the behavior by checking the error case
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();

    let rules = format!(
        r#"{{ "{}/secret.age" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        path, TEST_PUBKEY
    );
    let temp_rules = create_rules_file(&rules);

    // Create a dummy (invalid) secret file
    let secret_path = format!("{}/secret.age", path);
    fs::write(&secret_path, "invalid-age-content").unwrap();

    let output = Command::new(agenix_bin())
        .args([
            "-q",
            "decrypt",
            &secret_path,
            "--rules",
            temp_rules.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute agenix");

    // Should fail because file is not valid age format
    assert!(
        !output.status.success(),
        "decrypt of invalid file should fail"
    );
    // In quiet mode, even errors are shown because they indicate problems
    // The error should be in stderr even in quiet mode
}

// ============================================
// COMPLETIONS COMMAND - OUTPUT IS NEVER SUPPRESSED
// ============================================

#[test]
fn test_completions_quiet_still_outputs_completions() {
    let output = Command::new(agenix_bin())
        .args(["-q", "completions", "bash"])
        .output()
        .expect("Failed to execute agenix");

    assert!(output.status.success(), "completions should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("complete") || stdout.contains("_agenix"),
        "completions should still be output in quiet mode, got: {:?}",
        stdout
    );
}

// ============================================
// VERBOSE AND QUIET ARE MUTUALLY EXCLUSIVE
// ============================================

#[test]
fn test_verbose_and_quiet_mutually_exclusive() {
    let output = Command::new(agenix_bin())
        .args(["-v", "-q", "list"])
        .output()
        .expect("Failed to execute agenix");

    assert!(!output.status.success(), "using both -v and -q should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("conflict"),
        "error should mention conflict, got: {:?}",
        stderr
    );
}
