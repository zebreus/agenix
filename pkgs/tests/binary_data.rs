//! Integration tests for binary data support.
//!
//! These tests verify that agenix can handle binary data (all bytes from 0x00 to 0xff)
//! correctly in secrets and public files.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

/// Create a secrets.nix file in the given directory with the given content.
/// Returns the path to the created file.
fn create_rules_file_in_dir(dir: &std::path::Path, content: &str) -> std::path::PathBuf {
    let rules_path = dir.join("secrets.nix");
    fs::write(&rules_path, content).unwrap();
    rules_path
}

/// Helper to convert Path to string for use in command arguments.
fn path_to_str(path: &std::path::Path) -> &str {
    path.to_str().unwrap()
}

/// Default age public key for testing.
const TEST_PUBKEY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

/// Get the path to the agenix binary.
fn agenix_bin() -> String {
    env!("CARGO_BIN_EXE_agenix").to_string()
}

/// Generate binary data containing all bytes from 0x00 to 0xff.
fn generate_all_bytes() -> Vec<u8> {
    (0u8..=255u8).collect()
}

// ============================================
// ENCRYPT BINARY DATA TESTS
// ============================================

#[test]
fn test_encrypt_binary_data_all_bytes() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "binary-secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file_in_dir(secrets_nix_dir, &rules);

    // Generate binary data with all possible byte values
    let binary_data = generate_all_bytes();

    // Run encrypt with binary data via stdin
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&binary_data).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt should succeed with binary data, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the secret file was created
    assert!(secret_path.exists(), "Secret file should be created");
}

#[test]
fn test_encrypt_binary_data_from_file() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "binary-secret";
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));
    let input_path = secrets_nix_dir.join("binary-input");

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file_in_dir(secrets_nix_dir, &rules);

    // Create binary input file
    let binary_data = generate_all_bytes();
    fs::write(&input_path, &binary_data).unwrap();

    // Run encrypt with binary file
    let output = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--input",
            path_to_str(&input_path),
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "encrypt --input should succeed with binary data, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(secret_path.exists(), "Secret file should be created");
}

// ============================================
// DECRYPT BINARY DATA TESTS
// ============================================

#[test]
fn test_decrypt_binary_data_all_bytes() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "binary-secret";

    // Generate a proper age keypair for testing
    use age::secrecy::ExposeSecret;
    let secret_key = age::x25519::Identity::generate();
    let public_key = secret_key.to_public();
    let private_key_str = secret_key.to_string().expose_secret().to_string();
    let public_key_str = public_key.to_string();

    let temp_rules = create_rules_file_in_dir(
        secrets_nix_dir,
        &format!(
            r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            secret_name, public_key_str
        ),
    );

    // Generate binary data with all possible byte values
    let binary_data = generate_all_bytes();

    // Encrypt binary data
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&binary_data).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");
    assert!(
        output.status.success(),
        "encrypt should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Write the identity to a file for decryption
    let identity_file = secrets_nix_dir.join("identity");
    fs::write(&identity_file, &private_key_str).unwrap();

    // Decrypt
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "-i",
            path_to_str(&identity_file),
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "decrypt should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the decrypted data matches the original
    assert_eq!(
        output.stdout, binary_data,
        "Decrypted data should match original binary data"
    );
}

// ============================================
// EDIT BINARY DATA TESTS
// ============================================

#[test]
fn test_edit_binary_data_via_stdin() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "binary-secret";
    let temp_rules = create_rules_file_in_dir(
        secrets_nix_dir,
        &format!(
            r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
            secret_name, TEST_PUBKEY
        ),
    );

    // Generate binary data
    let binary_data = generate_all_bytes();

    // Edit with binary data via stdin (non-TTY mode)
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--force",
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&binary_data).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit should succeed with binary data, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the secret file was created
    let secret_path = secrets_nix_dir.join(format!("{}.age", secret_name));
    assert!(secret_path.exists(), "Secret file should be created");
}

// ============================================
// PUBLIC FILE BINARY DATA TESTS
// ============================================

#[test]
fn test_encrypt_public_binary_data() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "secret";
    let pub_path = secrets_nix_dir.join(format!("{}.pub", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file_in_dir(secrets_nix_dir, &rules);

    // Generate binary data
    let binary_data = generate_all_bytes();

    // Run encrypt with --public and binary data
    let mut child = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--public",
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&binary_data).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "encrypt --public should succeed with binary data, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the public file was created with correct content
    assert!(pub_path.exists(), ".pub file should be created");
    let file_content = fs::read(&pub_path).unwrap();
    assert_eq!(
        file_content, binary_data,
        "Public file content should match binary data"
    );
}

#[test]
fn test_decrypt_public_binary_data() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "secret";
    let pub_path = secrets_nix_dir.join(format!("{}.pub", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file_in_dir(secrets_nix_dir, &rules);

    // Create binary public file
    let binary_data = generate_all_bytes();
    fs::write(&pub_path, &binary_data).unwrap();

    // Run decrypt with --public
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "--public",
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "decrypt --public should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the output contains the binary data
    assert_eq!(
        output.stdout, binary_data,
        "Output should match binary data"
    );
}

#[test]
fn test_edit_public_binary_data() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "secret";
    let pub_path = secrets_nix_dir.join(format!("{}.pub", secret_name));

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file_in_dir(secrets_nix_dir, &rules);

    // Generate binary data
    let binary_data = generate_all_bytes();

    // Run edit with --public and binary data via stdin
    let mut child = Command::new(agenix_bin())
        .args([
            "edit",
            "--public",
            "--force",
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn agenix");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&binary_data).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to wait for agenix");

    assert!(
        output.status.success(),
        "edit --public should succeed with binary data, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the public file was created with correct content
    assert!(pub_path.exists(), ".pub file should be created");
    let file_content = fs::read(&pub_path).unwrap();
    assert_eq!(
        file_content, binary_data,
        "Public file content should match binary data"
    );
}

#[test]
fn test_encrypt_public_binary_data_from_file() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "secret";
    let pub_path = secrets_nix_dir.join(format!("{}.pub", secret_name));
    let input_path = secrets_nix_dir.join("binary-input.bin");

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file_in_dir(secrets_nix_dir, &rules);

    // Create binary input file
    let binary_data = generate_all_bytes();
    fs::write(&input_path, &binary_data).unwrap();

    // Run encrypt with --public and --input
    let output = Command::new(agenix_bin())
        .args([
            "encrypt",
            "--public",
            "--input",
            path_to_str(&input_path),
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "encrypt --public --input should succeed with binary data, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the public file was created with correct content
    assert!(pub_path.exists(), ".pub file should be created");
    let file_content = fs::read(&pub_path).unwrap();
    assert_eq!(
        file_content, binary_data,
        "Public file content should match binary data"
    );
}

#[test]
fn test_decrypt_public_binary_data_to_file() {
    let temp_dir = tempdir().unwrap();
    let secrets_nix_dir = temp_dir.path();

    let secret_name = "secret";
    let pub_path = secrets_nix_dir.join(format!("{}.pub", secret_name));
    let output_path = secrets_nix_dir.join("output.bin");

    let rules = format!(
        r#"{{ "{}" = {{ publicKeys = [ "{}" ]; }}; }}"#,
        secret_name, TEST_PUBKEY
    );
    let temp_rules = create_rules_file_in_dir(secrets_nix_dir, &rules);

    // Create binary public file
    let binary_data = generate_all_bytes();
    fs::write(&pub_path, &binary_data).unwrap();

    // Run decrypt with --public -o output
    let output = Command::new(agenix_bin())
        .args([
            "decrypt",
            "--public",
            "-o",
            path_to_str(&output_path),
            "--secrets-nix",
            path_to_str(&temp_rules),
            secret_name,
        ])
        .output()
        .expect("Failed to execute agenix");

    assert!(
        output.status.success(),
        "decrypt --public -o should succeed, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the output file was created with correct content
    assert!(output_path.exists(), "Output file should be created");
    let file_content = fs::read(&output_path).unwrap();
    assert_eq!(
        file_content, binary_data,
        "Output file content should match binary data"
    );
}
