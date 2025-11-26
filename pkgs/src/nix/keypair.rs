//! Cryptographic key pair generation for SSH and age.
//!
//! This module provides functions to generate Ed25519 SSH keypairs,
//! RSA SSH keypairs, and age x25519 keypairs for use in secret encryption.

use anyhow::Result;

pub fn generate_ed25519_keypair() -> Result<(String, String)> {
    use base64::{Engine as _, engine::general_purpose};
    use cosmian_crypto_core::reexport::rand_core::SeedableRng;
    use cosmian_crypto_core::{CsRng, Ed25519Keypair};
    use pkcs8::{EncodePrivateKey, LineEnding};

    // Generate the Ed25519 keypair using cosmian_crypto_core
    let mut rng = CsRng::from_entropy();
    let keypair = Ed25519Keypair::new(&mut rng)?;

    // Generate private key in PKCS#8 PEM format
    let private_key_pem = keypair.to_pkcs8_pem(LineEnding::LF)?;

    // Generate public key in SSH format (ssh-ed25519 AAAAC3Nza...)
    // SSH ed25519 public key format includes algorithm identifier + key data
    let mut ssh_key_data = Vec::new();

    // SSH wire format: length(algorithm) + algorithm + length(public_key) + public_key
    let algorithm = b"ssh-ed25519";
    ssh_key_data.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
    ssh_key_data.extend_from_slice(algorithm);

    let public_key_bytes = keypair.public_key.as_bytes();
    ssh_key_data.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
    ssh_key_data.extend_from_slice(public_key_bytes);

    // Base64 encoding
    let base64_encoded = general_purpose::STANDARD.encode(&ssh_key_data);
    let public_key_ssh = format!("ssh-ed25519 {}", base64_encoded);

    Ok((private_key_pem.to_string(), public_key_ssh))
}

pub fn generate_age_x25519_keypair() -> Result<(String, String)> {
    use age::secrecy::ExposeSecret;

    // Generate age x25519 keypair
    let secret_key = age::x25519::Identity::generate();
    let public_key = secret_key.to_public();

    // Convert to strings
    let private_key = secret_key.to_string().expose_secret().to_string();
    let public_key = public_key.to_string();

    Ok((private_key, public_key))
}

/// Generate an RSA keypair with the specified key size in bits.
/// Valid key sizes are 2048, 3072, and 4096.
/// Returns (private_key_pem, public_key_ssh) tuple.
///
/// # Testing
/// The tests for this function are slow (RSA key generation is computationally expensive)
/// and are skipped by default. When making changes to this function, run the RSA tests
/// explicitly with: `cargo test rsa -- --ignored`
pub fn generate_rsa_keypair(key_size: u32) -> Result<(String, String)> {
    use anyhow::anyhow;
    use base64::{Engine as _, engine::general_purpose};
    use cosmian_crypto_core::reexport::rand_core::SeedableRng;
    use cosmian_crypto_core::{CsRng, RsaKeyLength, RsaPrivateKey};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::traits::PublicKeyParts;

    // Map key size to RsaKeyLength enum
    let key_length = match key_size {
        2048 => RsaKeyLength::Modulus2048,
        3072 => RsaKeyLength::Modulus3072,
        4096 => RsaKeyLength::Modulus4096,
        _ => {
            return Err(anyhow!(
                "Invalid RSA key size: {}. Valid sizes are 2048, 3072, 4096",
                key_size
            ));
        }
    };

    // Generate the RSA keypair using cosmian_crypto_core
    let mut rng = CsRng::from_entropy();
    let private_key = RsaPrivateKey::new(&mut rng, key_length)?;
    let public_key = private_key.public_key();

    // Get private key in PKCS#8 PEM format
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)?;

    // Get public key in SSH format (ssh-rsa AAAA...)
    // SSH RSA public key format: string "ssh-rsa" || mpint e || mpint n
    // Get the RSA components from the public key DER
    let public_der = public_key.to_public_key_der()?;

    // Parse the DER to extract e and n using rsa crate
    use rsa::pkcs8::DecodePublicKey;
    let rsa_pub = rsa::RsaPublicKey::from_public_key_der(public_der.as_bytes())?;

    // Build SSH wire format
    let mut ssh_key_data = Vec::new();

    // Write algorithm identifier "ssh-rsa"
    let algorithm = b"ssh-rsa";
    ssh_key_data.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
    ssh_key_data.extend_from_slice(algorithm);

    // Write e (public exponent) as SSH mpint
    let e_bytes = rsa_pub.e().to_bytes_be();
    write_ssh_mpint(&mut ssh_key_data, &e_bytes);

    // Write n (modulus) as SSH mpint
    let n_bytes = rsa_pub.n().to_bytes_be();
    write_ssh_mpint(&mut ssh_key_data, &n_bytes);

    // Base64 encode and format
    let base64_encoded = general_purpose::STANDARD.encode(&ssh_key_data);
    let public_key_ssh = format!("ssh-rsa {}", base64_encoded);

    Ok((private_pem.to_string(), public_key_ssh))
}

/// Write a byte slice as an SSH mpint (multi-precision integer)
/// SSH mpint format: length (4 bytes) + data (with leading 0 byte if high bit is set)
fn write_ssh_mpint(output: &mut Vec<u8>, bytes: &[u8]) {
    // Skip all leading zeros, but keep at least one byte
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let bytes = &bytes[start..];

    // If high bit is set, prepend a zero byte (SSH mpint is signed, and we want positive)
    if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
        output.extend_from_slice(&((bytes.len() + 1) as u32).to_be_bytes());
        output.push(0);
        output.extend_from_slice(bytes);
    } else {
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ssh_keypair() -> Result<()> {
        let (private_key, public_key) = generate_ed25519_keypair()?;

        // Verify private key format (still PEM)
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(private_key.contains('\n'));

        // Verify public key format (now SSH format)
        assert!(public_key.starts_with("ssh-ed25519 "));
        assert!(!public_key.contains('\n')); // SSH format is single line
        assert!(!public_key.contains("-----")); // No PEM headers

        // Verify they're not empty or just headers
        assert!(private_key.len() > 100); // Should be substantial content
        assert!(public_key.len() > 50); // Should be substantial content

        // The base64 part should be valid base64
        let base64_part = &public_key[12..]; // Skip "ssh-ed25519 "
        assert!(
            base64_part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        );

        // Generate another keypair and verify they're different
        let (private_key2, public_key2) = generate_ed25519_keypair()?;

        assert_ne!(private_key, private_key2);
        assert_ne!(public_key, public_key2);

        Ok(())
    }

    #[test]
    fn test_generate_ssh_keypair_validity() -> Result<()> {
        let (private_key, public_key) = generate_ed25519_keypair()?;

        // Verify private key is valid PKCS#8 PEM format
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));

        // Parse SSH public key manually
        assert!(public_key.starts_with("ssh-ed25519 "));
        let base64_part = &public_key[12..]; // Skip "ssh-ed25519 "

        // Decode the SSH wire format
        use anyhow::anyhow;
        use base64::{Engine as _, engine::general_purpose};
        let decoded_data = general_purpose::STANDARD
            .decode(base64_part)
            .map_err(|e| anyhow!("Base64 decode error: {}", e))?;

        // Parse SSH wire format: length(algorithm) + algorithm + length(key) + key
        let mut pos = 0;

        // Read algorithm length and algorithm
        let algo_len = u32::from_be_bytes([
            decoded_data[pos],
            decoded_data[pos + 1],
            decoded_data[pos + 2],
            decoded_data[pos + 3],
        ]) as usize;
        pos += 4;

        let algorithm = &decoded_data[pos..pos + algo_len];
        assert_eq!(algorithm, b"ssh-ed25519");
        pos += algo_len;

        // Read key length and key
        let key_len = u32::from_be_bytes([
            decoded_data[pos],
            decoded_data[pos + 1],
            decoded_data[pos + 2],
            decoded_data[pos + 3],
        ]) as usize;
        pos += 4;

        // Ed25519 public key should be 32 bytes
        assert_eq!(key_len, 32);

        // Verify the remaining data is exactly the key
        let key_bytes = &decoded_data[pos..pos + key_len];
        assert_eq!(key_bytes.len(), 32);

        Ok(())
    }

    #[test]
    fn test_base64_roundtrip() -> Result<()> {
        let test_data = b"Hello, World! This is a test string for base64 encoding.";

        // Use the same base64 implementation as our SSH key generation
        use anyhow::anyhow;
        use base64::{Engine as _, engine::general_purpose};
        let encoded = general_purpose::STANDARD.encode(test_data);
        let decoded = general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|e| anyhow!("Base64 decode error: {}", e))?;

        assert_eq!(test_data.as_slice(), decoded.as_slice());

        Ok(())
    }

    #[test]
    fn test_generate_age_x25519_keypair() -> Result<()> {
        let (private_key, public_key) = generate_age_x25519_keypair()?;

        // Verify private key format (age secret key format)
        assert!(private_key.starts_with("AGE-SECRET-KEY-1"));
        assert!(!private_key.contains('\n')); // Single line
        assert!(!private_key.contains(' ')); // No spaces

        // Verify public key format (age public key format)
        assert!(public_key.starts_with("age1"));
        assert!(!public_key.contains('\n')); // Single line
        assert!(!public_key.contains(' ')); // No spaces

        // Verify they're not empty or just prefixes
        assert!(private_key.len() > 20); // Should be substantial content
        assert!(public_key.len() > 10); // Should be substantial content

        // Generate another keypair and verify they're different
        let (private_key2, public_key2) = generate_age_x25519_keypair()?;

        assert_ne!(private_key, private_key2);
        assert_ne!(public_key, public_key2);

        Ok(())
    }

    #[test]
    fn test_generate_age_keypair_format() -> Result<()> {
        let (private_key, public_key) = generate_age_x25519_keypair()?;

        // Private key should be exactly the right format (bech32 with AGE-SECRET-KEY-1 prefix)
        // Expected format: AGE-SECRET-KEY-1 + 58 bech32 characters
        assert_eq!(private_key.len(), 74); // "AGE-SECRET-KEY-1" (16) + 58 chars = 74

        // Public key should be exactly the right format (bech32 with age1 prefix)
        // Expected format: age1 + 58 bech32 characters
        assert_eq!(public_key.len(), 62); // "age1" (4) + 58 chars = 62

        // Verify character set (bech32 uses alphanumeric)
        // Private key suffix can have uppercase letters
        let private_suffix = &private_key[16..]; // Skip "AGE-SECRET-KEY-1"
        assert!(private_suffix.chars().all(|c| c.is_ascii_alphanumeric()));

        // Public key suffix uses lowercase only
        let public_suffix = &public_key[4..]; // Skip "age1"
        assert!(
            public_suffix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );

        Ok(())
    }

    // Tests for RSA keypair generation
    // Slow tests (>2s) are ignored by default. Run with: cargo test rsa -- --ignored
    #[test]
    #[ignore]
    fn test_generate_rsa_keypair_2048() -> Result<()> {
        let (private_key, public_key) = generate_rsa_keypair(2048)?;

        // Verify private key format (PKCS#8 PEM)
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(private_key.contains('\n'));

        // Verify public key format (SSH format)
        assert!(public_key.starts_with("ssh-rsa "));
        assert!(!public_key.contains('\n')); // SSH format is single line
        assert!(!public_key.contains("-----")); // No PEM headers

        // Verify they're not empty or just headers
        assert!(private_key.len() > 1000); // RSA 2048 private key is substantial
        assert!(public_key.len() > 350); // RSA 2048 public key is substantial

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_generate_rsa_keypair_4096() -> Result<()> {
        let (private_key, public_key) = generate_rsa_keypair(4096)?;

        // Verify private key format
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));

        // Verify public key format
        assert!(public_key.starts_with("ssh-rsa "));

        // 4096-bit keys are larger than 2048-bit
        assert!(private_key.len() > 3000);
        assert!(public_key.len() > 700);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_generate_rsa_keypair_different_each_time() -> Result<()> {
        let (private_key1, public_key1) = generate_rsa_keypair(2048)?;
        let (private_key2, public_key2) = generate_rsa_keypair(2048)?;

        assert_ne!(private_key1, private_key2);
        assert_ne!(public_key1, public_key2);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_generate_rsa_keypair_3072() -> Result<()> {
        let (private_key, public_key) = generate_rsa_keypair(3072)?;

        // Verify private key format
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));

        // Verify public key format
        assert!(public_key.starts_with("ssh-rsa "));

        // 3072-bit keys should be between 2048 and 4096 in size
        assert!(private_key.len() > 1500);
        assert!(private_key.len() < 3500);
        assert!(public_key.len() > 500);
        assert!(public_key.len() < 750);

        Ok(())
    }

    #[test]
    fn test_generate_rsa_keypair_invalid_size() {
        let result = generate_rsa_keypair(1024);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid RSA key size")
        );

        let result2 = generate_rsa_keypair(512);
        assert!(result2.is_err());
    }

    #[test]
    #[ignore]
    fn test_rsa_public_key_format() -> Result<()> {
        let (_, public_key) = generate_rsa_keypair(2048)?;

        // Verify SSH public key format
        assert!(public_key.starts_with("ssh-rsa "));

        // The base64 part should be valid base64
        let base64_part = &public_key[8..]; // Skip "ssh-rsa "
        assert!(
            base64_part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        );

        // Decode the SSH wire format to verify structure
        use base64::{Engine as _, engine::general_purpose};
        let decoded = general_purpose::STANDARD.decode(base64_part)?;

        // Read algorithm length (first 4 bytes)
        let algo_len =
            u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]) as usize;
        assert_eq!(algo_len, 7); // "ssh-rsa" is 7 characters

        // Read algorithm name
        let algorithm = &decoded[4..4 + algo_len];
        assert_eq!(algorithm, b"ssh-rsa");

        Ok(())
    }
}
