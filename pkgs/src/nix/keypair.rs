use anyhow::Result;

/// Generate an Ed25519 SSH keypair
pub fn generate_ed25519_keypair() -> Result<(String, String)> {
    use base64::{Engine as _, engine::general_purpose};
    use ed25519_dalek::ed25519::signature::rand_core::OsRng;
    use ed25519_dalek::pkcs8;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Generate private key in PEM format
    let private_key_pem = signing_key.to_pkcs8_pem(pkcs8::spki::der::pem::LineEnding::LF)?;

    // Generate public key in SSH format (ssh-ed25519 AAAAC3Nza...)
    // SSH ed25519 public key format includes algorithm identifier + key data
    let mut ssh_key_data = Vec::new();

    // SSH wire format: length(algorithm) + algorithm + length(public_key) + public_key
    let algorithm = b"ssh-ed25519";
    ssh_key_data.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
    ssh_key_data.extend_from_slice(algorithm);

    let public_key_bytes = verifying_key.as_bytes();
    ssh_key_data.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
    ssh_key_data.extend_from_slice(public_key_bytes);

    // Base64 encoding using the base64 crate
    let base64_encoded = general_purpose::STANDARD.encode(&ssh_key_data);
    let public_key_ssh = format!("ssh-ed25519 {}", base64_encoded);

    Ok((private_key_pem.to_string(), public_key_ssh))
}

/// Generate an Age x25519 keypair
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

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

        // Test that we can parse the generated keys back using the same library
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        use ed25519_dalek::{SigningKey, VerifyingKey};

        // Parse private key (still PEM format)
        let parsed_private_key = SigningKey::from_pkcs8_pem(&private_key)?;

        // Parse SSH public key manually
        assert!(public_key.starts_with("ssh-ed25519 "));
        let base64_part = &public_key[12..]; // Skip "ssh-ed25519 "

        // Decode the SSH wire format
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

        let key_bytes = &decoded_data[pos..pos + key_len];
        let parsed_public_key = VerifyingKey::from_bytes(key_bytes.try_into()?)?;

        // Verify that the public key derived from private key matches the parsed SSH public key
        let derived_public_key = parsed_private_key.verifying_key();
        assert_eq!(derived_public_key.as_bytes(), parsed_public_key.as_bytes());

        // Test signing and verification to ensure the keypair works
        use ed25519_dalek::{Signer, Verifier};

        let message = b"test message for signing";
        let signature = parsed_private_key.sign(message);

        // Verify the signature with the public key
        assert!(parsed_public_key.verify(message, &signature).is_ok());

        // Verify that a different message fails verification
        let wrong_message = b"wrong message";
        assert!(parsed_public_key.verify(wrong_message, &signature).is_err());

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
}
