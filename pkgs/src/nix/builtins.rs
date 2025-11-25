//! Custom Nix builtins for secret generation.
//!
//! Provides various builtins for generating secrets and keypairs in Nix expressions:
//! - `randomString` - Generate random alphanumeric strings
//! - `randomHex` - Generate random hexadecimal strings
//! - `randomBase64` - Generate random base64-encoded strings
//! - `passwordSafe` - Generate random password-safe strings
//! - `uuid` - Generate random UUIDv4 strings
//! - `sshKey` - Generate SSH Ed25519 keypairs
//! - `rsaKey` - Generate SSH RSA keypairs (with configurable key size)
//! - `ageKey` - Generate age x25519 keypairs

use snix_eval::builtin_macros;

#[builtin_macros::builtins]
pub mod impure_builtins {
    use base64::{Engine as _, engine::general_purpose};
    use rand::Rng;
    use rand::distr::Alphanumeric;
    use rand::rng;
    use snix_eval::ErrorKind;
    use snix_eval::NixAttrs;
    use snix_eval::NixString;
    use snix_eval::Value;
    use snix_eval::generators::Gen;
    use snix_eval::generators::GenCo;
    use std::collections::BTreeMap;

    /// Creates a Nix attribute set containing `secret` and `public` keys from a keypair.
    fn create_keypair_attrset(private_key: String, public_key: String) -> Value {
        let mut attrs: BTreeMap<NixString, Value> = BTreeMap::new();
        attrs.insert(
            NixString::from("secret".as_bytes()),
            Value::String(NixString::from(private_key.as_bytes())),
        );
        attrs.insert(
            NixString::from("public".as_bytes()),
            Value::String(NixString::from(public_key.as_bytes())),
        );
        Value::Attrs(Box::new(NixAttrs::from(attrs)))
    }

    /// Generates a random alphanumeric string of given length
    #[builtin("randomString")]
    async fn builtin_random_string(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let length = var.as_int()?;
        if length < 0 || length > 2i64.pow(16) {
            return Err(ErrorKind::Abort(
                "Length for randomString must be between 0 and 2^16".to_string(),
            ));
        }

        let random_string: String = rng()
            .sample_iter(&Alphanumeric)
            .take(usize::try_from(length).unwrap())
            .map(char::from)
            .collect();
        Ok(Value::String(NixString::from(random_string.as_bytes())))
    }

    /// Generates a random hexadecimal string of given length (number of hex characters)
    #[builtin("randomHex")]
    async fn builtin_random_hex(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let length = var.as_int()?;
        if length < 0 || length > 2i64.pow(16) {
            return Err(ErrorKind::Abort(
                "Length for randomHex must be between 0 and 2^16".to_string(),
            ));
        }

        // Each byte gives 2 hex characters, so we need length/2 bytes (rounded up)
        let byte_count = (usize::try_from(length).unwrap() + 1) / 2;
        let mut bytes = vec![0u8; byte_count];
        rng().fill(&mut bytes[..]);

        // Convert to hex and truncate to exact length
        let hex_string: String = bytes
            .iter()
            .flat_map(|b| [b >> 4, b & 0x0f])
            .take(usize::try_from(length).unwrap())
            .map(|n| {
                if n < 10 {
                    (b'0' + n) as char
                } else {
                    (b'a' + n - 10) as char
                }
            })
            .collect();
        Ok(Value::String(NixString::from(hex_string.as_bytes())))
    }

    /// Generates a random base64-encoded string from given number of bytes
    #[builtin("randomBase64")]
    async fn builtin_random_base64(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let byte_count = var.as_int()?;
        if byte_count < 0 || byte_count > 2i64.pow(16) {
            return Err(ErrorKind::Abort(
                "Byte count for randomBase64 must be between 0 and 2^16".to_string(),
            ));
        }

        let mut bytes = vec![0u8; usize::try_from(byte_count).unwrap()];
        rng().fill(&mut bytes[..]);

        let base64_string = general_purpose::STANDARD.encode(&bytes);
        Ok(Value::String(NixString::from(base64_string.as_bytes())))
    }

    /// Generates a random password-safe string (alphanumeric + safe special chars)
    /// Uses characters that are safe in most contexts (no quotes, backslashes, etc.)
    #[builtin("passwordSafe")]
    async fn builtin_password_safe(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let length = var.as_int()?;
        if length < 0 || length > 2i64.pow(16) {
            return Err(ErrorKind::Abort(
                "Length for passwordSafe must be between 0 and 2^16".to_string(),
            ));
        }

        // Safe character set: alphanumeric + some special chars that don't need escaping
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+=.";
        let mut rng = rng();

        let password: String = (0..length)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        Ok(Value::String(NixString::from(password.as_bytes())))
    }

    /// Generates a random UUIDv4 string
    #[builtin("uuid")]
    async fn builtin_uuid(co: GenCo, _var: Value) -> Result<Value, ErrorKind> {
        let mut bytes = [0u8; 16];
        rng().fill(&mut bytes);

        // Set version to 4 (random UUID)
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        // Set variant to RFC 4122
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        // Format as UUID string
        let uuid = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        );
        Ok(Value::String(NixString::from(uuid.as_bytes())))
    }

    /// Generates an SSH Ed25519 keypair
    #[builtin("sshKey")]
    async fn builtin_ssh_key(co: GenCo, _var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_ed25519_keypair;

        let (private_key, public_key) = generate_ed25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate SSH keypair: {}", e)))?;

        Ok(create_keypair_attrset(private_key, public_key))
    }

    /// Generates an age x25519 keypair
    #[builtin("ageKey")]
    async fn builtin_age_key(co: GenCo, _var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_age_x25519_keypair;

        let (private_key, public_key) = generate_age_x25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate age keypair: {}", e)))?;

        Ok(create_keypair_attrset(private_key, public_key))
    }

    /// Generates an RSA SSH keypair with configurable key size
    /// Options:
    /// - `keySize` (optional): Key size in bits. Valid values: 2048, 3072, 4096. Default: 4096
    /// Returns an attrset with `secret` (PKCS#8 PEM private key) and `public` (SSH public key)
    #[builtin("rsaKey")]
    async fn builtin_rsa_key(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_rsa_keypair;

        // Get key size from options, default to 4096
        let key_size = match &var {
            Value::Attrs(attrs) => {
                if let Some(size_val) = attrs.select(NixString::from("keySize".as_bytes()).as_ref())
                {
                    size_val.as_int()? as u32
                } else {
                    4096
                }
            }
            _ => 4096,
        };

        // Validate key size
        if key_size != 2048 && key_size != 3072 && key_size != 4096 {
            return Err(ErrorKind::Abort(format!(
                "Invalid RSA key size: {}. Valid sizes are 2048, 3072, 4096",
                key_size
            )));
        }

        let (private_key, public_key) = generate_rsa_keypair(key_size)
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate RSA keypair: {}", e)))?;

        Ok(create_keypair_attrset(private_key, public_key))
    }
}

#[cfg(test)]
mod tests {
    use crate::nix::eval::eval_nix_expression;
    use crate::nix::eval::value_to_string;
    use anyhow::Result;
    use snix_eval::Value;
    use std::env::current_dir;

    /// Helper function to extract secret and public keys from a keypair attrset Value
    fn extract_keypair(value: Value) -> Result<(String, String)> {
        let attrs = match value {
            Value::Attrs(attrs) => attrs,
            _ => anyhow::bail!("Expected attribute set"),
        };

        let (mut secret, mut public) = (String::new(), String::new());
        for (k, v) in attrs.into_iter_sorted() {
            let key = k.as_str().map(|s| s.to_owned()).unwrap_or_default();
            let value = value_to_string(v.clone()).unwrap_or_default();
            match key.as_str() {
                "secret" => secret = value,
                "public" => public = value,
                _ => {}
            }
        }
        Ok((secret, public))
    }

    #[test]
    fn test_generate_ssh_key_builtin() -> Result<()> {
        // Test the sshKey builtin function
        let nix_expr = "(builtins.sshKey {}).secret";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let private_key = value_to_string(output)?;

        // Verify it's a PEM private key
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(private_key.len() > 100);

        Ok(())
    }

    #[test]
    fn test_generate_ssh_key_builtin_public_key() -> Result<()> {
        // Test accessing the public key from the SSH key builtin
        let nix_expr = "(builtins.sshKey {}).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify it's an SSH public key
        assert!(public_key.starts_with("ssh-ed25519 "));
        assert!(!public_key.contains('\n'));
        assert!(public_key.len() > 50);

        Ok(())
    }

    #[test]
    fn test_generate_ssh_key_builtin_consistency() -> Result<()> {
        // Test that multiple calls generate different keys
        let nix_expr1 = "builtins.sshKey {}";
        let nix_expr2 = "builtins.sshKey {}";
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        let (private1, public1) = extract_keypair(output1)?;
        let (private2, public2) = extract_keypair(output2)?;

        // Keys should be different each time
        assert_ne!(public1, public2);
        assert_ne!(private1, private2);

        // Both should be valid SSH keys
        assert!(public1.starts_with("ssh-ed25519 "));
        assert!(public2.starts_with("ssh-ed25519 "));

        Ok(())
    }

    #[test]
    fn test_age_key_builtin() -> Result<()> {
        // Test the ageKey builtin function
        let nix_expr = "(builtins.ageKey {}).secret";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let private_key = value_to_string(output)?;

        // Verify it's an age secret key
        assert!(private_key.starts_with("AGE-SECRET-KEY-1"));
        assert!(!private_key.contains('\n'));
        assert!(private_key.len() == 74);

        Ok(())
    }

    #[test]
    fn test_age_key_builtin_public_key() -> Result<()> {
        // Test accessing the public key from the age key builtin
        let nix_expr = "(builtins.ageKey {}).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify it's an age public key
        assert!(public_key.starts_with("age1"));
        assert!(!public_key.contains('\n'));
        assert_eq!(public_key.len(), 62);

        Ok(())
    }

    #[test]
    fn test_age_key_builtin_consistency() -> Result<()> {
        // Test that multiple calls generate different keys
        let nix_expr1 = "builtins.ageKey {}";
        let nix_expr2 = "builtins.ageKey {}";
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        // Extract the values as attribute sets
        let attrs1 = match output1 {
            Value::Attrs(attrs) => attrs,
            _ => panic!("Expected attribute set"),
        };
        let attrs2 = match output2 {
            Value::Attrs(attrs) => attrs,
            _ => panic!("Expected attribute set"),
        };

        let (private1, public1) =
            attrs1
                .into_iter_sorted()
                .fold((String::new(), String::new()), |mut acc, (k, v)| {
                    let key = k.as_str().unwrap().to_owned();
                    let value = value_to_string(v.clone()).unwrap();
                    if key == "secret" {
                        acc.0 = value;
                    } else if key == "public" {
                        acc.1 = value;
                    }
                    acc
                });
        let (private2, public2) =
            attrs2
                .into_iter_sorted()
                .fold((String::new(), String::new()), |mut acc, (k, v)| {
                    let key = k.as_str().unwrap().to_owned();
                    let value = value_to_string(v.clone()).unwrap();
                    if key == "secret" {
                        acc.0 = value;
                    } else if key == "public" {
                        acc.1 = value;
                    }
                    acc
                });

        // Keys should be different each time
        assert_ne!(public1, public2);
        assert_ne!(private1, private2);

        // Both should be valid age keys
        assert!(public1.starts_with("age1"));
        assert!(public2.starts_with("age1"));
        assert!(private1.starts_with("AGE-SECRET-KEY-1"));
        assert!(private2.starts_with("AGE-SECRET-KEY-1"));

        Ok(())
    }

    // Tests for randomHex builtin
    #[test]
    fn test_random_hex_builtin() -> Result<()> {
        let nix_expr = "builtins.randomHex 32";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let hex_string = value_to_string(output)?;

        // Verify length and hex characters
        assert_eq!(hex_string.len(), 32);
        assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            hex_string
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );

        Ok(())
    }

    #[test]
    fn test_random_hex_zero_length() -> Result<()> {
        let nix_expr = "builtins.randomHex 0";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let hex_string = value_to_string(output)?;
        assert_eq!(hex_string.len(), 0);

        Ok(())
    }

    #[test]
    fn test_random_hex_odd_length() -> Result<()> {
        let nix_expr = "builtins.randomHex 7";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let hex_string = value_to_string(output)?;
        assert_eq!(hex_string.len(), 7);
        assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));

        Ok(())
    }

    #[test]
    fn test_random_hex_different_each_time() -> Result<()> {
        let nix_expr1 = "builtins.randomHex 32";
        let nix_expr2 = "builtins.randomHex 32";
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        let hex1 = value_to_string(output1)?;
        let hex2 = value_to_string(output2)?;

        assert_ne!(hex1, hex2);

        Ok(())
    }

    // Tests for randomBase64 builtin
    #[test]
    fn test_random_base64_builtin() -> Result<()> {
        let nix_expr = "builtins.randomBase64 32";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let base64_string = value_to_string(output)?;

        // 32 bytes = 44 base64 characters (with padding)
        assert_eq!(base64_string.len(), 44);
        assert!(
            base64_string.ends_with("==")
                || base64_string.ends_with("=")
                || base64_string
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        );

        Ok(())
    }

    #[test]
    fn test_random_base64_zero_bytes() -> Result<()> {
        let nix_expr = "builtins.randomBase64 0";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let base64_string = value_to_string(output)?;
        assert_eq!(base64_string.len(), 0);

        Ok(())
    }

    #[test]
    fn test_random_base64_different_each_time() -> Result<()> {
        let nix_expr1 = "builtins.randomBase64 32";
        let nix_expr2 = "builtins.randomBase64 32";
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        let base64_1 = value_to_string(output1)?;
        let base64_2 = value_to_string(output2)?;

        assert_ne!(base64_1, base64_2);

        Ok(())
    }

    // Tests for passwordSafe builtin
    #[test]
    fn test_password_safe_builtin() -> Result<()> {
        let nix_expr = "builtins.passwordSafe 32";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let password = value_to_string(output)?;

        assert_eq!(password.len(), 32);
        // Verify only safe characters are used
        let safe_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+=.";
        assert!(password.chars().all(|c| safe_chars.contains(c)));

        Ok(())
    }

    #[test]
    fn test_password_safe_zero_length() -> Result<()> {
        let nix_expr = "builtins.passwordSafe 0";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let password = value_to_string(output)?;
        assert_eq!(password.len(), 0);

        Ok(())
    }

    #[test]
    fn test_password_safe_different_each_time() -> Result<()> {
        let nix_expr1 = "builtins.passwordSafe 32";
        let nix_expr2 = "builtins.passwordSafe 32";
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        let password1 = value_to_string(output1)?;
        let password2 = value_to_string(output2)?;

        assert_ne!(password1, password2);

        Ok(())
    }

    #[test]
    fn test_password_safe_no_dangerous_chars() -> Result<()> {
        // Generate a longer password to have higher probability of hitting special chars
        let nix_expr = "builtins.passwordSafe 256";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let password = value_to_string(output)?;

        // These characters can cause issues in shell scripts, config files, etc.
        let dangerous_chars = "\"'`\\$!#&|;<>(){}[]^~*?";
        assert!(!password.chars().any(|c| dangerous_chars.contains(c)));

        Ok(())
    }

    // Tests for uuid builtin
    #[test]
    fn test_uuid_builtin() -> Result<()> {
        let nix_expr = "builtins.uuid {}";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let uuid = value_to_string(output)?;

        // UUID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|&c| c == '-').count(), 4);

        // Verify dashes are in correct positions
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);

        // Verify version 4 (character at position 14 should be '4')
        assert_eq!(uuid.chars().nth(14), Some('4'));

        // Verify variant (character at position 19 should be 8, 9, a, or b)
        let variant_char = uuid.chars().nth(19).unwrap();
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b',
            "Invalid variant character: {}",
            variant_char
        );

        // Verify all characters are hex (except dashes)
        assert!(uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert!(
            uuid.chars()
                .filter(|c| c.is_ascii())
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );

        Ok(())
    }

    #[test]
    fn test_uuid_different_each_time() -> Result<()> {
        let nix_expr1 = "builtins.uuid {}";
        let nix_expr2 = "builtins.uuid {}";
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        let uuid1 = value_to_string(output1)?;
        let uuid2 = value_to_string(output2)?;

        assert_ne!(uuid1, uuid2);

        Ok(())
    }

    // Tests for rsaKey builtin
    #[test]
    fn test_rsa_key_builtin_default() -> Result<()> {
        // Test the rsaKey builtin with default key size (4096)
        let nix_expr = "(builtins.rsaKey {}).secret";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let private_key = value_to_string(output)?;

        // Verify it's a PEM private key
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(private_key.len() > 1000); // RSA 4096 private key is substantial

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_public_key() -> Result<()> {
        // Test accessing the public key from the RSA key builtin
        let nix_expr = "(builtins.rsaKey {}).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify it's an SSH public key
        assert!(public_key.starts_with("ssh-rsa "));
        assert!(!public_key.contains('\n'));
        assert!(public_key.len() > 500); // RSA public key is substantial

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_with_2048_bits() -> Result<()> {
        // Test rsaKey with 2048 bit key size
        let nix_expr = "(builtins.rsaKey { keySize = 2048; }).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify it's an SSH public key
        assert!(public_key.starts_with("ssh-rsa "));
        assert!(public_key.len() > 350); // 2048-bit key has shorter public key

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_with_3072_bits() -> Result<()> {
        // Test rsaKey with 3072 bit key size
        let nix_expr = "(builtins.rsaKey { keySize = 3072; }).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify it's an SSH public key
        assert!(public_key.starts_with("ssh-rsa "));

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_with_4096_bits() -> Result<()> {
        // Test rsaKey with explicit 4096 bit key size
        let nix_expr = "(builtins.rsaKey { keySize = 4096; }).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify it's an SSH public key
        assert!(public_key.starts_with("ssh-rsa "));
        assert!(public_key.len() > 700); // 4096-bit key has longer public key

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_different_each_time() -> Result<()> {
        // Test that multiple calls generate different keys
        let nix_expr1 = "(builtins.rsaKey { keySize = 2048; }).public";
        let nix_expr2 = "(builtins.rsaKey { keySize = 2048; }).public";
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        let key1 = value_to_string(output1)?;
        let key2 = value_to_string(output2)?;

        assert_ne!(key1, key2);

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_invalid_key_size() {
        // Test with invalid key size - should fail
        let nix_expr = "builtins.rsaKey { keySize = 1024; }";
        let current_dir = current_dir().unwrap();

        let result = eval_nix_expression(nix_expr, &current_dir);
        assert!(result.is_err());
    }
}
