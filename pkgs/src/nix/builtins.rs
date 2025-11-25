//! Custom Nix builtins for secret generation.
//!
//! Provides builtins for generating secrets and keypairs:
//! - Random strings: `randomString`, `randomHex`, `randomBase64`, `passwordSafe`
//! - UUIDs: `uuid`
//! - Keypairs: `sshKey` (Ed25519), `rsaKey` (RSA), `ageKey` (x25519)
//! - Hash functions: `blake2b`, `blake2s`, `keccak`

use snix_eval::builtin_macros;

#[builtin_macros::builtins]
pub mod impure_builtins {
    use base64::{Engine as _, engine::general_purpose};
    use rand::distr::Alphanumeric;
    use rand::{Rng, rng};
    use snix_eval::generators::{Gen, GenCo};
    use snix_eval::{ErrorKind, NixAttrs, NixString, Value};
    use std::collections::BTreeMap;

    /// Maximum length for random string generation (2^16).
    const MAX_LENGTH: i64 = 65536;

    /// Validates length argument for random generators.
    fn validate_length(length: i64, name: &str) -> Result<usize, ErrorKind> {
        if length < 0 || length > MAX_LENGTH {
            return Err(ErrorKind::Abort(format!(
                "{}: length must be between 0 and {}",
                name, MAX_LENGTH
            )));
        }
        Ok(length as usize)
    }

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

    /// Computes a BLAKE2b-512 hash of a string.
    #[builtin("blake2b")]
    async fn builtin_blake2b(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        use cosmian_crypto_core::blake2::{Blake2b512, Digest};
        let _ = co;
        let data = var
            .to_str()
            .map_err(|_| ErrorKind::Abort("blake2b: argument must be a string".into()))?;
        let mut hasher = Blake2b512::new();
        hasher.update(data.as_bytes());
        Ok(Value::String(NixString::from(
            hex::encode(hasher.finalize()).as_bytes(),
        )))
    }

    /// Computes a BLAKE2s-256 hash of a string.
    #[builtin("blake2s")]
    async fn builtin_blake2s(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        use cosmian_crypto_core::blake2::{Blake2s256, Digest};
        let _ = co;
        let data = var
            .to_str()
            .map_err(|_| ErrorKind::Abort("blake2s: argument must be a string".into()))?;
        let mut hasher = Blake2s256::new();
        hasher.update(data.as_bytes());
        Ok(Value::String(NixString::from(
            hex::encode(hasher.finalize()).as_bytes(),
        )))
    }

    /// Computes a SHA3-256 (Keccak) hash of a string.
    #[builtin("keccak")]
    async fn builtin_keccak(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        use cosmian_crypto_core::reexport::tiny_keccak::{Hasher, Sha3};
        let _ = co;
        let data = var
            .to_str()
            .map_err(|_| ErrorKind::Abort("keccak: argument must be a string".into()))?;
        let mut hasher = Sha3::v256();
        hasher.update(data.as_bytes());
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        Ok(Value::String(NixString::from(
            hex::encode(result).as_bytes(),
        )))
    }

    /// Generates a random alphanumeric string of given length.
    #[builtin("randomString")]
    async fn builtin_random_string(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let _ = co;
        let len = validate_length(var.as_int()?, "randomString")?;
        let s: String = rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect();
        Ok(Value::String(NixString::from(s.as_bytes())))
    }

    /// Generates a random hexadecimal string of given length.
    #[builtin("randomHex")]
    async fn builtin_random_hex(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let _ = co;
        let len = validate_length(var.as_int()?, "randomHex")?;
        let byte_count = (len + 1) / 2;
        let mut bytes = vec![0u8; byte_count];
        rng().fill(&mut bytes[..]);
        let hex: String = bytes
            .iter()
            .flat_map(|b| [b >> 4, b & 0x0f])
            .take(len)
            .map(|n| {
                if n < 10 {
                    (b'0' + n) as char
                } else {
                    (b'a' + n - 10) as char
                }
            })
            .collect();
        Ok(Value::String(NixString::from(hex.as_bytes())))
    }

    /// Generates a random base64-encoded string from given number of bytes.
    #[builtin("randomBase64")]
    async fn builtin_random_base64(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let _ = co;
        let len = validate_length(var.as_int()?, "randomBase64")?;
        let mut bytes = vec![0u8; len];
        rng().fill(&mut bytes[..]);
        let b64 = general_purpose::STANDARD.encode(&bytes);
        Ok(Value::String(NixString::from(b64.as_bytes())))
    }

    /// Generates a random password-safe string (alphanumeric + `-_+=.`).
    #[builtin("passwordSafe")]
    async fn builtin_password_safe(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+=.";
        let _ = co;
        let len = validate_length(var.as_int()?, "passwordSafe")?;
        let mut rng = rng();
        let password: String = (0..len)
            .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
            .collect();
        Ok(Value::String(NixString::from(password.as_bytes())))
    }

    /// Generates a random UUIDv4 string.
    #[builtin("uuid")]
    async fn builtin_uuid(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let _ = (co, var);
        let mut bytes = [0u8; 16];
        rng().fill(&mut bytes);
        // Set version to 4 and variant to RFC 4122
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
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

    /// Generates an SSH Ed25519 keypair.
    #[builtin("sshKey")]
    async fn builtin_ssh_key(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_ed25519_keypair;
        let _ = (co, var);
        let (private_key, public_key) = generate_ed25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate SSH keypair: {}", e)))?;
        Ok(create_keypair_attrset(private_key, public_key))
    }

    /// Generates an age x25519 keypair.
    #[builtin("ageKey")]
    async fn builtin_age_key(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_age_x25519_keypair;
        let _ = (co, var);
        let (private_key, public_key) = generate_age_x25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate age keypair: {}", e)))?;
        Ok(create_keypair_attrset(private_key, public_key))
    }

    /// Generates an RSA SSH keypair with configurable key size (2048, 3072, 4096).
    #[builtin("rsaKey")]
    async fn builtin_rsa_key(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_rsa_keypair;
        let _ = co;
        let key_size = match &var {
            Value::Attrs(attrs) => {
                if let Some(v) = attrs.select(NixString::from("keySize".as_bytes()).as_ref()) {
                    v.as_int()? as u32
                } else {
                    4096
                }
            }
            _ => 4096,
        };
        if !matches!(key_size, 2048 | 3072 | 4096) {
            return Err(ErrorKind::Abort(format!(
                "Invalid RSA key size: {}. Valid sizes: 2048, 3072, 4096",
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

        let (private1, public1) = extract_keypair(output1)?;
        let (private2, public2) = extract_keypair(output2)?;

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
        // Test the rsaKey builtin with explicit 2048 key size (faster than default 4096)
        let nix_expr = "(builtins.rsaKey { keySize = 2048; }).secret";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let private_key = value_to_string(output)?;

        // Verify it's a PEM private key
        assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_key.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(private_key.len() > 1000); // RSA private key is substantial

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_public_key() -> Result<()> {
        // Test accessing the public key from the RSA key builtin (use 2048 for speed)
        let nix_expr = "(builtins.rsaKey { keySize = 2048; }).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify it's an SSH public key
        assert!(public_key.starts_with("ssh-rsa "));
        assert!(!public_key.contains('\n'));
        assert!(public_key.len() > 350); // RSA public key is substantial

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

    #[test]
    fn test_rsa_key_builtin_consistency() -> Result<()> {
        // Test that both secret and public keys are generated consistently
        let nix_expr = "builtins.rsaKey { keySize = 2048; }";
        let current_dir = current_dir()?;

        let output = eval_nix_expression(nix_expr, &current_dir)?;
        let (secret, public) = extract_keypair(output)?;

        // Verify both keys are present and valid
        assert!(secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(secret.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(public.starts_with("ssh-rsa "));
        assert!(!public.contains('\n'));

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_key_size_affects_length() -> Result<()> {
        // Test that larger key sizes produce longer keys
        let nix_expr_2048 = "builtins.rsaKey { keySize = 2048; }";
        let nix_expr_4096 = "builtins.rsaKey { keySize = 4096; }";
        let current_dir = current_dir()?;

        let output_2048 = eval_nix_expression(nix_expr_2048, &current_dir)?;
        let output_4096 = eval_nix_expression(nix_expr_4096, &current_dir)?;

        let (secret_2048, public_2048) = extract_keypair(output_2048)?;
        let (secret_4096, public_4096) = extract_keypair(output_4096)?;

        // 4096-bit keys should be significantly larger than 2048-bit keys
        assert!(secret_4096.len() > secret_2048.len());
        assert!(public_4096.len() > public_2048.len());

        // Verify approximate size expectations
        assert!(secret_2048.len() > 1000);
        assert!(secret_4096.len() > 3000);
        assert!(public_2048.len() > 350);
        assert!(public_4096.len() > 700);

        Ok(())
    }

    #[test]
    fn test_rsa_key_builtin_invalid_key_size_512() {
        // Test with 512 bit key size - should fail
        let nix_expr = "builtins.rsaKey { keySize = 512; }";
        let current_dir = current_dir().unwrap();

        let result = eval_nix_expression(nix_expr, &current_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_key_builtin_invalid_key_size_8192() {
        // Test with 8192 bit key size - should fail (not supported)
        let nix_expr = "builtins.rsaKey { keySize = 8192; }";
        let current_dir = current_dir().unwrap();

        let result = eval_nix_expression(nix_expr, &current_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_key_builtin_public_key_format() -> Result<()> {
        // Test that RSA public key is in valid SSH format
        let nix_expr = "(builtins.rsaKey { keySize = 2048; }).public";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let public_key = value_to_string(output)?;

        // Verify SSH public key format
        assert!(public_key.starts_with("ssh-rsa "));
        let base64_part = &public_key[8..]; // Skip "ssh-rsa "

        // The base64 part should be valid base64
        assert!(
            base64_part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        );

        // Decode and verify SSH wire format
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

    // Tests for blake2b builtin
    #[test]
    fn test_blake2b() -> Result<()> {
        let nix_expr = r#"builtins.blake2b "hello""#;
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let hash = value_to_string(output)?;

        // Blake2b-512 produces 128 hex characters
        assert_eq!(hash.len(), 128);
        // Verify it's valid hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        Ok(())
    }

    #[test]
    fn test_blake2b_different_data() -> Result<()> {
        let nix_expr1 = r#"builtins.blake2b "hello""#;
        let nix_expr2 = r#"builtins.blake2b "world""#;
        let current_dir = current_dir()?;

        let output1 = eval_nix_expression(nix_expr1, &current_dir)?;
        let output2 = eval_nix_expression(nix_expr2, &current_dir)?;

        let hash1 = value_to_string(output1)?;
        let hash2 = value_to_string(output2)?;

        // Verify they're different
        assert_ne!(hash1, hash2);
        assert_eq!(hash1.len(), 128);
        assert_eq!(hash2.len(), 128);

        Ok(())
    }

    // Tests for blake2s builtin
    #[test]
    fn test_blake2s() -> Result<()> {
        let nix_expr = r#"builtins.blake2s "hello""#;
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let hash = value_to_string(output)?;

        // Blake2s-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        // Verify it's valid hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        Ok(())
    }

    // Tests for keccak builtin (SHA3-256)
    #[test]
    fn test_keccak() -> Result<()> {
        let nix_expr = r#"builtins.keccak "hello""#;
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let hash = value_to_string(output)?;

        // SHA3-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        // Known SHA3-256 hash of "hello"
        assert_eq!(
            hash,
            "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
        );

        Ok(())
    }

    #[test]
    fn test_keccak_different_data() -> Result<()> {
        let nix_expr = r#"builtins.keccak "world""#;
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let hash = value_to_string(output)?;

        // Verify it's different from "hello"
        assert_ne!(
            hash,
            "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
        );
        assert_eq!(hash.len(), 64);

        Ok(())
    }
}
