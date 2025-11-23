//! Custom Nix builtins for secret generation.
//!
//! Provides `randomString`, `sshKey`, and `ageKey` builtins for use in
//! Nix expressions to generate secrets and keypairs.

use snix_eval::builtin_macros;

#[builtin_macros::builtins]
pub mod impure_builtins {
    use rand::Rng;
    use rand::distr::Alphanumeric;
    use rand::rng;
    use snix_eval::ErrorKind;
    use snix_eval::NixString;
    use snix_eval::Value;
    use snix_eval::generators::Gen;
    use snix_eval::generators::GenCo;

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

    /// Generates an SSH Ed25519 keypair
    #[builtin("sshKey")]
    async fn builtin_ssh_key(co: GenCo, _var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_ed25519_keypair;
        use snix_eval::NixAttrs;
        use std::collections::BTreeMap;

        // Generate the SSH keypair
        let (private_key, public_key) = generate_ed25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate SSH keypair: {}", e)))?;

        // Create a Nix attribute set with `secret` and `public`
        let mut attrs: BTreeMap<NixString, Value> = BTreeMap::new();
        attrs.insert(
            NixString::from("secret".as_bytes()),
            Value::String(NixString::from(private_key.as_bytes())),
        );
        attrs.insert(
            NixString::from("public".as_bytes()),
            Value::String(NixString::from(public_key.as_bytes())),
        );

        Ok(Value::Attrs(Box::new(NixAttrs::from(attrs))))
    }

    /// Generates an age x25519 keypair
    #[builtin("ageKey")]
    async fn builtin_age_key(co: GenCo, _var: Value) -> Result<Value, ErrorKind> {
        use crate::nix::keypair::generate_age_x25519_keypair;
        use snix_eval::NixAttrs;
        use std::collections::BTreeMap;

        // Generate the age x25519 keypair
        let (private_key, public_key) = generate_age_x25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate age keypair: {}", e)))?;

        // Create a Nix attribute set with `secret` and `public`
        let mut attrs: BTreeMap<NixString, Value> = BTreeMap::new();
        attrs.insert(
            NixString::from("secret".as_bytes()),
            Value::String(NixString::from(private_key.as_bytes())),
        );
        attrs.insert(
            NixString::from("public".as_bytes()),
            Value::String(NixString::from(public_key.as_bytes())),
        );

        Ok(Value::Attrs(Box::new(NixAttrs::from(attrs))))
    }
}

#[cfg(test)]
mod tests {
    use crate::nix::eval::eval_nix_expression;
    use crate::nix::eval::value_to_string;
    use anyhow::Result;
    use snix_eval::Value;
    use std::env::current_dir;

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
        // Get public keys from both calls

        // Keys should be different each time
        assert_ne!(public1, public2);
        assert_ne!(private1, private2);
        eprintln!("public1: {}", public1);

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
}
