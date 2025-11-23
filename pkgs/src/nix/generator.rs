use anyhow::{Result, anyhow};
use snix_eval::{NixString, Value};
use std::env::current_dir;

use crate::nix::evaluation::eval_nix_expression;
use crate::nix::value_conversion::{value_to_optional_string, value_to_string};

/// Represents the output of a generator function
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratorOutput {
    pub secret: String,
    pub public: Option<String>,
}

/// Check if a file should be armored (ASCII-armored output)
pub fn generate_secret(rules_path: &str, file: &str) -> Result<Option<String>> {
    let nix_expr = format!(
        "(let rules = import {rules_path}; in if builtins.hasAttr \"generator\" rules.\"{file}\" then (rules.\"{file}\".generator {{}}) else null)",
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    value_to_optional_string(output)
}

/// Get the generator output for a file, handling both string and attrset outputs
/// If no explicit generator is provided, automatically selects a generator based on the file ending:
/// - Files ending with "ed25519", "ssh", or "ssh_key" use builtins.sshKey (SSH Ed25519 keypair)
/// - Files ending with "x25519" use builtins.ageKey (age x25519 keypair)
/// - Files ending with "password" or "passphrase" use builtins.randomString 32
pub fn generate_secret_with_public(
    rules_path: &str,
    file: &str,
) -> Result<Option<GeneratorOutput>> {
    // Build Nix expression that checks for explicit generator or uses automatic selection
    let nix_expr = format!(
        r#"(let 
          rules = import {rules_path};
          name = builtins.replaceStrings ["A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M" "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z"] ["a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z"] "{file}";
          hasSuffix = s: builtins.match ".*${{s}}(\.age)?$" name != null;
          auto = 
            if hasSuffix "ed25519" || hasSuffix "ssh" || hasSuffix "ssh_key" 
            then builtins.sshKey
            else if hasSuffix "x25519"
            then builtins.ageKey
            else if hasSuffix "password" || hasSuffix "passphrase"
            then (_: builtins.randomString 32)
            else null;
          result = if builtins.hasAttr "generator" rules."{file}"
                   then rules."{file}".generator {{}}
                   else if auto != null then auto {{}} else null;
        in builtins.deepSeq result result)"#,
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    // Commonly used attribute names as constants
    const SECRET_KEY: &[u8] = b"secret";
    const PUBLIC_KEY: &[u8] = b"public";

    match output {
        Value::Null => Ok(None),
        Value::String(s) => {
            // Generator returned just a string - this is the secret
            Ok(Some(GeneratorOutput {
                secret: s.as_str()?.to_owned(),
                public: None,
            }))
        }
        Value::Attrs(attrs) => {
            // Generator returned an attrset - extract secret and public
            let secret = attrs
                .select(NixString::from(SECRET_KEY).as_ref())
                .ok_or_else(|| anyhow!("Generator attrset must have 'secret' key"))?;
            let secret_str = value_to_string(secret.clone())?;

            let public = attrs
                .select(NixString::from(PUBLIC_KEY).as_ref())
                .map(|v| value_to_string(v.clone()))
                .transpose()?;

            Ok(Some(GeneratorOutput {
                secret: secret_str,
                public,
            }))
        }
        _ => Err(anyhow!(
            "Generator must return either a string or an attrset with 'secret' and optional 'public' keys, got: {:?}",
            output
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper function to create test Nix files
    fn create_test_rules_file(content: &str) -> Result<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "{}", content)?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    #[test]
    fn test_basic_generator_functionality() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "generated-secret";
          };
          "secret2.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert_eq!(result, Some("generated-secret".to_string()));
        let result2 = generate_secret(temp_file.path().to_str().unwrap(), "secret2.age")?;
        assert_eq!(result2, None);
        Ok(())
    }

    #[test]
    fn test_generate_secret_with_public_string_only() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "just-a-secret";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, "just-a-secret");
        assert_eq!(output.public, None);
        Ok(())
    }

    #[test]
    fn test_generate_secret_with_public_attrset() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { secret = "my-secret"; public = "my-public-key"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, "my-secret");
        assert_eq!(output.public, Some("my-public-key".to_string()));
        Ok(())
    }

    #[test]
    fn test_generate_secret_with_public_ssh_key() -> Result<()> {
        let rules_content = r#"
        {
          "ssh-key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "ssh-key.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Verify it's a PEM private key
        assert!(output.secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(output.secret.contains("-----END PRIVATE KEY-----"));

        // Verify the public key is in SSH format
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("ssh-ed25519 "));
        assert!(!public.contains('\n'));

        Ok(())
    }

    #[test]
    fn test_auto_generator_ed25519_ending() -> Result<()> {
        let rules_content = r#"
        {
          "my-key-ed25519.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "my-key-ed25519.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate an SSH keypair automatically
        assert!(output.secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("ssh-ed25519 "));

        Ok(())
    }

    #[test]
    fn test_auto_generator_x25519_ending() -> Result<()> {
        let rules_content = r#"
        {
          "identity-x25519.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "identity-x25519.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate an age x25519 keypair automatically
        assert!(output.secret.starts_with("AGE-SECRET-KEY-"));
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("age1"));

        Ok(())
    }

    #[test]
    fn test_auto_generator_password_ending() -> Result<()> {
        let rules_content = r#"
        {
          "database-password.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret_with_public(
            temp_file.path().to_str().unwrap(),
            "database-password.age",
        )?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate a 32-character random string
        assert_eq!(output.secret.len(), 32);
        assert!(output.public.is_none()); // Random string doesn't have public output

        Ok(())
    }

    #[test]
    fn test_auto_generator_no_match() -> Result<()> {
        let rules_content = r#"
        {
          "random-secret.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "random-secret.age")?;

        // Should return None when no matching ending and no explicit generator
        assert_eq!(result, None);

        Ok(())
    }

    #[test]
    fn test_explicit_generator_overrides_auto() -> Result<()> {
        let rules_content = r#"
        {
          "my-password.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "custom-fixed-value";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "my-password.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should use explicit generator, not auto-generated random string
        assert_eq!(output.secret, "custom-fixed-value");
        assert!(output.public.is_none());

        Ok(())
    }
}
