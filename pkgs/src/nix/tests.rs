#[cfg(test)]
mod tests {
    use crate::nix::rules::resolve_public_key;
    use crate::nix::value_conversion::value_to_string;
    use crate::nix::*;
    use anyhow::{Result, anyhow};
    use snix_eval::Value;
    use std::env::current_dir;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    // Helper function to create test Nix files
    fn create_test_rules_file(content: &str) -> Result<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "{}", content)?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    // Helper function to create a temporary directory with test files
    fn create_test_workspace() -> Result<(TempDir, String)> {
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8"
            ];
            armor = true;
          };
          "secret2.age" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
            ];
            armor = false;
          };
          "secret3.age" = {
            publicKeys = [ 
              "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5example"
            ];
            # No armor attribute - should default to false
          };
        }
        "#;

        fs::write(&rules_path, rules_content)?;
        Ok((temp_dir, rules_path.to_string_lossy().to_string()))
    }

    // Tests for get_public_keys() function
    #[test]
    fn test_get_public_keys_single_key() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_public_keys(temp_file.path().to_str().unwrap(), "test.age")?;

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        );
        Ok(())
    }

    #[test]
    fn test_get_public_keys_multiple_keys() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8"
            ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_public_keys(temp_file.path().to_str().unwrap(), "test.age")?;

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        );
        assert_eq!(
            result[1],
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8"
        );
        Ok(())
    }

    #[test]
    fn test_get_public_keys_empty_array() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_public_keys(temp_file.path().to_str().unwrap(), "test.age")?;

        assert_eq!(result.len(), 0);
        Ok(())
    }

    #[test]
    fn test_get_public_keys_nonexistent_file() {
        let result = get_public_keys("/nonexistent/rules.nix", "test.age");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_public_keys_nonexistent_secret() -> Result<()> {
        let rules_content = r#"
        {
          "other.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_public_keys(temp_file.path().to_str().unwrap(), "nonexistent.age");
        assert!(result.is_err());
        // Should fail because the secret doesn't exist in the rules
        Ok(())
    }

    #[test]
    fn test_get_public_keys_invalid_nix_syntax() {
        let invalid_content = "{ invalid nix syntax !!!";
        let temp_file = create_test_rules_file(invalid_content).unwrap();

        let result = get_public_keys(temp_file.path().to_str().unwrap(), "test.age");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_public_keys_wrong_type() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = "not-an-array";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_public_keys(temp_file.path().to_str().unwrap(), "test.age");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected JSON array")
        );
        Ok(())
    }

    #[test]
    fn test_get_public_keys_mixed_types_in_array() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              42
            ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_public_keys(temp_file.path().to_str().unwrap(), "test.age");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected string public key")
        );
        Ok(())
    }

    // Tests for should_armor() function
    #[test]
    fn test_should_armor_true() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            armor = true;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = should_armor(temp_file.path().to_str().unwrap(), "test.age")?;

        assert_eq!(result, true);
        Ok(())
    }

    #[test]
    fn test_should_armor_false() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            armor = false;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = should_armor(temp_file.path().to_str().unwrap(), "test.age")?;

        assert_eq!(result, false);
        Ok(())
    }

    #[test]
    fn test_should_armor_missing_attribute() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            # No armor attribute
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = should_armor(temp_file.path().to_str().unwrap(), "test.age")?;

        // Should default to false when armor attribute is missing
        assert_eq!(result, false);
        Ok(())
    }

    #[test]
    fn test_should_armor_nonexistent_file() {
        let result = should_armor("/nonexistent/rules.nix", "test.age");
        assert!(result.is_err());
    }

    #[test]
    fn test_should_armor_nonexistent_secret() -> Result<()> {
        let rules_content = r#"
        {
          "other.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            armor = true;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = should_armor(temp_file.path().to_str().unwrap(), "nonexistent.age");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_should_armor_wrong_type() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            armor = "not-a-boolean";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = should_armor(temp_file.path().to_str().unwrap(), "test.age");
        assert!(result.is_err());
        // The error is caught at Nix evaluation level - this is actually good behavior
        // as it catches type errors early in the Nix expression evaluation
        Ok(())
    }

    // Tests for get_all_files() function
    #[test]
    fn test_get_all_files_single_file() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_all_files(temp_file.path().to_str().unwrap())?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "test.age");
        Ok(())
    }

    #[test]
    fn test_get_all_files_multiple_files() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret2.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret3.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_all_files(temp_file.path().to_str().unwrap())?;

        assert_eq!(result.len(), 3);
        // Note: Nix attribute names might not preserve order
        assert!(result.contains(&"secret1.age".to_string()));
        assert!(result.contains(&"secret2.age".to_string()));
        assert!(result.contains(&"secret3.age".to_string()));
        Ok(())
    }

    #[test]
    fn test_get_all_files_empty_rules() -> Result<()> {
        let rules_content = "{ }";
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_all_files(temp_file.path().to_str().unwrap())?;

        assert_eq!(result.len(), 0);
        Ok(())
    }

    #[test]
    fn test_get_all_files_nonexistent_file() {
        let result = get_all_files("/nonexistent/rules.nix");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_all_files_invalid_nix() {
        let invalid_content = "{ invalid syntax !!!";
        let temp_file = create_test_rules_file(invalid_content).unwrap();

        let result = get_all_files(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_all_files_non_attrset_root() -> Result<()> {
        let rules_content = r#"[ "not" "an" "attrset" ]"#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_all_files(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
        // Should fail because builtins.attrNames expects an attribute set
        Ok(())
    }

    // Integration Tests
    #[test]
    fn test_integration_realistic_workflow() -> Result<()> {
        let (_temp_dir, rules_path) = create_test_workspace()?;

        // Test getting all files
        let all_files = get_all_files(&rules_path)?;
        assert_eq!(all_files.len(), 3);
        assert!(all_files.contains(&"secret1.age".to_string()));
        assert!(all_files.contains(&"secret2.age".to_string()));
        assert!(all_files.contains(&"secret3.age".to_string()));

        // Test getting public keys for each file
        let keys1 = get_public_keys(&rules_path, "secret1.age")?;
        assert_eq!(keys1.len(), 2);

        let keys2 = get_public_keys(&rules_path, "secret2.age")?;
        assert_eq!(keys2.len(), 1);

        let keys3 = get_public_keys(&rules_path, "secret3.age")?;
        assert_eq!(keys3.len(), 1);

        // Test armor settings
        assert_eq!(should_armor(&rules_path, "secret1.age")?, true);
        assert_eq!(should_armor(&rules_path, "secret2.age")?, false);
        assert_eq!(should_armor(&rules_path, "secret3.age")?, false); // Default

        Ok(())
    }

    #[test]
    fn test_integration_complex_nix_expressions() -> Result<()> {
        let rules_content = r#"
        let
          commonKeys = [
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8"
          ];
          adminKeys = [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5example"
          ];
        in
        {
          "database.age" = {
            publicKeys = commonKeys ++ adminKeys;
            armor = true;
          };
          "api-key.age" = {
            publicKeys = commonKeys;
            armor = false;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 2);

        let db_keys = get_public_keys(temp_file.path().to_str().unwrap(), "database.age")?;
        assert_eq!(db_keys.len(), 3); // 2 common + 1 admin key

        let api_keys = get_public_keys(temp_file.path().to_str().unwrap(), "api-key.age")?;
        assert_eq!(api_keys.len(), 2); // Only common keys

        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "database.age")?,
            true
        );
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "api-key.age")?,
            false
        );

        Ok(())
    }

    // Edge Case Tests
    #[test]
    fn test_special_characters_in_filenames() -> Result<()> {
        let rules_content = r#"
        {
          "secret-with-dashes.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret_with_underscores.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret.with.dots.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 3);

        // Test each special character filename
        let keys1 = get_public_keys(temp_file.path().to_str().unwrap(), "secret-with-dashes.age")?;
        assert_eq!(keys1.len(), 1);

        let keys2 = get_public_keys(
            temp_file.path().to_str().unwrap(),
            "secret_with_underscores.age",
        )?;
        assert_eq!(keys2.len(), 1);

        let keys3 = get_public_keys(temp_file.path().to_str().unwrap(), "secret.with.dots.age")?;
        assert_eq!(keys3.len(), 1);

        Ok(())
    }

    // Advanced and Creative Test Scenarios
    #[test]
    fn test_absolute_path_rules_file() -> Result<()> {
        let rules_content = r#"
        {
          "test.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let absolute_path = temp_file.path().canonicalize()?;

        let result = get_public_keys(absolute_path.to_str().unwrap(), "test.age")?;

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        );
        Ok(())
    }

    #[test]
    fn test_rules_file_with_imports() -> Result<()> {
        // Create a temporary directory structure
        let temp_dir = TempDir::new()?;

        // Create a common keys file
        let common_keys_path = temp_dir.path().join("common-keys.nix");
        let common_keys_content = r#"
        [
          "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8"
        ]
        "#;
        fs::write(&common_keys_path, common_keys_content)?;

        // Create main rules file that imports the common keys
        let rules_path = temp_dir.path().join("rules.nix");
        let rules_content = format!(
            r#"
        let
          commonKeys = import {};
          adminKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5admin";
        in
        {{
          "database.age" = {{
            publicKeys = commonKeys ++ [ adminKey ];
            armor = true;
          }};
          "config.age" = {{
            publicKeys = commonKeys;
            armor = false;
          }};
        }}
        "#,
            common_keys_path.to_str().unwrap()
        );
        fs::write(&rules_path, rules_content)?;

        // Test the imported configuration
        let all_files = get_all_files(rules_path.to_str().unwrap())?;
        assert_eq!(all_files.len(), 2);

        let db_keys = get_public_keys(rules_path.to_str().unwrap(), "database.age")?;
        assert_eq!(db_keys.len(), 3); // 2 common + 1 admin

        let config_keys = get_public_keys(rules_path.to_str().unwrap(), "config.age")?;
        assert_eq!(config_keys.len(), 2); // Just common keys

        assert_eq!(
            should_armor(rules_path.to_str().unwrap(), "database.age")?,
            true
        );
        assert_eq!(
            should_armor(rules_path.to_str().unwrap(), "config.age")?,
            false
        );

        Ok(())
    }

    #[test]
    fn test_deeply_nested_nix_expressions() -> Result<()> {
        let rules_content = r#"
        let
          mkSecret = name: keys: armor: {
            "${name}.age" = {
              publicKeys = keys;
            } // (if armor then { armor = true; } else {});
          };
          
          userKeys = {
            alice = "age1alice...";
            bob = "age1bob...";
            charlie = "age1charlie...";
          };
          
          teamKeys = builtins.attrValues userKeys;
          
          secrets = 
            (mkSecret "team-password" teamKeys true) //
            (mkSecret "alice-private" [ userKeys.alice ] false) //
            (mkSecret "shared-config" (teamKeys ++ [ "age1admin..." ]) true);
        in
        secrets
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 3);
        assert!(all_files.contains(&"team-password.age".to_string()));
        assert!(all_files.contains(&"alice-private.age".to_string()));
        assert!(all_files.contains(&"shared-config.age".to_string()));

        // Test armor settings based on function parameters
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "team-password.age")?,
            true
        );
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "alice-private.age")?,
            false
        );
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "shared-config.age")?,
            true
        );

        // Test key counts
        let team_keys = get_public_keys(temp_file.path().to_str().unwrap(), "team-password.age")?;
        assert_eq!(team_keys.len(), 3); // alice, bob, charlie

        let alice_keys = get_public_keys(temp_file.path().to_str().unwrap(), "alice-private.age")?;
        assert_eq!(alice_keys.len(), 1); // Just alice

        let shared_keys = get_public_keys(temp_file.path().to_str().unwrap(), "shared-config.age")?;
        assert_eq!(shared_keys.len(), 4); // alice, bob, charlie + admin

        Ok(())
    }

    #[test]
    fn test_unicode_and_special_characters() -> Result<()> {
        let rules_content = r#"
        {
          "secret-with-unicode-🔐.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret with spaces.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret@with#symbols%.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "путь/к/секрету.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 4);

        // Test Unicode filename
        let unicode_keys = get_public_keys(
            temp_file.path().to_str().unwrap(),
            "secret-with-unicode-🔐.age",
        )?;
        assert_eq!(unicode_keys.len(), 1);

        // Test spaces in filename
        let space_keys =
            get_public_keys(temp_file.path().to_str().unwrap(), "secret with spaces.age")?;
        assert_eq!(space_keys.len(), 1);

        // Test special symbols
        let symbol_keys = get_public_keys(
            temp_file.path().to_str().unwrap(),
            "secret@with#symbols%.age",
        )?;
        assert_eq!(symbol_keys.len(), 1);

        // Test Cyrillic characters
        let cyrillic_keys =
            get_public_keys(temp_file.path().to_str().unwrap(), "путь/к/секрету.age")?;
        assert_eq!(cyrillic_keys.len(), 1);

        Ok(())
    }

    #[test]
    fn test_very_large_configuration() -> Result<()> {
        let mut rules_content = String::from("{\n");

        // Generate 100 secrets with varying configurations
        (0..100).for_each(|i| {
            let armor = if i % 3 == 0 { "true" } else { "false" };
            let key_count = (i % 5) + 1; // 1-5 keys per secret

            let keys_str: String = (0..key_count)
                .map(|j| format!("\"age1key{}user{}example\"", i, j))
                .collect::<Vec<_>>()
                .join(" ");

            rules_content.push_str(&format!(
                "  \"secret-{:03}.age\" = {{\n    publicKeys = [ {} ];\n    armor = {};\n  }};\n",
                i, keys_str, armor
            ));
        });

        rules_content.push_str("}\n");

        let temp_file = create_test_rules_file(&rules_content)?;

        // Test that we can handle large configurations
        let start_time = std::time::Instant::now();
        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        let duration = start_time.elapsed();

        assert_eq!(all_files.len(), 100);

        // Performance check - should complete within reasonable time
        assert!(
            duration.as_millis() < 2000,
            "Large config took too long: {:?}",
            duration
        );

        // Spot check a few secrets
        let keys_0 = get_public_keys(temp_file.path().to_str().unwrap(), "secret-000.age")?;
        assert_eq!(keys_0.len(), 1); // 0 % 5 + 1 = 1

        let keys_7 = get_public_keys(temp_file.path().to_str().unwrap(), "secret-007.age")?;
        assert_eq!(keys_7.len(), 3); // 7 % 5 + 1 = 3

        // Check armor settings
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "secret-000.age")?,
            true
        ); // 0 % 3 == 0
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "secret-001.age")?,
            false
        ); // 1 % 3 != 0
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "secret-003.age")?,
            true
        ); // 3 % 3 == 0

        Ok(())
    }

    #[test]
    fn test_conditional_configuration() -> Result<()> {
        let rules_content = r#"
        let
          isDevelopment = true;
          isProduction = false;
          
          devKeys = [ "age1dev..." ];
          prodKeys = [ "age1prod1..." "age1prod2..." ];
          adminKey = "age1admin...";
          
          mkConditionalSecret = name: condition: keys: {
            "${name}.age" = if condition then {
              publicKeys = keys ++ [ adminKey ];
              armor = true;
            } else {
              publicKeys = keys;
              armor = false;
            };
          };
        in
        (mkConditionalSecret "dev-secret" isDevelopment devKeys) //
        (mkConditionalSecret "prod-secret" isProduction prodKeys) //
        {
          "always-present.age" = {
            publicKeys = [ adminKey ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 3);

        // Dev secret should include admin key (condition is true)
        let dev_keys = get_public_keys(temp_file.path().to_str().unwrap(), "dev-secret.age")?;
        assert_eq!(dev_keys.len(), 2); // devKey + adminKey
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "dev-secret.age")?,
            true
        );

        // Prod secret should not include admin key (condition is false)
        let prod_keys = get_public_keys(temp_file.path().to_str().unwrap(), "prod-secret.age")?;
        assert_eq!(prod_keys.len(), 2); // Just prodKeys, no admin
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "prod-secret.age")?,
            false
        );

        Ok(())
    }

    #[test]
    fn test_relative_path_imports() -> Result<()> {
        // Create a nested directory structure
        let temp_dir = TempDir::new()?;
        let subdir = temp_dir.path().join("config");
        fs::create_dir_all(&subdir)?;

        // Create keys file in subdirectory
        let keys_path = subdir.join("keys.nix");
        fs::write(
            &keys_path,
            r#"
        {
          admin = "age1admin...";
          user1 = "age1user1...";
          user2 = "age1user2...";
        }
        "#,
        )?;

        // Create rules file that imports with relative path
        let rules_path = temp_dir.path().join("secrets.nix");
        let rules_content = r#"
        let
          keys = import ./config/keys.nix;
        in
        {
          "admin-only.age" = {
            publicKeys = [ keys.admin ];
            armor = true;
          };
          "user-shared.age" = {
            publicKeys = [ keys.user1 keys.user2 ];
            armor = false;
          };
          "everyone.age" = {
            publicKeys = builtins.attrValues keys;
          };
        }
        "#;
        fs::write(&rules_path, rules_content)?;

        // Test the configuration
        let all_files = get_all_files(rules_path.to_str().unwrap())?;
        assert_eq!(all_files.len(), 3);

        let admin_keys = get_public_keys(rules_path.to_str().unwrap(), "admin-only.age")?;
        assert_eq!(admin_keys.len(), 1);
        assert_eq!(admin_keys[0], "age1admin...");

        let user_keys = get_public_keys(rules_path.to_str().unwrap(), "user-shared.age")?;
        assert_eq!(user_keys.len(), 2);

        let everyone_keys = get_public_keys(rules_path.to_str().unwrap(), "everyone.age")?;
        assert_eq!(everyone_keys.len(), 3);

        Ok(())
    }

    #[test]
    fn test_dynamic_attribute_names() -> Result<()> {
        let rules_content = r#"
        let
          environments = [ "dev" "staging" "prod" ];
          
          mkEnvSecret = env: {
            "${env}-database.age" = {
              publicKeys = [ "age1${env}..." ];
              armor = env == "prod";
            };
            "${env}-api-key.age" = {
              publicKeys = [ "age1${env}..." "age1admin..." ];
              armor = false;
            };
          };
          
          envSecrets = builtins.foldl' (acc: env: acc // (mkEnvSecret env)) {} environments;
        in
        envSecrets // {
          "global-config.age" = {
            publicKeys = [ "age1global..." ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 7); // 3 envs * 2 secrets each + 1 global = 7

        // Check environment-specific files exist
        assert!(all_files.contains(&"dev-database.age".to_string()));
        assert!(all_files.contains(&"staging-api-key.age".to_string()));
        assert!(all_files.contains(&"prod-database.age".to_string()));
        assert!(all_files.contains(&"global-config.age".to_string()));

        // Check armor settings (only prod-database should be armored)
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "dev-database.age")?,
            false
        );
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "staging-database.age")?,
            false
        );
        assert_eq!(
            should_armor(temp_file.path().to_str().unwrap(), "prod-database.age")?,
            true
        );

        // Check key counts (api-key files should have 2 keys, others 1)
        let dev_db_keys = get_public_keys(temp_file.path().to_str().unwrap(), "dev-database.age")?;
        assert_eq!(dev_db_keys.len(), 1);

        let dev_api_keys = get_public_keys(temp_file.path().to_str().unwrap(), "dev-api-key.age")?;
        assert_eq!(dev_api_keys.len(), 2);

        Ok(())
    }

    #[test]
    fn test_error_handling_in_complex_expressions() -> Result<()> {
        // Test with recursive function that might cause evaluation errors
        let rules_content = r#"
        let
          # This creates a potentially problematic recursive structure
          mkRecursive = depth: 
            if depth <= 0 then {}
            else {
              "secret-${toString depth}.age" = {
                publicKeys = [ "age1level${toString depth}..." ];
              };
            } // (mkRecursive (depth - 1));
        in
        mkRecursive 5
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 5);

        // Verify all levels were created correctly
        (1..=5).try_for_each(|i| -> Result<()> {
            let filename = format!("secret-{}.age", i);
            assert!(all_files.contains(&filename));

            let keys = get_public_keys(temp_file.path().to_str().unwrap(), &filename)?;
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], format!("age1level{}...", i));
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_path_traversal_protection() -> Result<()> {
        // Test that we handle potentially problematic paths safely
        let rules_content = r#"
        {
          "../../../etc/passwd.age" = {
            publicKeys = [ "age1hacker..." ];
          };
          "./normal-file.age" = {
            publicKeys = [ "age1normal..." ];
          };
          "/absolute/path/secret.age" = {
            publicKeys = [ "age1absolute..." ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let all_files = get_all_files(temp_file.path().to_str().unwrap())?;
        assert_eq!(all_files.len(), 3);

        // All paths should be treated as literal strings, not interpreted as filesystem paths
        assert!(all_files.contains(&"../../../etc/passwd.age".to_string()));
        assert!(all_files.contains(&"./normal-file.age".to_string()));
        assert!(all_files.contains(&"/absolute/path/secret.age".to_string()));

        // Should be able to query them normally
        let keys1 = get_public_keys(
            temp_file.path().to_str().unwrap(),
            "../../../etc/passwd.age",
        )?;
        assert_eq!(keys1.len(), 1);

        let keys2 = get_public_keys(temp_file.path().to_str().unwrap(), "./normal-file.age")?;
        assert_eq!(keys2.len(), 1);

        let keys3 = get_public_keys(
            temp_file.path().to_str().unwrap(),
            "/absolute/path/secret.age",
        )?;
        assert_eq!(keys3.len(), 1);

        Ok(())
    }

    // Test to verify error message formatting is captured in anyhow
    #[test]
    fn test_formatted_error_capture() -> Result<()> {
        // This test verifies that Nix errors are properly captured with formatting
        let result = get_public_keys("/nonexistent/path/to/rules.nix", "test.age");

        match result {
            Err(err) => {
                let error_string = err.to_string();

                // The error should contain our formatted Nix error message
                assert!(error_string.contains("Failed to evaluate Nix expression"));
                assert!(error_string.contains("Errors:"));
                assert!(error_string.contains("No such file or directory"));

                Ok(())
            }
            Ok(_) => {
                // This should not succeed with a nonexistent file
                panic!("Expected an error but got success");
            }
        }
    }

    // #[test]
    // fn funky_test() {
    //     let invalid_content = "{result = let x = 8; in y: x + y;}"; // Invalid because 'y' is undefined

    //     let result = eval_nix_expression(
    //         "{result = let x = 8; in y: x + y;}.result",
    //         current_dir().unwrap().as_path(),
    //     );
    //     let result = result.unwrap();
    //     let func_result = result.as_closure().unwrap();
    //     // func_result.
    //     let mut lambda = func_result.lambda.clone();
    //     let chunk = func_result.chunk();
    //     eprintln!("{:?}", chunk.disassemble_op(writer, source, width, idx));
    // }

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
        // Note: Nix attribute names might not preserve order
        Ok(())
    }

    #[test]
    fn test_secret_generator_builtins() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: builtins.randomString 16;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret(temp_file.path().to_str().unwrap(), "secret1.age")?;
        let result1 = result.unwrap();
        assert_eq!(result1.len(), 16);
        let result = generate_secret(temp_file.path().to_str().unwrap(), "secret1.age")?;
        let result2 = result.unwrap();
        assert_eq!(result2.len(), 16);
        assert_ne!(result1, result2); // Should be different random strings
        Ok(())
    }

    #[test]
    fn test_generate_ssh_key_builtin() -> Result<()> {
        let rules_content = r#"
        {
          "ssh-key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: (builtins.sshKey {}).secret;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret(temp_file.path().to_str().unwrap(), "ssh-key.age")?;
        let private_key = result.unwrap();

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
    fn test_base64_roundtrip() -> Result<()> {
        let test_data = b"Hello, World! This is a test string for base64 encoding.";

        // Use the same base64 implementation as our SSH key generation
        use base64::{Engine as _, engine::general_purpose};
        let encoded = general_purpose::STANDARD.encode(test_data);
        let decoded = general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|e| anyhow!("Base64 decode error: {}", e))?;

        assert_eq!(test_data.as_slice(), decoded.as_slice());

        Ok(())
    }

    // Tests for generate_secret_with_public function
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
    fn test_generate_secret_with_public_attrset_secret_only() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { secret = "only-secret"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, "only-secret");
        assert_eq!(output.public, None);
        Ok(())
    }

    #[test]
    fn test_generate_secret_with_public_attrset_missing_secret() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { public = "only-public"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age");

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must have 'secret' key")
        );
        Ok(())
    }

    #[test]
    fn test_generate_secret_with_public_no_generator() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert_eq!(result, None);
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
    fn test_generate_secret_with_public_random_string() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: 
              let secret = builtins.randomString 32;
              in { secret = secret; public = "metadata-for-${secret}"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Verify secret is the expected length
        assert_eq!(output.secret.len(), 32);

        // Verify public contains the reference to the secret
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("metadata-for-"));

        Ok(())
    }

    // Tests for age x25519 keypair generation
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

    #[test]
    fn test_age_key_builtin() -> Result<()> {
        // Test the ageKey builtin function
        let rules_content = r#"
        {
          "age-key.age" = {
          publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          generator = { }: (builtins.ageKey {}).secret;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret(temp_file.path().to_str().unwrap(), "age-key.age")?;
        let private_key = result.unwrap();

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

    #[test]
    fn test_generate_age_keypair_with_public() -> Result<()> {
        // Test using ageKey in a generator that returns both secret and public
        let rules_content = r#"
        {
          "age-key.age" = {
          publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          generator = builtins.ageKey;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "age-key.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Verify it's an age secret key
        assert!(output.secret.starts_with("AGE-SECRET-KEY-1"));
        assert!(!output.secret.contains('\n'));

        // Verify the public key is in age format
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("age1"));
        assert!(!public.contains('\n'));

        Ok(())
    }

    // Tests for automatic generator selection based on file endings
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
    fn test_age_key_can_encrypt_decrypt() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Generate an age keypair using the builtin
        let nix_expr = "builtins.ageKey {}";
        let current_dir = current_dir()?;
        let output = eval_nix_expression(nix_expr, &current_dir)?;

        let attrs = match output {
            Value::Attrs(attrs) => attrs,
            _ => panic!("Expected attribute set"),
        };

        let (private_key, public_key) =
            attrs
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

        // Create temporary files for testing encryption/decryption
        let mut plaintext_file = NamedTempFile::new()?;
        let encrypted_file = NamedTempFile::new()?;
        let decrypted_file = NamedTempFile::new()?;
        let mut identity_file = NamedTempFile::new()?;

        // Write test content
        let test_content = "Hello, age encryption!";
        plaintext_file.write_all(test_content.as_bytes())?;
        plaintext_file.flush()?;

        // Write identity to file
        writeln!(identity_file, "{}", private_key)?;
        identity_file.flush()?;

        // Encrypt with the public key
        use crate::crypto::encrypt_from_file;
        encrypt_from_file(
            plaintext_file.path().to_str().unwrap(),
            encrypted_file.path().to_str().unwrap(),
            &[public_key.clone()],
            false,
        )?;

        // Decrypt with the private key
        use crate::crypto::decrypt_to_file;
        decrypt_to_file(
            encrypted_file.path().to_str().unwrap(),
            decrypted_file.path(),
            Some(identity_file.path().to_str().unwrap()),
        )?;

        // Verify content matches
        let decrypted_content = std::fs::read_to_string(decrypted_file.path())?;
        assert_eq!(test_content, decrypted_content);
        Ok(())
    }

    fn test_auto_generator_ssh_ending() -> Result<()> {
        let rules_content = r#"
        {
          "deployment-ssh.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "deployment-ssh.age")?;

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
    fn test_auto_generator_ssh_key_ending() -> Result<()> {
        let rules_content = r#"
        {
          "server_ssh_key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "server_ssh_key.age")?;

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
    fn test_auto_generator_passphrase_ending() -> Result<()> {
        let rules_content = r#"
        {
          "backup-passphrase.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret_with_public(
            temp_file.path().to_str().unwrap(),
            "backup-passphrase.age",
        )?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate a 32-character random string
        assert_eq!(output.secret.len(), 32);
        assert!(output.public.is_none()); // Random string doesn't have public output

        Ok(())
    }

    #[test]
    fn test_auto_generator_case_insensitive() -> Result<()> {
        let rules_content = r#"
        {
          "MyKey-ED25519.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "Database-PASSWORD.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        // Test uppercase ED25519
        let result1 =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "MyKey-ED25519.age")?;
        assert!(result1.is_some());
        let output1 = result1.unwrap();
        assert!(output1.secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(output1.public.is_some());

        // Test uppercase PASSWORD
        let result2 = generate_secret_with_public(
            temp_file.path().to_str().unwrap(),
            "Database-PASSWORD.age",
        )?;
        assert!(result2.is_some());
        let output2 = result2.unwrap();
        assert_eq!(output2.secret.len(), 32);
        assert!(output2.public.is_none());

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

    // Tests for secret reference resolution
    #[test]
    fn test_resolve_public_key_actual_ssh_key() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        let ssh_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8";
        let result = resolve_public_key(rules_dir, ssh_key)?;

        // Should return the key unchanged
        assert_eq!(result, ssh_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_actual_age_key() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        let age_key = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let result = resolve_public_key(rules_dir, age_key)?;

        // Should return the key unchanged
        assert_eq!(result, age_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_secret_reference_with_age_suffix() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        // Create a .pub file for the secret
        let pub_file = rules_dir.join("my-ssh-key.age.pub");
        let public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8";
        std::fs::write(&pub_file, format!("{}\n", public_key))?;

        // Reference with .age suffix
        let result = resolve_public_key(rules_dir, "my-ssh-key.age")?;

        // Should resolve to the public key
        assert_eq!(result, public_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_secret_reference_without_age_suffix() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        // Create a .pub file for the secret
        let pub_file = rules_dir.join("my-ssh-key.age.pub");
        let public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8";
        std::fs::write(&pub_file, format!("{}\n", public_key))?;

        // Reference without .age suffix
        let result = resolve_public_key(rules_dir, "my-ssh-key")?;

        // Should resolve to the public key
        assert_eq!(result, public_key);
        Ok(())
    }

    #[test]
    fn test_resolve_public_key_nonexistent_reference() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let rules_dir = temp_dir.path();

        // Reference to a non-existent secret
        let result = resolve_public_key(rules_dir, "nonexistent-key")?;

        // Should return the original string
        assert_eq!(result, "nonexistent-key");
        Ok(())
    }

    #[test]
    fn test_get_public_keys_with_secret_reference() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Create a public key file
        let pub_file = temp_dir.path().join("deploy-key.age.pub");
        let deploy_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeployKeyPublicKeyExample";
        std::fs::write(&pub_file, format!("{}\n", deploy_public_key))?;

        // Create a rules file that references the secret
        let rules_path = temp_dir.path().join("secrets.nix");
        let rules_content = r#"
        {
          "deploy-key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret-using-deploy-key.age" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              "deploy-key"
            ];
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_public_keys(rules_path.to_str().unwrap(), "secret-using-deploy-key.age")?;

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        );
        assert_eq!(result[1], deploy_public_key);

        Ok(())
    }

    #[test]
    fn test_get_public_keys_with_mixed_keys_and_references() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Create multiple public key files
        let ssh_key_pub = temp_dir.path().join("server-ssh.age.pub");
        let ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIServerSSHKey";
        std::fs::write(&ssh_key_pub, format!("{}\n", ssh_public_key))?;

        let age_key_pub = temp_dir.path().join("backup-key.age.pub");
        let age_public_key = "age1abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuv";
        std::fs::write(&age_key_pub, format!("{}\n", age_public_key))?;

        // Create a rules file with mixed public keys and references
        let rules_path = temp_dir.path().join("secrets.nix");
        let rules_content = r#"
        {
          "server-ssh.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "backup-key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "app-secret.age" = {
            publicKeys = [ 
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDirectPublicKey"
              "server-ssh"
              "age1directagekey1234567890abcdefghijklmnopqrstuvwxyz12345678"
              "backup-key.age"
            ];
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_public_keys(rules_path.to_str().unwrap(), "app-secret.age")?;

        assert_eq!(result.len(), 4);
        assert_eq!(
            result[0],
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDirectPublicKey"
        ); // Direct SSH key
        assert_eq!(result[1], ssh_public_key); // Resolved from server-ssh
        assert_eq!(
            result[2],
            "age1directagekey1234567890abcdefghijklmnopqrstuvwxyz12345678"
        ); // Direct age key
        assert_eq!(result[3], age_public_key); // Resolved from backup-key.age

        Ok(())
    }

    #[test]
    fn test_get_public_keys_reference_with_generated_ssh_key() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Simulate a generated SSH keypair (only the .pub file would exist)
        let ssh_key_pub = temp_dir.path().join("generated-deploy-key.age.pub");
        let ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeneratedDeployKey";
        std::fs::write(&ssh_key_pub, format!("{}\n", ssh_public_key))?;

        // Create a rules file where one secret uses another's public key
        let rules_path = temp_dir.path().join("secrets.nix");
        let rules_content = r#"
        {
          "generated-deploy-key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: builtins.sshKey {};
          };
          "authorized-keys.age" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              "generated-deploy-key"
            ];
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_public_keys(rules_path.to_str().unwrap(), "authorized-keys.age")?;

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        );
        assert_eq!(result[1], ssh_public_key);

        Ok(())
    }
}
