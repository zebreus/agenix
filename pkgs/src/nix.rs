use anyhow::{Context, Result, anyhow};
use snix_eval::EvaluationBuilder;
use snix_eval::Value;
use snix_eval::builtin_macros;
use std::env::current_dir;
use std::path::Path;

#[builtin_macros::builtins]
mod impure_builtins {
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
        if length < 0 && length > 2i64.pow(16) {
            // TODO use better error kind
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
}

pub fn eval_nix_expression(expr: &str, path: &Path) -> Result<Value> {
    let path = std::path::absolute(path).with_context(|| {
        format!(
            "Failed to get absolute path for evaluation at {}",
            path.display()
        )
    })?;

    let builder = EvaluationBuilder::new_impure();
    let evaluation = builder.add_builtins(impure_builtins::builtins()).build();
    let sourcemap = evaluation.source_map();

    let result = evaluation.evaluate(expr, Some(path));

    // Capture formatted errors and warnings instead of printing directly
    let error_messages: Vec<String> = result
        .errors
        .iter()
        .map(snix_eval::Error::fancy_format_str)
        .collect();

    let warning_messages: Vec<String> = result
        .warnings
        .iter()
        .map(|warning| warning.fancy_format_str(&sourcemap))
        .collect();

    let Some(result) = result.value else {
        // Include captured errors and warnings in the anyhow error
        let mut error_msg = "Failed to evaluate Nix expression".to_string();

        if !error_messages.is_empty() {
            error_msg.push_str("\n\nErrors:\n");
            error_msg.push_str(&error_messages.join("\n"));
        }

        if !warning_messages.is_empty() {
            error_msg.push_str("\n\nWarnings:\n");
            error_msg.push_str(&warning_messages.join("\n"));
        }

        return Err(anyhow!("{error_msg}"));
    };

    // If there are warnings but evaluation succeeded, we could optionally log them
    // For now, we'll just proceed silently with warnings

    Ok(result)
}

fn value_to_string_array(value: Value) -> Result<Vec<String>> {
    match value {
        Value::List(arr) => arr
            .into_iter()
            .map(|v| {
                match v {
                    Value::String(s) => Ok(s.as_str().map(std::string::ToString::to_string)?),
                    Value::Thunk(thunk) => {
                        // Try to extract the value from the thunk
                        let debug_str = format!("{thunk:?}");
                        // Look for pattern: Thunk(RefCell { value: Evaluated(String("...")) })
                        if let Some(start) = debug_str.find("Evaluated(String(\"") {
                            let start = start + "Evaluated(String(\"".len();
                            if let Some(end) = debug_str[start..].find("\"))") {
                                let extracted = &debug_str[start..start + end];
                                return Ok(extracted.to_string());
                            }
                        }
                        Err(anyhow!("Could not extract string from thunk: {thunk:?}"))
                    }
                    _ => Err(anyhow!("Expected string public key, got: {v:?}")),
                }
            })
            .collect::<Result<Vec<_>, _>>(),
        _ => Err(anyhow!(
            "Expected JSON array for public keys, got: {value:?}"
        )),
    }
}

fn value_to_string(v: Value) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.as_str().map(std::string::ToString::to_string)?),
        Value::Thunk(thunk) => {
            // Try to extract the value from the thunk
            let debug_str = format!("{thunk:?}");
            // Look for pattern: Thunk(RefCell { value: Evaluated(String("...")) })
            if let Some(start) = debug_str.find("Evaluated(String(\"") {
                let start = start + "Evaluated(String(\"".len();
                if let Some(end) = debug_str[start..].find("\"))") {
                    let extracted = &debug_str[start..start + end];
                    return Ok(extracted.to_string());
                }
            }
            Err(anyhow!("Could not extract string from thunk: {thunk:?}"))
        }
        _ => Err(anyhow!("Expected string public key, got: {v:?}")),
    }
}

fn value_to_bool(value: &Value) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(anyhow!("Expected boolean value, got: {value:?}")),
    }
}

fn value_to_optional_string(value: Value) -> Result<Option<String>> {
    match value {
        Value::Null => Ok(None),
        _ => value_to_string(value).map(Some),
    }
}

/// Get public keys for a file from the rules
pub fn get_public_keys(rules_path: &str, file: &str) -> Result<Vec<String>> {
    let nix_expr = format!(
        "(let rules = import {rules_path}; keys = rules.\"{file}\".publicKeys; in builtins.deepSeq keys keys)"
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    let keys = value_to_string_array(output)?;

    Ok(keys)
}

/// Check if a file should be armored (ASCII-armored output)
pub fn should_armor(rules_path: &str, file: &str) -> Result<bool> {
    let nix_expr = format!(
        "(let rules = import {rules_path}; in (builtins.hasAttr \"armor\" rules.\"{file}\" && rules.\"{file}\".armor))",
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    value_to_bool(&output)
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

/// Get all file names from the rules
pub fn get_all_files(rules_path: &str) -> Result<Vec<String>> {
    let nix_expr = format!(
        "(let rules = import {rules_path}; names = builtins.attrNames rules; in builtins.deepSeq names names)"
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    let keys = value_to_string_array(output)?;

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
