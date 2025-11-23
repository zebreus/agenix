use anyhow::{Context, Result};
use std::env::current_dir;
use std::path::Path;

use crate::nix::evaluation::eval_nix_expression;
use crate::nix::value_conversion::{value_to_bool, value_to_string_array};

/// Resolve a potential secret reference to a public key
/// If the key_str looks like a public key (starts with ssh-, age1, etc.), return it as-is
/// If it looks like a secret name, try to read the corresponding .pub file
pub(crate) fn resolve_public_key(rules_dir: &Path, key_str: &str) -> Result<String> {
    // Check if this looks like an actual public key
    if key_str.starts_with("ssh-") || key_str.starts_with("age1") || key_str.starts_with("sk-") {
        return Ok(key_str.to_string());
    }

    // Try to resolve as a secret reference
    // Remove .age suffix if present to get the base secret name
    let secret_name = if key_str.ends_with(".age") {
        &key_str[..key_str.len() - 4]
    } else {
        key_str
    };

    // Try both with and without .age suffix for the pub file
    let pub_file_paths = [
        rules_dir.join(format!("{}.age.pub", secret_name)),
        rules_dir.join(format!("{}.pub", secret_name)),
    ];

    for pub_file_path in &pub_file_paths {
        if pub_file_path.exists() {
            let public_key = std::fs::read_to_string(pub_file_path)
                .with_context(|| {
                    format!(
                        "Failed to read public key file: {}",
                        pub_file_path.display()
                    )
                })?
                .trim()
                .to_string();
            return Ok(public_key);
        }
    }

    // If no .pub file found, return the original string (might be a public key we don't recognize)
    Ok(key_str.to_string())
}

/// Get public keys for a file from the rules
pub fn get_public_keys(rules_path: &str, file: &str) -> Result<Vec<String>> {
    let nix_expr = format!(
        "(let rules = import {rules_path}; keys = rules.\"{file}\".publicKeys; in builtins.deepSeq keys keys)"
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    let keys = value_to_string_array(output)?;

    // Resolve any secret references to actual public keys
    let rules_path_obj = Path::new(rules_path);
    let rules_dir = rules_path_obj.parent().unwrap_or_else(|| Path::new("."));

    let resolved_keys: Result<Vec<String>> = keys
        .into_iter()
        .map(|key| resolve_public_key(rules_dir, &key))
        .collect();

    resolved_keys
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
}
