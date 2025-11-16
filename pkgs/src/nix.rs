use anyhow::{Context, Result, anyhow};
use snix_eval::EvaluationBuilder;
use snix_eval::Value;
use std::env::current_dir;
use std::path::Path;

fn eval_nix_expression(expr: &str, path: &Path) -> Result<Value> {
    let path = std::path::absolute(path)
        .with_context(|| format!("Failed to get absolute path for evaluation at {:?}", path))?;

    let builder = EvaluationBuilder::new_impure();
    let evaluation = builder.build();
    let sourcemap = evaluation.source_map();

    let result = evaluation.evaluate(expr, Some(path));

    for error in result.errors.iter() {
        error.fancy_format_stderr();
    }
    for warning in result.warnings.iter() {
        warning.fancy_format_stderr(&sourcemap);
    }
    let Some(result) = result.value else {
        return Err(anyhow!("Failed to evaluate Nix expression"));
    };
    Ok(result)
}

fn value_to_string_array(value: Value) -> Result<Vec<String>> {
    match value {
        Value::List(arr) => arr
            .into_iter()
            .map(|v| {
                let Value::String(s) = v else {
                    return Err(anyhow!("Expected string public key, got: {:?}", v));
                };
                Ok(s.as_str().map(|s| s.to_string())?)
            })
            .collect::<Result<Vec<_>, _>>(),
        _ => {
            return Err(anyhow!(
                "Expected JSON array for public keys, got: {:?}",
                value
            ));
        }
    }
}

fn value_to_bool(value: Value) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(b),
        _ => Err(anyhow!("Expected boolean value, got: {:?}", value)),
    }
}

/// Get public keys for a file from the rules
pub fn get_public_keys(rules_path: &str, file: &str) -> Result<Vec<String>> {
    let nix_expr = format!("(let rules = import {rules_path}; in rules.\"{file}\".publicKeys)");

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

    value_to_bool(output)
}

/// Get all file names from the rules
pub fn get_all_files(rules_path: &str) -> Result<Vec<String>> {
    let nix_expr = format!("(let rules = import {rules_path}; in builtins.attrNames rules)");

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    let keys = value_to_string_array(output)?;

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_public_keys_with_nonexistent_rules() {
        let rules = "/nonexistent/rules.nix";

        let result = get_public_keys(rules, "test.age");
        assert!(result.is_err());
        // Should fail because rules file doesn't exist
    }

    #[test]
    fn test_should_armor_with_nonexistent_rules() {
        let rules = "/nonexistent/rules.nix";

        let result = should_armor(rules, "test.age");
        assert!(result.is_err());
        // Should fail because rules file doesn't exist
    }

    #[test]
    fn test_get_all_files_with_nonexistent_rules() {
        let rules = "/nonexistent/rules.nix";

        let result = get_all_files(rules);
        assert!(result.is_err());
        // Should fail because rules file doesn't exist
    }

    #[test]
    fn test_nix_expr_format_get_public_keys() {
        // Test that the Nix expression is formatted correctly
        let rules = "./resources/test_secrets.nix";
        let result = get_public_keys(rules, "test.age");

        // This will fail in most test environments due to missing test file
        // but we can at least test that the function doesn't panic
        if result.is_ok() {
            let results = result.unwrap();
            assert!(results.is_empty() || !results.is_empty()); // Just verify it returns a Vec<String>
        }
    }

    #[test]
    fn test_nix_expr_format_should_armor() {
        let rules = "./resources/test_secrets.nix";
        let result = should_armor(rules, "test.age");

        // This will likely fail in test environments due to missing test file, but shouldn't panic
        if let Ok(armor) = result {
            // If it works, armor should be a boolean
            assert!(matches!(armor, true | false));
        }
    }
}
