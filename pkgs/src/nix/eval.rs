//! Nix expression evaluation utilities.
//!
//! Provides functions for evaluating Nix expressions and converting Nix values
//! to Rust types.

use anyhow::{Context, Result, anyhow};
use snix_eval::EvaluationBuilder;
use snix_eval::Value;
use std::path::Path;

/// Extract a string from a thunk by parsing its debug representation.
///
/// Note: This is a workaround needed because snix_eval doesn't currently provide
/// a proper API to evaluate thunks. The debug format parsing is fragile and should
/// be replaced with proper thunk evaluation once available in the upstream library.
fn extract_string_from_thunk(thunk: &dyn std::fmt::Debug) -> Result<String> {
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

pub fn eval_nix_expression(expr: &str, path: &Path) -> Result<Value> {
    let path = std::path::absolute(path).with_context(|| {
        format!(
            "Failed to get absolute path for evaluation at {}",
            path.display()
        )
    })?;

    let builder = EvaluationBuilder::new_impure();
    let evaluation = builder
        .add_builtins(crate::nix::builtins::impure_builtins::builtins())
        .build();
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

pub fn value_to_string_array(value: Value) -> Result<Vec<String>> {
    match value {
        Value::List(arr) => arr
            .into_iter()
            .map(|v| match v {
                Value::String(s) => Ok(s.as_str().map(std::string::ToString::to_string)?),
                Value::Thunk(ref thunk) => extract_string_from_thunk(thunk),
                _ => Err(anyhow!("Expected string public key, got: {v:?}")),
            })
            .collect::<Result<Vec<_>, _>>(),
        _ => Err(anyhow!(
            "Expected JSON array for public keys, got: {value:?}"
        )),
    }
}

pub fn value_to_string(v: Value) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.as_str().map(std::string::ToString::to_string)?),
        Value::Thunk(ref thunk) => extract_string_from_thunk(thunk),
        _ => Err(anyhow!("Expected string public key, got: {v:?}")),
    }
}

pub fn value_to_bool(value: &Value) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(anyhow!("Expected boolean value, got: {value:?}")),
    }
}

pub fn value_to_optional_string(value: Value) -> Result<Option<String>> {
    match value {
        Value::Null => Ok(None),
        _ => value_to_string(value).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::current_dir;

    // Test to verify error message formatting is captured in anyhow
    #[test]
    fn test_formatted_error_capture() -> Result<()> {
        // This test verifies that Nix errors are properly captured with formatting
        let result = eval_nix_expression("import /nonexistent/path/to/rules.nix", &current_dir()?);

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
}
