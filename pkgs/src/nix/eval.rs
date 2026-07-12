//! Nix expression evaluation and value conversion.

use rootcause::markers::SendSync;
use rootcause::report;
use rootcause::report_collection::ReportCollection;
use rootcause::{Report, prelude::*};
use snix_eval::{EvaluationBuilder, Value};
use std::any::Any;
use std::path::Path;

/// Evaluate a Nix expression with the agenix builtins available.
///
/// `path` is the location the expression is evaluated at; relative paths in
/// the expression resolve against it.
pub fn eval_nix_expression(expr: &str, path: &Path) -> Result<Value, Report> {
    let path = std::path::absolute(path).context("Failed to make evaluation path absolute")?;

    let evaluation = EvaluationBuilder::new_impure()
        .add_builtins(super::builtins::impure_builtins::builtins())
        .build();
    let sourcemap = evaluation.source_map();

    let result = evaluation.evaluate(expr, Some(path));

    let Some(value) = result.value else {
        let mut reports: ReportCollection<dyn Any, SendSync> = ReportCollection::new();
        for error in &result.errors {
            reports.push(report!("{}", error.fancy_format_str()).into_cloneable());
        }
        for warning in &result.warnings {
            reports.push(report!("{}", warning.fancy_format_str(&sourcemap)).into_cloneable());
        }
        return Err(reports
            .context("Failed to evaluate Nix expression")
            .into_dyn_any());
    };

    Ok(value)
}

pub fn value_to_string(value: &Value) -> Result<String, Report> {
    match value {
        Value::String(s) => Ok(s.as_str().map(ToString::to_string)?),
        Value::Thunk(thunk) => value_to_string(&thunk.value()),
        wrong => Err(report!("Expected string").attach(format!("got: {wrong:?}"))),
    }
}

pub fn value_to_bool(value: &Value) -> Result<bool, Report> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::Thunk(thunk) => value_to_bool(&thunk.value()),
        wrong => Err(report!("Expected boolean").attach(format!("got: {wrong:?}"))),
    }
}

pub fn value_to_string_array(value: &Value) -> Result<Vec<String>, Report> {
    match value {
        Value::List(list) => list.into_iter().map(value_to_string).collect(),
        Value::Thunk(thunk) => value_to_string_array(&thunk.value()),
        wrong => Err(report!("Expected list of strings").attach(format!("got: {wrong:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::current_dir;

    #[test]
    fn test_formatted_error_capture() {
        let result = eval_nix_expression(
            "import /nonexistent/path/to/rules.nix",
            &current_dir().unwrap(),
        );

        let error_string = format!("{:?}", result.unwrap_err());
        assert!(error_string.contains("Failed to evaluate Nix expression"));
        assert!(error_string.contains("No such file or directory"));
    }

    #[test]
    fn test_simple_evaluation() {
        let value = eval_nix_expression(r#""hello" + " world""#, &current_dir().unwrap()).unwrap();
        assert_eq!(value_to_string(&value).unwrap(), "hello world");
    }
}
