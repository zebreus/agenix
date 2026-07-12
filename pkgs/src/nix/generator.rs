//! Calling generator functions from secrets.nix.
//!
//! A generator receives `{ secrets, publics }` where both attrsets map every
//! entry name to a lazy `builtins.getSecret`/`builtins.getPublic` thunk.
//! Forcing a thunk re-enters the resolution engine, so a generator can use
//! other secrets without any explicit dependency ordering.

use super::eval::{eval_nix_expression, value_to_string};
use super::raw_secret_entry::{effective_entry_nix, nix_string_literal};
use rootcause::{Report, prelude::*, report};
use snix_eval::Value;
use std::path::Path;

/// What a generator produced. A generator returns either a plain string
/// (secret only) or an attrset with `secret` and/or `public` strings.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratorOutput {
    pub secret: Option<String>,
    pub public: Option<String>,
}

/// Run the generator of `name` and return its output.
///
/// Must only be called for entries that have a generator.
pub fn call_generator(
    rules_path: &Path,
    dir: &Path,
    name: &str,
    known_names: &[String],
) -> Result<GeneratorOutput, Report> {
    let rules_path_str = rules_path
        .to_str()
        .ok_or_else(|| report!("Path to secrets.nix is not valid UTF-8"))?;

    let nix_expr = format!(
        r#"let
          rules = import {rules_path_str};
          entry = {effective_entry} rules {name_literal};
          generator = entry.generator;
          result =
            if generator == null
            then throw "Entry '{name}' has no generator"
            else if builtins.isFunction generator
            then generator {args}
            else generator;
        in builtins.deepSeq result result"#,
        effective_entry = effective_entry_nix(),
        name_literal = nix_string_literal(name),
        args = generator_args_nix(known_names),
    );

    let output = eval_nix_expression(&nix_expr, dir)?;
    parse_generator_output(output)
}

/// The `{ secrets, publics }` argument passed to generator functions.
/// Every value is a lazy thunk; nothing is resolved until the generator
/// actually uses it.
fn generator_args_nix(known_names: &[String]) -> String {
    let thunks = |builtin: &str| {
        known_names
            .iter()
            .map(|name| {
                let literal = nix_string_literal(name);
                format!("{literal} = builtins.{builtin} {literal}; ")
            })
            .collect::<String>()
    };
    format!(
        "{{ secrets = {{ {} }}; publics = {{ {} }}; }}",
        thunks("getSecret"),
        thunks("getPublic"),
    )
}

/// Parse a generator result: a string, or an attrset with `secret` and/or
/// `public` string values.
fn parse_generator_output(output: Value) -> Result<GeneratorOutput, Report> {
    match output {
        Value::String(s) => Ok(GeneratorOutput {
            secret: Some(s.as_str()?.to_owned()),
            public: None,
        }),
        Value::Attrs(attrs) => {
            let secret = attrs
                .select("secret")
                .map(|v| value_to_string(&v))
                .transpose()
                .context("Invalid 'secret' in generator output")?;
            let public = attrs
                .select("public")
                .map(|v| value_to_string(&v))
                .transpose()
                .context("Invalid 'public' in generator output")?;

            if secret.is_none() && public.is_none() {
                return Err(report!(
                    "The attrset returned by the generator must contain a \
                     'secret' and/or 'public' key"
                ));
            }
            Ok(GeneratorOutput { secret, public })
        }
        wrong => Err(report!(
            "A generator must return a string or an attrset with 'secret' \
             and/or 'public' keys"
        )
        .attach(format!("got: {wrong:?}"))),
    }
}
