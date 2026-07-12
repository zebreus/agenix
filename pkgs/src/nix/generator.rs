//! This module contains functions to call the generator nix expression
//! global state is not use here besides via builtins.getSecret and builtins.getPublic

use super::eval::{eval_nix_expression, value_to_string};
use cached::proc_macro::cached;
use rootcause::Report;
use rootcause::markers::Cloneable;
use rootcause::markers::SendSync;
use rootcause::report;
use snix_eval::NixString;
use snix_eval::Value;
use std::env::current_dir;
use std::path::PathBuf;

/// Represents the output of a generator function.
///
/// A generator can return:
/// - A string (becomes `secret`, no `public`)
/// - An attrset with `secret` only: `{ secret = "value"; }`
/// - An attrset with `public` only: `{ public = "value"; }`
/// - An attrset with both: `{ secret = "value"; public = "value"; }`
///
/// The `public` only form is useful for generating metadata that other secrets
/// can depend on without actually encrypting any data.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratorOutput {
    /// The secret content to encrypt into an age-encrypted `.age` file.
    ///
    /// When `None`, no encrypted file is created (public-only generator).
    /// This is useful for generating metadata that other secrets can depend on.
    pub secret: Option<String>,

    /// The public content to write to a `.pub` file.
    ///
    /// When `Some`, a `.age.pub` file is created containing this content.
    /// This is typically used for SSH public keys, age public keys, or
    /// other metadata that should be available without decryption.
    /// When `None`, no `.pub` file is created.
    pub public: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GeneratorInput {
    pub known_entries: Vec<String>,
}

impl GeneratorInput {
    fn to_nix_expr(&self) -> String {
        let mut expr = String::from("{ ");

        expr.push_str("secrets = { ");
        for name in &self.known_entries {
            expr.push_str(&format!("\"{}\" = builtins.getSecret \"{}\"; ", name, name));
        }
        expr.push_str("}; ");

        expr.push_str("publics = { ");
        for name in &self.known_entries {
            expr.push_str(&format!("\"{}\" = builtins.getPublic \"{}\"; ", name, name));
        }
        expr.push_str("}; ");

        expr
    }
}

/// Returns to a nix function that maps a name to either {} or { generator = ... , hasPublic = ... , hasSecret = ... }
/// depending on whether a known implicit generator exists for the name
pub(super) fn get_implicit_generator_nix_expr() -> String {
    r#"(name: (let
          lowercaseName = builtins.replaceStrings
            ["A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M"
             "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z"]
            ["a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m"
             "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z"]
            "${{name}}";
          
          hasSuffix = suffix: builtins.match ".*${suffix}$" lowercaseName != null;
          
          in
            if hasSuffix "ed25519" || hasSuffix "ssh" || hasSuffix "ssh_key"
            then { generator = builtins.sshKey; hasPublic = true; hasSecret = true; }
            else if hasSuffix "x25519"
            then { generator = builtins.ageKey; hasPublic = true; hasSecret = true; }
            else if hasSuffix "_wg" || hasSuffix "_wireguard"
            then { generator = builtins.wireguardKey; hasPublic = true; hasSecret = true; }
            else if hasSuffix "password" || hasSuffix "passphrase"
            then { generator = (_: builtins.randomString 32); hasSecret = true; }
            else { }))"#
        .to_string()
}

/// Returns to a nix function that maps a secrets.nix and a name to either {} or { generator = ... , hasPublic = ... , hasSecret = ... }
/// depending on whether a explicit or implicit generator is set.
/// generator = null means that there is explicitly no generator set.
/// hasPublic from the secrets.nix entry has precedence over the value inferred from the implicit generator output.
pub(super) fn get_entry_with_implicit_generator() -> String {
    r#"(rules: name: (let
          raw_entry = rules."${name}";
          implicitGeneratorAttrset = {get_implicit_generator_nix_expr} name;

          implicitHasSecretPublic = if builtins.hasAttr "hasSecret" raw_entry && raw_entry.hasSecret == false then
            { hasSecret = false; hasPublic = true; }
          else { hasSecret = true; hasPublic = false; };
        
          entry = if builtins.hasAttr "generator" raw_entry
            then raw_entry
            else ( implicitHasSecretPublic // implicitGeneratorAttrset // raw_entry );
          in
          entry
          ))"#
    .to_string()
}

/// Build a Nix expression that evaluates a generator with automatic fallback
fn build_generator_nix_expression(rules_path: &str, name: &str, generator_args: &str) -> String {
    format!(
        r#"(let
          rules = import {rules_path};
          
          generatorAttrset = {get_entry_with_implicit_generator} rules {name};
          
          callGenerator = gen:
            if builtins.isFunction gen
            then gen ({generator_args})
            else gen;
          
          result =
            if builtins.hasAttr "generator" generatorAttrset
            then callGenerator generatorAttrset.generator
            else null;
        in
          builtins.deepSeq result result)"#,
        get_entry_with_implicit_generator = get_entry_with_implicit_generator(),
    )
}

/// Parse generator output from Nix evaluation result
fn parse_generator_output(output: Value) -> Result<GeneratorOutput, Report> {
    const SECRET_KEY: &[u8; 6] = b"secret";
    const PUBLIC_KEY: &[u8; 6] = b"public";

    match output {
        Value::Null | Value::AttrNotFound => Ok(GeneratorOutput {
            secret: None,
            public: None,
        }),
        Value::String(s) => Ok(GeneratorOutput {
            secret: Some(s.as_str()?.to_owned()),
            public: None,
        }),
        Value::Attrs(attrs) => {
            let secret = attrs
                .select("secret")
                .map(|v| value_to_string(&v))
                .transpose()?;
            let public = attrs
                .select("public")
                .map(|v| value_to_string(&v))
                .transpose()?;

            // At least one of secret or public must be present
            if secret.is_none() && public.is_none() {
                return Err(report!(
                    "The attrset returned by `generator` must have at least 'secret' or 'public' key. Fix the generator function."
                ));
            }

            Ok(GeneratorOutput { secret, public })
        }
        _ => Err(report!(
            "The `generator` function must return string or attrset with 'secret' and/or 'public' keys",
        ).attach(format!("but it returned: {:?}", output))),
    }
}

/// Internal function that accepts a custom context for the generator
pub fn call_generator(
    secrets_nix_path: &PathBuf,
    current_dir: &PathBuf,
    name: &str,
    input: GeneratorInput,
) -> Result<GeneratorOutput, Report> {
    let nix_expr = build_generator_nix_expression(
        secrets_nix_path.to_str().unwrap(),
        &name,
        &input.to_nix_expr(),
    );

    match eval_nix_expression(nix_expr.as_str(), &current_dir) {
        Ok(output) => parse_generator_output(output),
        Err(e) => Err(e),
    }
}
