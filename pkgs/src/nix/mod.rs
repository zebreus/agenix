//! Nix expression evaluation and secret management integration.
//!
//! This module provides functionality for evaluating Nix expressions to extract
//! public keys, file lists, and generator configurations from rules files.

pub mod builtins;
pub mod eval;
pub mod keypair;

use anyhow::{Context, Result};
use eval::{eval_nix_expression, value_to_bool, value_to_string, value_to_string_array};
use snix_eval::NixString;
use snix_eval::Value;
use std::env::current_dir;
use std::path::Path;

/// Check if a string looks like an actual public key (not a secret reference)
/// SSH keys have format: "ssh-TYPE BASE64DATA" or "sk-ssh-... ..."
/// Age keys start with "age1" and are Bech32 encoded (no spaces)
fn is_actual_public_key(key_str: &str) -> bool {
    // Age public keys: start with "age1" and contain no spaces
    if key_str.starts_with("age1") && !key_str.contains(' ') {
        return true;
    }

    // SSH public keys: must have a space (format: "ssh-type base64data [comment]")
    // Also handle sk- prefixed keys (security key)
    if (key_str.starts_with("ssh-")
        || key_str.starts_with("sk-ssh-")
        || key_str.starts_with("sk-ecdsa-"))
        && key_str.contains(' ')
    {
        return true;
    }

    false
}

/// Resolve a potential secret reference to a public key
/// If the key_str looks like a public key (starts with ssh-, age1, etc.), return it as-is
/// If it looks like a secret name, try to read the corresponding .pub file
pub(crate) fn resolve_public_key(rules_dir: &Path, key_str: &str) -> Result<String> {
    // Check if this looks like an actual public key
    if is_actual_public_key(key_str) {
        return Ok(key_str.to_string());
    }

    // Try to resolve as a secret reference
    // Strip .age suffix for backwards compatibility
    let secret_name = key_str.strip_suffix(".age").unwrap_or(key_str);

    // Public file is now <secret_name>.pub in the same directory
    let pub_file_path = rules_dir.join(format!("{}.pub", secret_name));

    if pub_file_path.exists() {
        let public_key = std::fs::read_to_string(&pub_file_path)
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

    // If no .pub file found, return the original string (might be a public key we don't recognize)
    Ok(key_str.to_string())
}

/// Get public keys for a file from the rules
pub fn get_public_keys(rules_path: &str, file: &str) -> Result<Vec<String>> {
    let nix_expr = format!(
        r#"let
          rules = import {rules_path};
          secretExists = builtins.hasAttr "{file}" rules;
          hasKeys = secretExists && builtins.hasAttr "publicKeys" rules."{file}";
          keys = if !secretExists then throw "Secret '{file}' is not defined in {rules_path}. Please add it to the secrets configuration."
                 else if hasKeys then rules."{file}".publicKeys 
                 else [];
        in
          builtins.deepSeq keys keys"#
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

/// Get the raw public keys for a file from the rules (without resolving secret references)
/// This returns the strings as they appear in the rules file.
fn get_raw_public_keys(rules_path: &str, file: &str) -> Result<Vec<String>> {
    let nix_expr = format!(
        r#"let
          rules = import {rules_path};
          secretExists = builtins.hasAttr "{file}" rules;
          keys = if secretExists then rules."{file}".publicKeys else throw "Secret '{file}' is not defined in {rules_path}. Please add it to the secrets configuration.";
        in
          builtins.deepSeq keys keys"#
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    value_to_string_array(output)
}

/// Get the secret references from a secret's publicKeys array.
/// Returns a list of secret names that are referenced as recipients.
/// Only returns references that look like secret names (not actual public keys).
pub fn get_public_key_references(
    rules_path: &str,
    file: &str,
    all_files: &[String],
) -> Vec<String> {
    let raw_keys = match get_raw_public_keys(rules_path, file) {
        Ok(keys) => keys,
        Err(_) => return vec![],
    };

    let mut refs = Vec::new();
    for key in raw_keys {
        // Skip actual public keys
        if is_actual_public_key(&key) {
            continue;
        }

        // This looks like a secret reference (a secret name)
        // Secret names are used directly in secrets.nix (no .age suffix)
        let secret_ref = &key;

        // Check if this matches any secret in all_files
        if all_files.contains(secret_ref) && !refs.contains(secret_ref) {
            refs.push(secret_ref.to_string());
        }
    }

    refs
}

/// Check if a file should be armored (ASCII-armored output)
pub fn should_armor(rules_path: &str, file: &str) -> Result<bool> {
    let nix_expr = format!(
        r#"let
          rules = import {rules_path};
          secretExists = builtins.hasAttr "{file}" rules;
          result = if !secretExists then throw "Secret '{file}' is not defined in {rules_path}. Please add it to the secrets configuration."
                   else
                     let
                       secret = rules."{file}";
                       hasArmor = builtins.hasAttr "armor" secret;
                     in hasArmor && secret.armor;
        in
          builtins.deepSeq result result"#
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    value_to_bool(&output)
}

/// Metadata about what outputs a secret has (or will have when generated).
#[derive(Debug, Clone, PartialEq)]
pub struct SecretOutputInfo {
    /// Whether the secret has (or will produce) a secret/encrypted file
    pub has_secret: bool,
    /// Whether the secret has (or will produce) a public file
    pub has_public: bool,
}

/// Validate that the output info is valid (at least one of hasSecret or hasPublic must be true)
fn validate_output_info(info: &SecretOutputInfo, file: &str) -> Result<()> {
    if !info.has_secret && !info.has_public {
        return Err(anyhow::anyhow!(
            "Secret '{}' has both hasSecret=false and hasPublic=false. \
             A secret must produce at least one output (either an encrypted .age file or a .pub file). \
             Set hasSecret=true to create an encrypted secret, or hasPublic=true to create a public-only entry.",
            file
        ));
    }
    Ok(())
}

/// Get information about what outputs a secret has or will produce.
///
/// This checks in priority order:
/// 1. Explicit `hasSecret` / `hasPublic` attributes in secrets.nix
/// 2. If a generator exists (explicit or implicit), attempt to deduce from generator output type
/// 3. Fall back to checking file existence (.age and .pub files)
///
/// # Errors
/// Returns an error if both `hasSecret` and `hasPublic` are false, as a secret
/// must produce at least one output.
pub fn get_secret_output_info(rules_path: &str, file: &str) -> Result<SecretOutputInfo> {
    // First check for explicit attributes in secrets.nix
    let explicit_info = get_explicit_output_info(rules_path, file)?;
    if let Some(info) = explicit_info {
        validate_output_info(&info, file)?;
        return Ok(info);
    }

    // Try to infer from generator if present
    if let Some(info) = infer_output_info_from_generator(rules_path, file)? {
        validate_output_info(&info, file)?;
        return Ok(info);
    }

    // Fall back to checking file existence
    let rules_path_obj = std::path::Path::new(rules_path);
    let rules_dir = rules_path_obj
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    // Public file is now <secret_name>.pub in the same directory as secrets.nix
    let pub_path = rules_dir.join(format!("{}.pub", file));
    let has_public = pub_path.exists();

    // For files without explicit config, assume hasSecret = true (default behavior)
    // This is always valid since has_secret=true
    Ok(SecretOutputInfo {
        has_secret: true,
        has_public,
    })
}

/// Check for explicitly set hasSecret/hasPublic attributes in secrets.nix
fn get_explicit_output_info(rules_path: &str, file: &str) -> Result<Option<SecretOutputInfo>> {
    let nix_expr = format!(
        r#"let
          rules = import {rules_path};
          secretExists = builtins.hasAttr "{file}" rules;
          
          result = if !secretExists then throw "Secret '{file}' is not defined in {rules_path}. Please add it to the secrets configuration."
          else
            let
              secret = rules."{file}";
              hasSecretAttr = builtins.hasAttr "hasSecret" secret;
              hasPublicAttr = builtins.hasAttr "hasPublic" secret;
            in {{
              hasSecretAttr = hasSecretAttr;
              hasPublicAttr = hasPublicAttr;
              hasSecret = if hasSecretAttr then secret.hasSecret else null;
              hasPublic = if hasPublicAttr then secret.hasPublic else null;
            }};
        in
          builtins.deepSeq result result"#
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    let Value::Attrs(attrs) = output else {
        return Ok(None);
    };

    let has_secret_attr = attrs
        .select(NixString::from(b"hasSecretAttr" as &[u8]).as_ref())
        .map(|v| value_to_bool(&v.clone()))
        .transpose()?
        .unwrap_or(false);

    let has_public_attr = attrs
        .select(NixString::from(b"hasPublicAttr" as &[u8]).as_ref())
        .map(|v| value_to_bool(&v.clone()))
        .transpose()?
        .unwrap_or(false);

    // If neither attribute is explicitly set, return None to try other methods
    if !has_secret_attr && !has_public_attr {
        return Ok(None);
    }

    // Get the actual values, defaulting unset attrs to reasonable defaults
    let has_secret = if has_secret_attr {
        attrs
            .select(NixString::from(b"hasSecret" as &[u8]).as_ref())
            .map(|v| value_to_bool(&v.clone()))
            .transpose()?
            .unwrap_or(true)
    } else {
        true // Default: secrets have encrypted content
    };

    let has_public = if has_public_attr {
        attrs
            .select(NixString::from(b"hasPublic" as &[u8]).as_ref())
            .map(|v| value_to_bool(&v.clone()))
            .transpose()?
            .unwrap_or(false)
    } else {
        false // Default: no public unless specified
    };

    Ok(Some(SecretOutputInfo {
        has_secret,
        has_public,
    }))
}

/// Try to infer output info by evaluating the generator (if present)
fn infer_output_info_from_generator(
    rules_path: &str,
    file: &str,
) -> Result<Option<SecretOutputInfo>> {
    // Try generating with minimal context to see what output type we get
    match generate_secret_with_public(rules_path, file) {
        Ok(Some(output)) => Ok(Some(SecretOutputInfo {
            has_secret: output.secret.is_some(),
            has_public: output.public.is_some(),
        })),
        Ok(None) => Ok(None), // No generator
        Err(_) => Ok(None),   // Generator failed (probably needs dependencies)
    }
}

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

/// Get the generator output for a file, handling both string and attrset outputs
/// If no explicit generator is provided, automatically selects a generator based on the file ending:
/// - Files ending with "ed25519", "ssh", or "ssh_key" use builtins.sshKey (SSH Ed25519 keypair)
/// - Files ending with "x25519" use builtins.ageKey (age x25519 keypair)
/// - Files ending with "_wg" or "_wireguard" use builtins.wireguardKey (WireGuard keypair)
/// - Files ending with "password" or "passphrase" use builtins.randomString 32
///
/// The `secrets_arg` parameter is a Nix expression that will be passed as the argument to the generator.
/// This allows generators to access other secrets' contents.
pub fn generate_secret_with_public(
    rules_path: &str,
    file: &str,
) -> Result<Option<GeneratorOutput>> {
    generate_secret_with_public_and_context(rules_path, file, "{}")
}

/// Build a Nix expression that evaluates a generator with automatic fallback
fn build_generator_nix_expression(rules_path: &str, file: &str, attempt_arg: &str) -> String {
    format!(
        r#"let
          rules = import {rules_path};
          secretExists = builtins.hasAttr "{file}" rules;
          lowercaseName = builtins.replaceStrings
            ["A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M"
             "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z"]
            ["a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m"
             "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z"]
            "{file}";
          
          hasSuffix = suffix: builtins.match ".*${{suffix}}$" lowercaseName != null;
          
          autoGenerator =
            if hasSuffix "ed25519" || hasSuffix "ssh" || hasSuffix "ssh_key"
            then builtins.sshKey
            else if hasSuffix "x25519"
            then builtins.ageKey
            else if hasSuffix "_wg" || hasSuffix "_wireguard"
            then builtins.wireguardKey
            else if hasSuffix "password" || hasSuffix "passphrase"
            then (_: builtins.randomString 32)
            else null;
          
          secretsContext = {attempt_arg};
          
          callGenerator = gen:
            if builtins.isFunction gen
            then gen secretsContext
            else gen;
          
          hasExplicitGenerator = secretExists && builtins.hasAttr "generator" rules."{file}";
          
          result =
            if !secretExists
            then throw "Secret '{file}' is not defined in {rules_path}. Please add it to the secrets configuration."
            else if hasExplicitGenerator
            then callGenerator rules."{file}".generator
            else if autoGenerator != null
            then autoGenerator secretsContext
            else null;
        in
          builtins.deepSeq result result"#
    )
}

/// Parse generator output from Nix evaluation result
fn parse_generator_output(output: Value) -> Result<Option<GeneratorOutput>> {
    const SECRET_KEY: &[u8] = b"secret";
    const PUBLIC_KEY: &[u8] = b"public";

    match output {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(GeneratorOutput {
            secret: Some(s.as_str()?.to_owned()),
            public: None,
        })),
        Value::Attrs(attrs) => {
            let secret = attrs
                .select(NixString::from(SECRET_KEY).as_ref())
                .map(|v| value_to_string(v.clone()))
                .transpose()?;
            let public = attrs
                .select(NixString::from(PUBLIC_KEY).as_ref())
                .map(|v| value_to_string(v.clone()))
                .transpose()?;

            // At least one of secret or public must be present
            if secret.is_none() && public.is_none() {
                return Err(anyhow::anyhow!(
                    "Generator attrset must have at least 'secret' or 'public' key"
                ));
            }

            Ok(Some(GeneratorOutput { secret, public }))
        }
        _ => Err(anyhow::anyhow!(
            "Generator must return string or attrset with 'secret' and/or 'public' keys, got: {:?}",
            output
        )),
    }
}

/// Check if an error indicates a parameter mismatch (should retry with different params)
fn is_param_mismatch_error(error: &str) -> bool {
    error.contains("Unexpected argument")
        || error.contains("undefined variable")
        || error.contains("attribute")
        || error.contains("E003")
        || error.contains("E005")
        || error.contains("E031")
}

/// Build list of parameter attempts for generator invocation
fn build_param_attempts(secrets_arg: &str) -> Vec<String> {
    let extract_part = |prefix: &str| -> Option<String> {
        secrets_arg
            .find(&format!("{} = {{", prefix))
            .and_then(|start| {
                secrets_arg[start..]
                    .find("};")
                    .map(|end| format!("{{ {} }}", &secrets_arg[start..start + end + 2]))
            })
    };

    let publics = extract_part("publics");
    let secrets = extract_part("secrets");

    let mut attempts = vec!["{}".to_string()];
    if let Some(ref p) = publics {
        attempts.push(p.clone());
    }
    if let Some(ref s) = secrets {
        attempts.push(s.clone());
    }
    if secrets.is_some() && publics.is_some() {
        attempts.push(secrets_arg.to_string());
    }
    attempts
}

/// Internal function that accepts a custom context for the generator
pub(crate) fn generate_secret_with_public_and_context(
    rules_path: &str,
    file: &str,
    secrets_arg: &str,
) -> Result<Option<GeneratorOutput>> {
    let attempts = build_param_attempts(secrets_arg);
    let current_dir = current_dir()?;
    let mut last_error = None;

    for attempt_arg in &attempts {
        let nix_expr = build_generator_nix_expression(rules_path, file, attempt_arg);

        match eval_nix_expression(nix_expr.as_str(), &current_dir) {
            Ok(output) => return parse_generator_output(output),
            Err(e) => {
                if is_param_mismatch_error(&e.to_string()) {
                    last_error = Some(e);
                } else {
                    return Err(e);
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to call generator")))
}

/// Get all file names from the rules
pub fn get_all_files(rules_path: &str) -> Result<Vec<String>> {
    let nix_expr = format!(
        r#"let
          rules = import {rules_path};
          names = builtins.attrNames rules;
        in
          builtins.deepSeq names names"#
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;

    let keys = value_to_string_array(output)?;

    Ok(keys)
}

/// Get the dependencies of a secret (other secrets referenced in its generator or publicKeys)
/// Returns the list of secret names that this secret depends on.
///
/// Dependencies are determined in the following order:
/// 1. If `dependencies` attribute is explicitly specified, use it exclusively
/// 2. Otherwise, automatically detect dependencies from:
///    - Generator function parameters (secrets, publics)
///    - Secret references in publicKeys array (e.g., "deploy-key" instead of actual public key)
pub fn get_secret_dependencies(rules_path: &str, file: &str) -> Result<Vec<String>> {
    // First check if dependencies are explicitly specified
    let nix_expr = format!(
        r#"let
          rules = import {rules_path};
          secretExists = builtins.hasAttr "{file}" rules;
          result = if !secretExists then throw "Secret '{file}' is not defined in {rules_path}. Please add it to the secrets configuration."
                   else
                     let
                       secret = rules."{file}";
                       hasGenerator = builtins.hasAttr "generator" secret;
                       hasDeps = hasGenerator && builtins.hasAttr "dependencies" secret;
                     in if hasDeps then secret.dependencies else [];
        in
          builtins.deepSeq result result"#
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;
    let explicit_deps = value_to_string_array(output)?;

    // If dependencies are explicitly specified, use them
    if !explicit_deps.is_empty() {
        return Ok(explicit_deps);
    }

    // Otherwise, try to auto-detect dependencies from generator and publicKeys
    auto_detect_dependencies(rules_path, file)
}

/// Build Nix expression to test generator with given params
fn build_generator_test_expr(rules_path: &str, file: &str, params: &str) -> String {
    format!(
        r#"let
          rules = import {rules_path};
          secretExists = builtins.hasAttr "{file}" rules;
          
          result =
            if !secretExists
            then throw "Secret '{file}' is not defined in {rules_path}. Please add it to the secrets configuration."
            else
              let
                secret = rules."{file}";
                hasGenerator = builtins.hasAttr "generator" secret;
                generator = secret.generator;
              in
                if hasGenerator
                then (if builtins.isFunction generator then generator {params} else generator)
                else null;
        in
          builtins.deepSeq result result"#
    )
}

/// Extract secret basename from file path
fn extract_basename(path: &str) -> &str {
    let name = path.strip_suffix(".age").unwrap_or(path);
    std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name)
}

/// Extract dependencies mentioned in error message from known files
fn extract_deps_from_error(error: &str, all_files: &[String]) -> Vec<String> {
    all_files
        .iter()
        .filter_map(|f| {
            let name = f.strip_suffix(".age").unwrap_or(f);
            let basename = extract_basename(f);
            let patterns = [
                format!("'{}'", name),
                format!("\"{}\"", name),
                format!("'{}'", basename),
                format!("\"{}\"", basename),
            ];
            if patterns.iter().any(|p| error.contains(p)) {
                Some(basename.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Automatically detect dependencies by analyzing:
/// 1. What the generator references (secrets.X, publics.X)
/// 2. Secret references in publicKeys array
fn auto_detect_dependencies(rules_path: &str, file: &str) -> Result<Vec<String>> {
    let all_files = get_all_files(rules_path)?;
    let current_dir = current_dir()?;

    // First, collect dependencies from publicKeys references
    let mut pub_key_refs = get_public_key_references(rules_path, file, &all_files);

    // Remove self-references from publicKeys refs
    let file_basename = extract_basename(file);
    pub_key_refs.retain(|d| d != file_basename);

    // Try calling generator with empty params
    let nix_expr = build_generator_test_expr(rules_path, file, "{ }");
    match eval_nix_expression(&nix_expr, &current_dir) {
        Ok(_) => return Ok(pub_key_refs), // Generator doesn't need deps, return only publicKeys refs
        Err(e) if !e.to_string().contains("'secrets'") && !e.to_string().contains("'publics'") => {
            return Ok(pub_key_refs); // Generator error not about params, return only publicKeys refs
        }
        Err(_) => {} // Generator needs secrets/publics params, continue detection
    }

    // Try with different param combinations to detect specific dependencies
    // Note: We accumulate deps from errors, but if generator succeeds, we discard
    // the error-based deps and return only publicKeys refs (matching original behavior)
    let mut deps = Vec::new();
    for params in [
        "{ secrets = {}; publics = {}; }",
        "{ secrets = {}; }",
        "{ publics = {}; }",
    ] {
        let nix_expr = build_generator_test_expr(rules_path, file, params);
        match eval_nix_expression(&nix_expr, &current_dir) {
            Ok(_) => return Ok(pub_key_refs), // Generator succeeded - return only publicKeys refs
            Err(e) => deps.extend(extract_deps_from_error(&e.to_string(), &all_files)),
        }
    }

    // Generator couldn't succeed with any params - use detected error-based deps + publicKeys refs
    deps.extend(pub_key_refs);

    // Clean up: sort, dedupe, remove self-references
    deps.sort();
    deps.dedup();
    deps.retain(|d| d != file_basename);
    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::env::current_dir;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    /// Helper function to create test Nix files
    fn create_test_rules_file(content: &str) -> Result<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "{}", content)?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    /// Helper function to create a temporary directory with test files
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

        // Verify the error message is user-friendly (not raw Nix evaluation error)
        let error_msg = result.unwrap_err().to_string();
        eprintln!("Error message: {}", error_msg);
        assert!(error_msg.contains("nonexistent.age"));
        assert!(error_msg.contains("not defined") || error_msg.contains("Please add it"));

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

        assert!(result);
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

        assert!(!result);
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
        assert!(!result);
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
        assert!(should_armor(&rules_path, "secret1.age")?);
        assert!(!(should_armor(&rules_path, "secret2.age")?));
        assert!(!(should_armor(&rules_path, "secret3.age")?)); // Default

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

        assert!(should_armor(
            temp_file.path().to_str().unwrap(),
            "database.age"
        )?);
        assert!(!(should_armor(temp_file.path().to_str().unwrap(), "api-key.age")?));

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

        assert!(should_armor(rules_path.to_str().unwrap(), "database.age")?);
        assert!(!(should_armor(rules_path.to_str().unwrap(), "config.age")?));

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
        assert!(should_armor(
            temp_file.path().to_str().unwrap(),
            "team-password.age"
        )?);
        assert!(!(should_armor(temp_file.path().to_str().unwrap(), "alice-private.age")?));
        assert!(should_armor(
            temp_file.path().to_str().unwrap(),
            "shared-config.age"
        )?);

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
        assert!(should_armor(
            temp_file.path().to_str().unwrap(),
            "secret-000.age"
        )?); // 0 % 3 == 0
        assert!(!(should_armor(temp_file.path().to_str().unwrap(), "secret-001.age")?)); // 1 % 3 != 0
        assert!(should_armor(
            temp_file.path().to_str().unwrap(),
            "secret-003.age"
        )?); // 3 % 3 == 0

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
        assert!(should_armor(
            temp_file.path().to_str().unwrap(),
            "dev-secret.age"
        )?);

        // Prod secret should not include admin key (condition is false)
        let prod_keys = get_public_keys(temp_file.path().to_str().unwrap(), "prod-secret.age")?;
        assert_eq!(prod_keys.len(), 2); // Just prodKeys, no admin
        assert!(!(should_armor(temp_file.path().to_str().unwrap(), "prod-secret.age")?));

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
        assert!(!(should_armor(temp_file.path().to_str().unwrap(), "dev-database.age")?));
        assert!(!(should_armor(temp_file.path().to_str().unwrap(), "staging-database.age")?));
        assert!(should_armor(
            temp_file.path().to_str().unwrap(),
            "prod-database.age"
        )?);

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

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert!(result.is_some());
        assert_eq!(result.unwrap().secret, Some("generated-secret".to_string()));
        let result2 =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret2.age")?;
        assert!(result2.is_none());
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

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;
        let result1 = result.unwrap().secret.unwrap();
        assert_eq!(result1.len(), 16);
        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;
        let result2 = result.unwrap().secret.unwrap();
        assert_eq!(result2.len(), 16);
        assert_ne!(result1, result2); // Should be different random strings
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
        assert_eq!(output.secret, Some("just-a-secret".to_string()));
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
        assert_eq!(output.secret, Some("my-secret".to_string()));
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
        assert_eq!(output.secret, Some("only-secret".to_string()));
        assert_eq!(output.public, None);
        Ok(())
    }

    #[test]
    fn test_generate_secret_with_public_attrset_public_only() -> Result<()> {
        // Test that generators can return only public (no secret)
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { public = "only-public"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, None);
        assert_eq!(output.public, Some("only-public".to_string()));
        Ok(())
    }

    #[test]
    fn test_generate_secret_with_public_attrset_empty_fails() -> Result<()> {
        // Test that an empty attrset (no secret, no public) fails
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { };
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
                .contains("at least 'secret' or 'public' key")
        );
        Ok(())
    }

    // Original test renamed for clarity - this tests the old expected error behavior
    // which is now changed since public-only is allowed
    #[test]
    fn test_generate_secret_with_public_attrset_other_key_fails() -> Result<()> {
        // Test that an attrset with only an unknown key fails
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { unknown_key = "value"; };
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
                .contains("at least 'secret' or 'public' key")
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
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(secret.contains("-----END PRIVATE KEY-----"));

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
        let secret = output.secret.as_ref().unwrap();
        assert_eq!(secret.len(), 32);

        // Verify public contains the reference to the secret
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("metadata-for-"));

        Ok(())
    }

    // Tests for age x25519 keypair generation
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
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("AGE-SECRET-KEY-1"));
        assert!(!secret.contains('\n'));

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
          "my-key-ed25519" = {
          publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "my-key-ed25519")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate an SSH keypair automatically
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("-----BEGIN PRIVATE KEY-----"));
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
            std::slice::from_ref(&public_key),
            false,
        )?;

        // Decrypt with the private key
        use crate::crypto::decrypt_to_file;
        let identities = vec![identity_file.path().to_str().unwrap().to_string()];
        decrypt_to_file(
            encrypted_file.path().to_str().unwrap(),
            decrypted_file.path(),
            &identities,
            true, // no_system_identities
        )?;

        // Verify content matches
        let decrypted_content = std::fs::read_to_string(decrypted_file.path())?;
        assert_eq!(test_content, decrypted_content);
        Ok(())
    }

    #[test]
    fn test_auto_generator_ssh_ending() -> Result<()> {
        let rules_content = r#"
        {
          "deployment-ssh" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "deployment-ssh")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate an SSH keypair automatically
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("ssh-ed25519 "));

        Ok(())
    }

    #[test]
    fn test_auto_generator_ssh_key_ending() -> Result<()> {
        let rules_content = r#"
        {
          "server_ssh_key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "server_ssh_key")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate an SSH keypair automatically
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("ssh-ed25519 "));

        Ok(())
    }

    #[test]
    fn test_auto_generator_x25519_ending() -> Result<()> {
        let rules_content = r#"
        {
          "identity-x25519" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "identity-x25519")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate an age x25519 keypair automatically
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("AGE-SECRET-KEY-"));
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("age1"));

        Ok(())
    }

    #[test]
    fn test_auto_generator_wg_ending() -> Result<()> {
        let rules_content = r#"
        {
          "server_wg" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = generate_secret_with_public(temp_file.path().to_str().unwrap(), "server_wg")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate a WireGuard keypair automatically
        let secret = output.secret.as_ref().unwrap();
        assert_eq!(secret.len(), 44); // Base64 encoded 32 bytes
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert_eq!(public.len(), 44);

        Ok(())
    }

    #[test]
    fn test_auto_generator_wireguard_ending() -> Result<()> {
        let rules_content = r#"
        {
          "client_wireguard" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "client_wireguard")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate a WireGuard keypair automatically
        let secret = output.secret.as_ref().unwrap();
        assert_eq!(secret.len(), 44);
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert_eq!(public.len(), 44);

        Ok(())
    }

    #[test]
    fn test_auto_generator_password_ending() -> Result<()> {
        let rules_content = r#"
        {
          "database-password" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "database-password")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate a 32-character random string
        let secret = output.secret.as_ref().unwrap();
        assert_eq!(secret.len(), 32);
        assert!(output.public.is_none()); // Random string doesn't have public output

        Ok(())
    }

    #[test]
    fn test_auto_generator_passphrase_ending() -> Result<()> {
        let rules_content = r#"
        {
          "backup-passphrase" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "backup-passphrase")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should generate a 32-character random string
        let secret = output.secret.as_ref().unwrap();
        assert_eq!(secret.len(), 32);
        assert!(output.public.is_none()); // Random string doesn't have public output

        Ok(())
    }

    #[test]
    fn test_auto_generator_case_insensitive() -> Result<()> {
        let rules_content = r#"
        {
          "MyKey-ED25519" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "Database-PASSWORD" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        // Test uppercase ED25519
        let result1 =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "MyKey-ED25519")?;
        assert!(result1.is_some());
        let output1 = result1.unwrap();
        let secret1 = output1.secret.as_ref().unwrap();
        assert!(secret1.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(output1.public.is_some());

        // Test uppercase PASSWORD
        let result2 =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "Database-PASSWORD")?;
        assert!(result2.is_some());
        let output2 = result2.unwrap();
        let secret2 = output2.secret.as_ref().unwrap();
        assert_eq!(secret2.len(), 32);
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
        assert_eq!(output.secret, Some("custom-fixed-value".to_string()));
        assert!(output.public.is_none());

        Ok(())
    }

    // Tests for direct expression generators (non-function generators)
    // These test that `generator = "value"` works in addition to `generator = {}: "value"`

    #[test]
    fn test_direct_expression_generator_string() -> Result<()> {
        // Test that `generator = "string"` works (direct string expression)
        let rules_content = r#"
        {
          "direct-string.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = "direct-secret-value";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "direct-string.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, Some("direct-secret-value".to_string()));
        assert!(output.public.is_none());
        Ok(())
    }

    #[test]
    fn test_direct_expression_generator_attrset() -> Result<()> {
        // Test that `generator = { secret = ...; public = ...; }` works (direct attrset expression)
        let rules_content = r#"
        {
          "direct-attrset.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { secret = "my-direct-secret"; public = "my-direct-public"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "direct-attrset.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, Some("my-direct-secret".to_string()));
        assert_eq!(output.public, Some("my-direct-public".to_string()));
        Ok(())
    }

    #[test]
    fn test_direct_expression_generator_ssh_key_call() -> Result<()> {
        // Test that `generator = builtins.sshKey {}` works (pre-evaluated builtin call)
        let rules_content = r#"
        {
          "direct-ssh-call.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey {};
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "direct-ssh-call.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should have generated an SSH keypair
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("ssh-ed25519 "));
        Ok(())
    }

    #[test]
    fn test_direct_expression_generator_random_string_call() -> Result<()> {
        // Test that `generator = builtins.randomString 32` works (pre-evaluated builtin call)
        let rules_content = r#"
        {
          "direct-random.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.randomString 32;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "direct-random.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        let secret = output.secret.as_ref().unwrap();
        assert_eq!(secret.len(), 32);
        assert!(output.public.is_none());
        Ok(())
    }

    #[test]
    fn test_direct_expression_generator_age_key_call() -> Result<()> {
        // Test that `generator = builtins.ageKey {}` works (pre-evaluated builtin call)
        let rules_content = r#"
        {
          "direct-age-key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.ageKey {};
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "direct-age-key.age")?;

        assert!(result.is_some());
        let output = result.unwrap();

        // Should have generated an age x25519 keypair
        let secret = output.secret.as_ref().unwrap();
        assert!(secret.starts_with("AGE-SECRET-KEY-"));
        assert!(output.public.is_some());
        let public = output.public.unwrap();
        assert!(public.starts_with("age1"));
        Ok(())
    }

    #[test]
    fn test_function_generator_still_works_with_empty_arg() -> Result<()> {
        // Ensure the existing behavior for function generators still works
        let rules_content = r#"
        {
          "func-empty.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = {}: "from-function";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "func-empty.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, Some("from-function".to_string()));
        Ok(())
    }

    #[test]
    fn test_function_generator_with_secrets_arg() -> Result<()> {
        // Ensure the existing behavior for function generators with two args still works
        // Note: This generator accepts secrets/publics but doesn't actually use them,
        // so it works with empty context
        let rules_content = r#"
        {
          "func-with-arg.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { secrets ? {}, publics ? {} }: "works-with-optional-args";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        // This should work because the function accepts optional parameters
        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "func-with-arg.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.secret, Some("works-with-optional-args".to_string()));
        Ok(())
    }

    #[test]
    fn test_direct_expression_overrides_auto_generator() -> Result<()> {
        // A direct expression should override auto-generation based on file name
        let rules_content = r#"
        {
          "my-password.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = "explicit-password-value";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            generate_secret_with_public(temp_file.path().to_str().unwrap(), "my-password.age")?;

        assert!(result.is_some());
        let output = result.unwrap();
        // Should use direct expression, not auto-generated random string
        assert_eq!(output.secret, Some("explicit-password-value".to_string()));
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
        let pub_file = rules_dir.join("my-ssh-key.pub");
        let public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8";
        std::fs::write(&pub_file, format!("{}\n", public_key))?;

        // Reference with .age suffix (backwards compatibility - should strip it)
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
        let pub_file = rules_dir.join("my-ssh-key.pub");
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
        let pub_file = temp_dir.path().join("deploy-key.pub");
        let deploy_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeployKeyPublicKeyExample";
        std::fs::write(&pub_file, format!("{}\n", deploy_public_key))?;

        // Create a rules file that references the secret
        let rules_path = temp_dir.path().join("secrets.nix");
        let rules_content = r#"
        {
          "deploy-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "secret-using-deploy-key" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              "deploy-key"
            ];
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_public_keys(rules_path.to_str().unwrap(), "secret-using-deploy-key")?;

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
        let ssh_key_pub = temp_dir.path().join("server-ssh.pub");
        let ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIServerSSHKey";
        std::fs::write(&ssh_key_pub, format!("{}\n", ssh_public_key))?;

        let age_key_pub = temp_dir.path().join("backup-key.pub");
        let age_public_key = "age1abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuv";
        std::fs::write(&age_key_pub, format!("{}\n", age_public_key))?;

        // Create a rules file with mixed public keys and references
        let rules_path = temp_dir.path().join("secrets.nix");
        let rules_content = r#"
        {
          "server-ssh" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "backup-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
          "app-secret" = {
            publicKeys = [ 
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDirectPublicKey"
              "server-ssh"
              "age1directagekey1234567890abcdefghijklmnopqrstuvwxyz12345678"
              "backup-key"
            ];
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_public_keys(rules_path.to_str().unwrap(), "app-secret")?;

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
        assert_eq!(result[3], age_public_key); // Resolved from backup-key

        Ok(())
    }

    #[test]
    fn test_get_public_keys_reference_with_generated_ssh_key() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Simulate a generated SSH keypair (only the .pub file would exist)
        let ssh_key_pub = temp_dir.path().join("generated-deploy-key.pub");
        let ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeneratedDeployKey";
        std::fs::write(&ssh_key_pub, format!("{}\n", ssh_public_key))?;

        // Create a rules file where one secret uses another's public key
        let rules_path = temp_dir.path().join("secrets.nix");
        let rules_content = r#"
        {
          "generated-deploy-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: builtins.sshKey {};
          };
          "authorized-keys" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              "generated-deploy-key"
            ];
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_public_keys(rules_path.to_str().unwrap(), "authorized-keys")?;

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        );
        assert_eq!(result[1], ssh_public_key);

        Ok(())
    }

    // Tests for secret dependencies
    #[test]
    fn test_get_secret_dependencies_no_dependencies() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "simple-secret";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert_eq!(result.len(), 0);
        Ok(())
    }

    #[test]
    fn test_get_secret_dependencies_with_dependencies() -> Result<()> {
        let rules_content = r#"
        {
          "base-secret.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "base";
          };
          "derived-secret.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            dependencies = [ "base-secret" ];
            generator = { secrets }: "derived-from-${secrets.base-secret.secret}";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result =
            get_secret_dependencies(temp_file.path().to_str().unwrap(), "derived-secret.age")?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "base-secret");
        Ok(())
    }

    #[test]
    fn test_get_secret_dependencies_no_generator() -> Result<()> {
        let rules_content = r#"
        {
          "secret1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "secret1.age")?;

        assert_eq!(result.len(), 0);
        Ok(())
    }

    // Auto-detection tests
    #[test]
    fn test_auto_detect_dependencies_single_public() -> Result<()> {
        let rules_content = r#"
        {
          "base.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { secret = "base-secret"; public = "base-public"; };
          };
          "derived.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { publics }: publics."base";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "derived.age")?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "base");
        Ok(())
    }

    #[test]
    fn test_auto_detect_dependencies_single_secret() -> Result<()> {
        let rules_content = r#"
        {
          "base.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "base-secret";
          };
          "derived.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { secrets }: "derived-" + secrets."base";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "derived.age")?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "base");
        Ok(())
    }

    #[test]
    fn test_auto_detect_dependencies_multiple() -> Result<()> {
        let rules_content = r#"
        {
          "key1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { secret = "key1"; public = "pub1"; };
          };
          "key2.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { secret = "key2"; public = "pub2"; };
          };
          "derived.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { secrets, publics }: secrets."key1" + publics."key2";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "derived.age")?;

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"key1".to_string()));
        assert!(result.contains(&"key2".to_string()));
        Ok(())
    }

    #[test]
    fn test_auto_detect_no_dependencies() -> Result<()> {
        let rules_content = r#"
        {
          "standalone.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "standalone-secret";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "standalone.age")?;

        assert_eq!(result.len(), 0);
        Ok(())
    }

    #[test]
    fn test_explicit_deps_override_auto_detect() -> Result<()> {
        // Even if generator references key2, explicit dependencies should be used
        let rules_content = r#"
        {
          "key1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "key1";
          };
          "key2.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "key2";
          };
          "derived.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            dependencies = [ "key1" ];
            generator = { publics }: publics."key2";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "derived.age")?;

        // Should return explicit dependencies, not auto-detected ones
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "key1");
        Ok(())
    }

    #[test]
    fn test_auto_detect_with_age_suffix() -> Result<()> {
        let rules_content = r#"
        {
          "deploy-key.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "config.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { publics }: publics."deploy-key";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "config.age")?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "deploy-key");
        Ok(())
    }

    #[test]
    fn test_auto_detect_ignores_self_reference() -> Result<()> {
        // A generator that somehow references its own name shouldn't include itself
        let rules_content = r#"
        {
          "key1.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "key1-secret";
          };
          "self-ref.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { publics }: publics."key1";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "self-ref.age")?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "key1");
        assert!(!result.contains(&"self-ref".to_string()));
        Ok(())
    }

    #[test]
    fn test_auto_detect_complex_expression() -> Result<()> {
        let rules_content = r#"
        {
          "dbpass.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "db-pass";
          };
          "apikey.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "api-key";
          };
          "config.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { secrets }: ''
              DB_PASSWORD=${secrets."dbpass"}
              API_KEY=${secrets."apikey"}
            '';
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "config.age")?;

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"dbpass".to_string()));
        assert!(result.contains(&"apikey".to_string()));
        Ok(())
    }

    #[test]
    fn test_auto_detect_conditional_reference() -> Result<()> {
        // Note: Conditional references like `publics ? "optional"` won't be auto-detected
        // because they don't cause errors when the attribute is missing.
        // Users should explicitly specify dependencies for conditional access.
        let rules_content = r#"
        {
          "optional.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: "optional-secret";
          };
          "derived.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { publics }: if publics ? "optional" then publics."optional" else "default";
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;

        let result = get_secret_dependencies(temp_file.path().to_str().unwrap(), "derived.age")?;

        // Conditional access won't be detected because it doesn't cause an error
        assert_eq!(result.len(), 0);
        Ok(())
    }

    // Tests for publicKey-based implicit dependencies
    #[test]
    fn test_public_key_reference_creates_implicit_dependency() -> Result<()> {
        // When a secret references another secret in publicKeys, it should create an implicit dependency
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "ssh-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "app-secret" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" "ssh-key" ];
            generator = { }: "app-secret-content";
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_secret_dependencies(rules_path.to_str().unwrap(), "app-secret")?;

        // Should detect "ssh-key" as an implicit dependency from publicKeys
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "ssh-key");
        Ok(())
    }

    #[test]
    fn test_multiple_public_key_references_create_multiple_dependencies() -> Result<()> {
        // Multiple secret references in publicKeys should all become dependencies
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "deploy-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "backup-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "server-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "multi-recipient-secret" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" "deploy-key" "backup-key" "server-key" ];
            generator = { }: "secret-content";
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result =
            get_secret_dependencies(rules_path.to_str().unwrap(), "multi-recipient-secret")?;

        // Should detect all three secret references as dependencies
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"deploy-key".to_string()));
        assert!(result.contains(&"backup-key".to_string()));
        assert!(result.contains(&"server-key".to_string()));
        Ok(())
    }

    #[test]
    fn test_public_key_reference_with_age_suffix() -> Result<()> {
        // Test that the new format works correctly (no .age in secrets.nix)
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "base-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "derived" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" "base-key" ];
            generator = { }: "derived-content";
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_secret_dependencies(rules_path.to_str().unwrap(), "derived")?;

        // Should detect "base-key"
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "base-key");
        Ok(())
    }

    #[test]
    fn test_explicit_dependencies_override_public_key_detection() -> Result<()> {
        // When explicit dependencies are specified, publicKey-based detection is not used
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "key-a.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "key-b.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "explicit-deps.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" "key-a" ];
            dependencies = [ "key-b" ];
            generator = { publics }: publics."key-b";
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_secret_dependencies(rules_path.to_str().unwrap(), "explicit-deps.age")?;

        // Should only have the explicit dependency "key-b", not "key-a" from publicKeys
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "key-b");
        Ok(())
    }

    #[test]
    fn test_mixed_public_keys_and_references() -> Result<()> {
        // Mix of actual public keys and secret references should correctly identify only the references
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "ssh-host-key" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = builtins.sshKey;
          };
          "app-config" = {
            publicKeys = [ 
              "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8"
              "ssh-host-key"
              "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIExample"
            ];
            generator = { }: "config-content";
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_secret_dependencies(rules_path.to_str().unwrap(), "app-config")?;

        // Should only detect "ssh-host-key" as dependency, not the actual public keys
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "ssh-host-key");
        Ok(())
    }

    #[test]
    fn test_public_key_reference_to_nonexistent_secret_ignored() -> Result<()> {
        // References to secrets that don't exist in rules should be ignored
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "secret" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" "nonexistent-key" ];
            generator = { }: "content";
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_secret_dependencies(rules_path.to_str().unwrap(), "secret")?;

        // "nonexistent-key" should not be detected because it's not a valid secret in rules
        assert_eq!(result.len(), 0);
        Ok(())
    }

    #[test]
    fn test_public_key_reference_no_self_dependency() -> Result<()> {
        // A secret should not be detected as its own dependency
        let temp_dir = TempDir::new()?;
        let rules_path = temp_dir.path().join("secrets.nix");

        let rules_content = r#"
        {
          "self-ref" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" "self-ref" ];
            generator = { }: "content";
          };
        }
        "#;
        std::fs::write(&rules_path, rules_content)?;

        let result = get_secret_dependencies(rules_path.to_str().unwrap(), "self-ref")?;

        // Should not include self as dependency
        assert_eq!(result.len(), 0);
        Ok(())
    }

    // ===========================================
    // SECRET OUTPUT INFO TESTS
    // ===========================================

    #[test]
    fn test_get_secret_output_info_explicit_has_secret_false() -> Result<()> {
        let rules_content = r#"
        {
          "public-only.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            hasSecret = false;
            hasPublic = true;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let info = get_secret_output_info(temp_file.path().to_str().unwrap(), "public-only.age")?;

        assert!(!info.has_secret);
        assert!(info.has_public);
        Ok(())
    }

    #[test]
    fn test_get_secret_output_info_explicit_has_public_false() -> Result<()> {
        let rules_content = r#"
        {
          "secret-only.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            hasSecret = true;
            hasPublic = false;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let info = get_secret_output_info(temp_file.path().to_str().unwrap(), "secret-only.age")?;

        assert!(info.has_secret);
        assert!(!info.has_public);
        Ok(())
    }

    #[test]
    fn test_get_secret_output_info_inferred_from_generator_public_only() -> Result<()> {
        let rules_content = r#"
        {
          "metadata.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { public = "metadata-value"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let info = get_secret_output_info(temp_file.path().to_str().unwrap(), "metadata.age")?;

        assert!(!info.has_secret);
        assert!(info.has_public);
        Ok(())
    }

    #[test]
    fn test_get_secret_output_info_inferred_from_generator_both() -> Result<()> {
        let rules_content = r#"
        {
          "keypair.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            generator = { }: { secret = "private-key"; public = "public-key"; };
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let info = get_secret_output_info(temp_file.path().to_str().unwrap(), "keypair.age")?;

        assert!(info.has_secret);
        assert!(info.has_public);
        Ok(())
    }

    #[test]
    fn test_get_secret_output_info_default_secret_only() -> Result<()> {
        // Without explicit attrs or generator, should default to has_secret=true, has_public=false
        let rules_content = r#"
        {
          "plain.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let info = get_secret_output_info(temp_file.path().to_str().unwrap(), "plain.age")?;

        assert!(info.has_secret);
        assert!(!info.has_public);
        Ok(())
    }

    #[test]
    fn test_get_secret_output_info_partial_explicit() -> Result<()> {
        // Only hasPublic is set explicitly, hasSecret should default to true
        let rules_content = r#"
        {
          "partial.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            hasPublic = true;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let info = get_secret_output_info(temp_file.path().to_str().unwrap(), "partial.age")?;

        assert!(info.has_secret); // Default
        assert!(info.has_public); // Explicit
        Ok(())
    }

    #[test]
    fn test_get_secret_output_info_both_false_error() -> Result<()> {
        // Setting both hasSecret=false and hasPublic=false should error
        let rules_content = r#"
        {
          "invalid.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            hasSecret = false;
            hasPublic = false;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let result = get_secret_output_info(temp_file.path().to_str().unwrap(), "invalid.age");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hasSecret=false"));
        assert!(err.to_string().contains("hasPublic=false"));
        Ok(())
    }

    #[test]
    fn test_get_secret_output_info_secret_only_default_works() -> Result<()> {
        // hasSecret=true, hasPublic=false is the default and should work fine
        let rules_content = r#"
        {
          "secret-only.age" = {
            publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
            hasSecret = true;
            hasPublic = false;
          };
        }
        "#;
        let temp_file = create_test_rules_file(rules_content)?;
        let info = get_secret_output_info(temp_file.path().to_str().unwrap(), "secret-only.age")?;

        assert!(info.has_secret);
        assert!(!info.has_public);
        Ok(())
    }
}
