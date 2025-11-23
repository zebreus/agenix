pub mod builtins;
pub mod eval;
pub mod keypair;

#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use eval::{
    eval_nix_expression, value_to_bool, value_to_optional_string, value_to_string,
    value_to_string_array,
};
use snix_eval::NixString;
use snix_eval::Value;
use std::env::current_dir;
use std::path::Path;

/// Resolve a potential secret reference to a public key
/// If the key_str looks like a public key (starts with ssh-, age1, etc.), return it as-is
/// If it looks like a secret name, try to read the corresponding .pub file
#[cfg_attr(test, allow(dead_code))]
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
                .ok_or_else(|| anyhow::anyhow!("Generator attrset must have 'secret' key"))?;
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
        _ => Err(anyhow::anyhow!(
            "Generator must return either a string or an attrset with 'secret' and optional 'public' keys, got: {:?}",
            output
        )),
    }
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
