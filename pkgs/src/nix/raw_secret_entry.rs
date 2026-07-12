//! Nix expression evaluation and secret management integration.
//!
//! This module provides functionality for evaluating Nix expressions to extract
//! public keys, file lists, and generator configurations from rules files.

use super::eval::{eval_nix_expression, value_to_bool, value_to_string_array};
use super::public_key::PublicKeyString;
use anyhow::Result;
use rootcause::Report;
use rootcause::report;
use rootcause::report_collection::ReportCollection;
use snix_eval::NixString;
use snix_eval::Value;
use std::env::current_dir;

use crate::nix::eval::value_to_optional_bool;
use crate::nix::eval::value_to_optional_string_array;
use crate::nix::generator::get_entry_with_implicit_generator;

fn validate_name(name: &str) -> Result<(), Report> {
    if name.is_empty() {
        return Err(report!("Secret name cannot be empty"));
    }

    if name.ends_with(".age") {
        return Err(report!(
            "Secret name '{}' ends with '.age'. \
                Secret names in secrets.nix do not include the .age suffix. \
                Please use '{}' instead.",
            name,
            name.strip_suffix(".age").unwrap()
        ));
    }

    if name.contains('/') || name.contains('\\') {
        return Err(report!(
            "Secret name '{}' contains path separators. \
                Secret names must be simple names, not paths. \
                All secret files are located in the same directory as secrets.nix.",
            name
        ));
    }

    if name.starts_with('.') {
        return Err(report!(
            "Secret name '{}' starts with '.'. \
                Secret names must not start with a dot. \
                All secret files are located in the same directory as secrets.nix.",
            name
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawSecretEntry {
    pub public_keys: Vec<PublicKeyString>,
    /// Whether the secret is armored (ASCII encoded)
    pub armored: bool,
    // TODO: document behavior after implementation
    /// Whether the secret is expected to have a secret file
    /// If hasSecret or hasPublic is set explicitly in the rules, those values are used.
    ///
    /// If a implicit generator is used has_secret and has_public are set to true if the implicit generator produces secret and/or public output.
    ///
    /// If no explicit generator is used, defaults to
    /// {} => {hasSecret = true, hasPublic = false}
    /// {hasSecret = false} => {hasSecret = false, hasPublic = true}
    /// {hasSecret = true} => {hasSecret = true, hasPublic = false}
    /// {hasPublic = false} => {hasSecret = true, hasPublic = false}
    /// {hasPublic = true} => {hasSecret = true, hasPublic = true}
    ///
    /// If a explicit generator is used then ???
    pub has_secret: Option<bool>,
    /// See `has_secret` for documentation
    pub has_public: Option<bool>,
    /// Explicit dependencies listed in the secret entry
    pub explicit_dependencies: Option<Vec<String>>,
    // Whether a generator exists for this secret
    pub has_generator: bool,
    // // Whether the generator is implicitly set
    // pub implicit_generator: bool,
}

fn get_raw_secret_entry_nix_expr() -> String {
    // A function that takes rules and name and returns the raw secret entry in nix. Use
    let nix_expr = format!(
        r#"(rules: name: (let
      entry = {get_entry_with_implicit_generator} rules name;
      hasArmor = builtins.hasAttr "armor" entry;
      armorVal = if hasArmor then entry.armor else false;
      hasSecretVal = if builtins.hasAttr "hasSecret" entry then entry.hasSecret else null;
      hasPublicVal = if builtins.hasAttr "hasPublic" entry then entry.hasPublic else null;
      rawKeys = if builtins.hasAttr "publicKeys" entry then builtins.deepSeq entry.publicKeys entry.publicKeys else [];
      generator = {get_entry_with_implicit_generator} rules name;
      explicitDeps = if builtins.hasAttr "dependencies" entry then secret.dependencies else null;
      hasGenerator = builtins.hasAttr "generator" generator; # TODO: Add that back after I did some performance testing: && generator.generator != null;
      result = {{
      name = name;
      rawKeys = rawKeys;
      armor = armorVal;
      hasSecret = hasSecretVal;
      hasPublic = hasPublicVal;
      explicitDeps = explicitDeps;
      hasGenerator = hasGenerator;
      }};
    in
      builtins.deepSeq result result))"#,
        get_entry_with_implicit_generator = get_entry_with_implicit_generator()
    );

    nix_expr
}

fn parse_raw_secret_entry(output: Value) -> Result<RawSecretEntry, ReportCollection> {
    let mut errors = ReportCollection::new();

    // Parse bundled metadata
    let attrs = match output {
        Value::Attrs(a) => a,
        output => {
            errors.push(
                report!("secrets.nix entry is not an attrset, but: {output:?}",).into_cloneable(),
            );
            return Err(errors);
        }
    };

    let raw_keys = attrs
        .select(NixString::from(&"rawKeys"[..]).as_ref())
        .unwrap();
    let raw_keys = value_to_string_array(&raw_keys);

    let armored = attrs
        .select(NixString::from(&b"armor"[..]).as_ref())
        .unwrap();
    let armored = value_to_bool(&armored);

    let has_secret = attrs
        .select(NixString::from(&b"hasSecret"[..]).as_ref())
        .unwrap();
    let has_secret = value_to_optional_bool(&has_secret);

    let has_public = attrs
        .select(NixString::from(&b"hasPublic"[..]).as_ref())
        .unwrap();
    let has_public = value_to_optional_bool(&has_public);

    let explicit_dependencies = attrs
        .select(NixString::from(&b"explicitDeps"[..]).as_ref())
        .unwrap();
    let explicit_dependencies = value_to_optional_string_array(&explicit_dependencies);

    let has_generator = attrs
        .select(NixString::from(&b"hasGenerator"[..]).as_ref())
        .unwrap();
    let has_generator = value_to_bool(&has_generator);

    let raw_keys = match raw_keys {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(e.into_cloneable());
            None
        }
    };
    let armored = match armored {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(e.into_cloneable());
            None
        }
    };
    let has_secret = match has_secret {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(e.into_cloneable());
            None
        }
    };
    let has_public = match has_public {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(e.into_cloneable());
            None
        }
    };
    let explicit_dependencies = match explicit_dependencies {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(e.into_cloneable());
            None
        }
    };
    let has_generator = match has_generator {
        Ok(v) => v,
        Err(e) => {
            errors.push(e.into_cloneable());
            false
        }
    };

    if !errors.is_empty() {
        return Err(errors);
    }
    let raw_keys = raw_keys.unwrap();
    let armored = armored.unwrap();
    let has_secret = has_secret.unwrap();
    let has_public = has_public.unwrap();
    let explicit_dependencies = explicit_dependencies.unwrap();

    let raw_keys = raw_keys
        .into_iter()
        .map(|key| key.into())
        .collect::<Vec<_>>();

    return Ok(RawSecretEntry {
        public_keys: raw_keys,
        armored,
        has_secret,
        has_public,
        explicit_dependencies,
        has_generator,
    });
}

pub fn get_raw_secret_entry(
    rules_path: &std::path::Path,
    name: &str,
) -> Result<RawSecretEntry, Report> {
    validate_name(&name)?;
    let rules_path_str = rules_path
        .to_str()
        .expect("Invalid encoding on path to secrets.nix");

    // Bundle existence check, raw publicKeys, explicit armor/hasSecret/hasPublic and explicit dependencies in one eval
    let nix_expr = format!(
        r#"let
      rules = import {rules_path};
      getRawEntry = {get_raw_secret_entry_nix_expr};
      in getRawEntry rules "{name}""#,
        rules_path = rules_path_str,
        get_raw_secret_entry_nix_expr = get_raw_secret_entry_nix_expr()
    );
    let current = current_dir()?;
    let output = eval_nix_expression(&nix_expr, &current)?;

    parse_raw_secret_entry(output).map_err(|e| {
        e.context(format!(
            "Failed to get raw secret entry for secret '{}'",
            name
        ))
        .into_dyn_any()
    })
}
