//! Loading and interpreting entries from secrets.nix.
//!
//! The single source of truth for entry semantics is [`effective_entry_nix`]:
//! it merges the raw secrets.nix attrset with name-based implicit generators
//! and resolves the `hasSecret`/`hasPublic` defaulting rules. Both the
//! metadata load here and the generator call in [`super::generator`] go
//! through it, so they can never disagree.

use super::eval::{eval_nix_expression, value_to_bool, value_to_string_array};
use super::public_key::PublicKeyString;
use rootcause::{Report, prelude::*, report};
use snix_eval::Value;
use std::path::Path;

/// The two parts an entry can have on disk: `<name>.age` and `<name>.pub`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Part {
    Secret,
    Public,
}

impl Part {
    pub fn file_name(self, name: &str) -> String {
        match self {
            Part::Secret => format!("{name}.age"),
            Part::Public => format!("{name}.pub"),
        }
    }
}

/// An entry from secrets.nix with all defaulting rules applied.
#[derive(Debug, Clone, PartialEq)]
pub struct RawSecretEntry {
    pub public_keys: Vec<PublicKeyString>,
    /// Whether the secret file is ASCII-armored.
    pub armored: bool,
    pub has_secret: bool,
    pub has_public: bool,
    /// Declared dependencies. Only used for regeneration cascades, never for
    /// resolution order (Nix laziness handles that).
    pub dependencies: Vec<String>,
    pub has_generator: bool,
}

impl RawSecretEntry {
    pub fn has(&self, part: Part) -> bool {
        match part {
            Part::Secret => self.has_secret,
            Part::Public => self.has_public,
        }
    }
}

/// Validate a secret name. Names are strict: no paths, no leading dot, and
/// no `.age` suffix (the suffix belongs to the file, not the name).
pub fn validate_name(name: &str) -> Result<(), Report> {
    if name.is_empty() {
        return Err(report!("Secret name cannot be empty"));
    }
    if let Some(stripped) = name.strip_suffix(".age") {
        return Err(report!(
            "Secret name '{name}' ends with '.age'. \
             Secret names in secrets.nix do not include the .age suffix. \
             Use '{stripped}' instead."
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(report!(
            "Secret name '{name}' contains path separators. \
             Secret names must be simple names; all secret files live in the \
             same directory as secrets.nix."
        ));
    }
    if name.starts_with('.') {
        return Err(report!("Secret name '{name}' must not start with a dot."));
    }
    Ok(())
}

/// Escape a string as a Nix string literal.
pub(super) fn nix_string_literal(s: &str) -> String {
    let escaped = s
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace("${", r"\${");
    format!("\"{escaped}\"")
}

/// A Nix function `rules: name: entry` producing the effective entry:
/// implicit generators applied, `hasSecret`/`hasPublic` defaulting resolved.
///
/// The defaulting rules (see docs/core-design.md):
/// - A name-implied implicit generator carries its known shape.
/// - Otherwise the default is `hasSecret = true, hasPublic = false`.
/// - Explicit declarations always win.
/// - Declaring `hasSecret = false` without declaring `hasPublic` implies the
///   entry is public-only.
///
/// `generator` is null when the entry has none (or explicitly disabled it
/// with `generator = null`).
pub(super) fn effective_entry_nix() -> &'static str {
    r#"(rules: name:
      let
        raw =
          if builtins.isAttrs rules.${name}
          then rules.${name}
          else throw "Entry '${name}' in secrets.nix must be an attribute set";

        lower = builtins.replaceStrings
          ["A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M"
           "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z"]
          ["a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m"
           "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z"]
          name;
        hasSuffix = suffix: builtins.match ".*${suffix}$" lower != null;
        # Always lambdas, never bare builtins: generators are called with
        # the arguments their pattern names (builtins.functionArgs), which
        # is only well-defined for lambdas.
        implicit =
          if hasSuffix "ed25519" || hasSuffix "ssh" || hasSuffix "ssh_key"
          then { generator = { }: builtins.sshKey { }; hasSecret = true; hasPublic = true; }
          else if hasSuffix "x25519"
          then { generator = { }: builtins.ageKey { }; hasSecret = true; hasPublic = true; }
          else if hasSuffix "_wg" || hasSuffix "_wireguard"
          then { generator = { }: builtins.wireguardKey { }; hasSecret = true; hasPublic = true; }
          else if hasSuffix "password" || hasSuffix "passphrase"
          then { generator = { }: builtins.randomString 32; hasSecret = true; hasPublic = false; }
          else { };

        hasSecret = raw.hasSecret or (implicit.hasSecret or true);
        hasPublic =
          if raw ? hasPublic
          then raw.hasPublic
          else (implicit.hasPublic or false) || !hasSecret;
      in {
        inherit hasSecret hasPublic;
        generator = if raw ? generator then raw.generator else implicit.generator or null;
        publicKeys = raw.publicKeys or [ ];
        armor = raw.armor or false;
        dependencies = raw.dependencies or [ ];
      })"#
}

/// Load the effective entry metadata for `name` from the rules file.
/// The generator itself is not evaluated, only whether one exists.
pub fn get_raw_secret_entry(rules_path: &Path, name: &str) -> Result<RawSecretEntry, Report> {
    let rules_path_str = rules_path
        .to_str()
        .ok_or_else(|| report!("Path to secrets.nix is not valid UTF-8"))?;

    let nix_expr = format!(
        r#"let
          rules = import {rules_path_str};
          entry = {effective_entry} rules {name_literal};
          result = {{
            publicKeys = entry.publicKeys;
            armor = entry.armor;
            hasSecret = entry.hasSecret;
            hasPublic = entry.hasPublic;
            dependencies = entry.dependencies;
            hasGenerator = entry.generator != null;
          }};
        in builtins.deepSeq result result"#,
        effective_entry = effective_entry_nix(),
        name_literal = nix_string_literal(name),
    );

    let dir = rules_path.parent().unwrap_or_else(|| Path::new("."));
    let output = eval_nix_expression(&nix_expr, dir)
        .context(format!("Failed to load entry '{name}' from secrets.nix"))?;

    let Value::Attrs(attrs) = output else {
        return Err(report!("Entry metadata is not an attrset: {output:?}"));
    };
    let field = |key: &str| {
        attrs
            .select(key)
            .unwrap_or_else(|| panic!("metadata expression always produces '{key}'"))
    };

    Ok(RawSecretEntry {
        public_keys: value_to_string_array(&field("publicKeys"))
            .context(format!("Invalid publicKeys for '{name}'"))?
            .into_iter()
            .map(PublicKeyString::from)
            .collect(),
        armored: value_to_bool(&field("armor")).context(format!("Invalid armor for '{name}'"))?,
        has_secret: value_to_bool(&field("hasSecret"))
            .context(format!("Invalid hasSecret for '{name}'"))?,
        has_public: value_to_bool(&field("hasPublic"))
            .context(format!("Invalid hasPublic for '{name}'"))?,
        dependencies: value_to_string_array(&field("dependencies"))
            .context(format!("Invalid dependencies for '{name}'"))?,
        has_generator: value_to_bool(&field("hasGenerator"))
            .context(format!("Invalid generator for '{name}'"))?,
    })
}
