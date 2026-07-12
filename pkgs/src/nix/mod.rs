//! Nix expression evaluation and secret management integration.
//!
//! This module provides functionality for evaluating Nix expressions to extract
//! public keys, file lists, and generator configurations from rules files.

mod builtins;
mod eval;
mod generator;
mod global_state;
mod keypair;
mod public_key;
mod raw_secret_entry;

use anyhow::Result;
use eval::{eval_nix_expression, value_to_string_array};
use rootcause::Report;
use std::env::current_dir;
use std::path::Path;

// pub use global_state::*;

/// Get file names from the rules. Optionally validate and return a filtered subset.
pub fn get_all_files(rules_path: &Path) -> Result<Vec<String>, Report> {
    let rules_path_str = rules_path.to_str().expect("Invalid path encoding");

    let nix_expr = format!(
        r#"let
              rules = import {rules_path};
              names = builtins.attrNames rules;
            in
              builtins.deepSeq names names"#,
        rules_path = rules_path_str
    );

    let current_dir = current_dir()?;
    let output = eval_nix_expression(nix_expr.as_str(), &current_dir)?;
    let names = value_to_string_array(&output)?;
    Ok(names)
}
