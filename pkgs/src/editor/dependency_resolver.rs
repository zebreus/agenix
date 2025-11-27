//! Dependency resolution for secret generation.
//!
//! This module handles the dependency graph for secrets that reference
//! other secrets' public keys in their generators.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use crate::nix::{GeneratorOutput, get_secret_dependencies};

use super::context::SecretContext;
use super::secret_name::SecretName;

/// Resolves dependencies between secrets during generation.
pub struct DependencyResolver<'a> {
    /// The secret context
    ctx: &'a SecretContext,
    /// Generated secrets and their outputs
    generated_secrets: HashMap<String, GeneratorOutput>,
    /// Set of processed secret files
    processed: HashSet<String>,
}

impl<'a> DependencyResolver<'a> {
    /// Create a new dependency resolver.
    pub fn new(ctx: &'a SecretContext) -> Self {
        Self {
            ctx,
            generated_secrets: HashMap::new(),
            processed: HashSet::new(),
        }
    }

    /// Check if a file has been processed.
    pub fn is_processed(&self, file: &str) -> bool {
        self.processed.contains(file)
    }

    /// Mark a file as processed.
    pub fn mark_processed(&mut self, file: &str) {
        self.processed.insert(file.to_string());
    }

    /// Store a generated secret.
    pub fn store_generated(&mut self, file: &str, output: GeneratorOutput) {
        self.generated_secrets.insert(file.to_string(), output);
    }

    /// Resolve a dependency name to its full file path from the files list.
    pub fn resolve_dependency_path(&self, dep: &str) -> String {
        let dep_name = SecretName::new(dep);
        self.ctx
            .all_files()
            .iter()
            .find(|f| SecretName::new(f).matches(&dep_name))
            .cloned()
            .unwrap_or_else(|| dep.to_string())
    }

    /// Get public content for a secret from either generated secrets or .pub files.
    pub fn get_public_content(&self, file: &str) -> Result<Option<String>> {
        let secret_name = SecretName::new(file);
        let basename = secret_name.basename();

        // Check if we just generated it - search by basename
        for (key, output) in self.generated_secrets.iter() {
            if SecretName::new(key).basename() == basename
                && let Some(ref public) = output.public
            {
                return Ok(Some(public.clone()));
            }
        }

        // Check for .pub file
        let secret_base = SecretName::strip_age_suffix(file);
        let pub_file_paths = if secret_base.starts_with('/') || secret_base.starts_with('\\') {
            vec![
                PathBuf::from(format!("{}.age.pub", secret_base)),
                PathBuf::from(format!("{}.pub", secret_base)),
            ]
        } else {
            vec![
                self.ctx
                    .rules_dir()
                    .join(format!("{}.age.pub", secret_base)),
                self.ctx.rules_dir().join(format!("{}.pub", secret_base)),
            ]
        };

        for pub_file_path in &pub_file_paths {
            if pub_file_path.exists() {
                let content = fs::read_to_string(pub_file_path)?;
                return Ok(Some(content.trim().to_string()));
            }
        }

        Ok(None)
    }

    /// Check if a single dependency is satisfied (has public content available).
    ///
    /// Returns `(satisfied, is_missing)`:
    /// - `satisfied`: true if the dependency can be resolved
    /// - `is_missing`: true if the dependency cannot be found at all
    pub fn check_dependency_satisfied(&self, dep: &str) -> Result<(bool, bool)> {
        let dep_file = self.resolve_dependency_path(dep);
        let dep_name = SecretName::new(&dep_file);
        let dep_basename = dep_name.basename();

        let will_be_generated = self
            .ctx
            .all_files()
            .iter()
            .any(|f| SecretName::new(f).basename() == dep_basename);
        let exists = self
            .ctx
            .rules_dir()
            .join(dep_name.with_age_suffix())
            .exists();
        let has_public = self.get_public_content(&dep_file)?.is_some();

        // Missing: cannot be satisfied at all
        if !will_be_generated && !exists && !has_public {
            return Ok((false, true));
        }

        // Pending: will be generated but hasn't been processed yet
        if will_be_generated && !has_public {
            let is_processed = self
                .processed
                .iter()
                .any(|p| SecretName::new(p).basename() == dep_basename);
            if !is_processed {
                return Ok((false, false));
            }
        }

        // Exists but no public content
        if exists && !has_public {
            return Ok((false, false));
        }

        Ok((true, false))
    }

    /// Check if all dependencies for a secret are satisfied.
    ///
    /// Returns `(all_satisfied, missing_deps)`:
    /// - `all_satisfied`: true if all dependencies can be resolved
    /// - `missing_deps`: list of dependencies that cannot be found at all
    pub fn are_all_dependencies_satisfied(&self, deps: &[String]) -> Result<(bool, Vec<String>)> {
        let mut all_satisfied = true;
        let mut missing = Vec::new();

        for dep in deps {
            let (satisfied, is_missing) = self.check_dependency_satisfied(dep)?;
            if is_missing {
                missing.push(dep.clone());
            }
            if !satisfied {
                all_satisfied = false;
            }
        }

        Ok((all_satisfied, missing))
    }

    /// Find generated secret content by basename matching.
    pub fn find_generated_secret(&self, basename: &str) -> Option<&str> {
        self.generated_secrets
            .iter()
            .find(|(key, _)| SecretName::new(key).basename() == basename)
            .map(|(_, output)| output.secret.as_str())
    }

    /// Build the Nix context (secrets and publics attrsets) for dependencies.
    pub fn build_dependency_context(&self, deps: &[String]) -> Result<String> {
        if deps.is_empty() {
            return Ok("{}".to_string());
        }

        let mut secrets_parts = Vec::new();
        let mut publics_parts = Vec::new();

        for dep in deps {
            let dep_file = self.resolve_dependency_path(dep);
            let dep_name = SecretName::new(&dep_file);
            let dep_key = dep_name.normalized();
            let dep_basename = dep_name.basename();

            // Add public content if available
            if let Some(public) = self.get_public_content(&dep_file)? {
                publics_parts.push(format!(
                    r#""{}" = "{}";"#,
                    dep_key,
                    escape_nix_string(&public)
                ));
            }

            // Add secret content if available (from generated_secrets)
            if let Some(secret) = self.find_generated_secret(dep_basename) {
                secrets_parts.push(format!(
                    r#""{}" = "{}";"#,
                    dep_key,
                    escape_nix_string(secret)
                ));
            }
        }

        let secrets_str = format_nix_attrset("secrets", &secrets_parts);
        let publics_str = format_nix_attrset("publics", &publics_parts);

        Ok(format!("{{ {} {} }}", secrets_str, publics_str))
    }

    /// Collect all dependencies of a secret recursively.
    ///
    /// Silently ignores errors when getting dependencies (treats as having no dependencies).
    pub fn collect_dependencies(&self, file: &str, collected: &mut HashSet<String>) {
        let deps = get_secret_dependencies(self.ctx.rules_path(), file).unwrap_or_default();
        for dep in deps {
            let dep_file = self.resolve_dependency_path(&dep);
            let dep_name = SecretName::new(&dep_file);

            // Find the actual file in all_files that matches this dependency
            for f in self.ctx.all_files() {
                if SecretName::new(f).matches(&dep_name) && !collected.contains(f) {
                    collected.insert(f.clone());
                    // Recursively collect dependencies of this dependency
                    self.collect_dependencies(f, collected);
                }
            }
        }
    }
}

/// Escape a string for safe inclusion in a Nix string literal.
pub fn escape_nix_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\0' => result.push_str("\\0"),
            '$' => result.push_str("\\$"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Build Nix attrset string from key-value pairs.
fn format_nix_attrset(name: &str, parts: &[String]) -> String {
    if parts.is_empty() {
        format!("{} = {{}};", name)
    } else {
        format!("{} = {{ {} }};", name, parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_nix_string() {
        assert_eq!(escape_nix_string("hello"), "hello");
        assert_eq!(escape_nix_string("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_nix_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_nix_string("hello\\world"), "hello\\\\world");
        assert_eq!(escape_nix_string("$HOME"), "\\$HOME");
    }

    #[test]
    fn test_format_nix_attrset_empty() {
        assert_eq!(format_nix_attrset("test", &[]), "test = {};");
    }

    #[test]
    fn test_format_nix_attrset_with_parts() {
        let parts = vec![r#""key1" = "val1";"#.to_string()];
        assert_eq!(
            format_nix_attrset("test", &parts),
            r#"test = { "key1" = "val1"; };"#
        );
    }
}
