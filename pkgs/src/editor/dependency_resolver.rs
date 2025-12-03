//! Dependency resolution for secret generation.
//!
//! This module handles the dependency graph for secrets that reference
//! other secrets' public keys in their generators.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;

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
        let name = secret_name.name();

        // Check if we just generated it - search by name
        for (key, output) in self.generated_secrets.iter() {
            if SecretName::new(key).name() == name
                && let Some(ref public) = output.public
            {
                return Ok(Some(public.clone()));
            }
        }

        // Check for .pub file - now it's just <name>.pub
        let pub_file_path = self.ctx.rules_dir().join(secret_name.public_file());

        if pub_file_path.exists() {
            let content = fs::read_to_string(pub_file_path)?;
            return Ok(Some(content.trim().to_string()));
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
        let name = dep_name.name();

        let will_be_generated = self
            .ctx
            .all_files()
            .iter()
            .any(|f| SecretName::new(f).name() == name);
        let exists = self
            .ctx
            .rules_dir()
            .join(dep_name.secret_file())
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
                .any(|p| SecretName::new(p).name() == name);
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

    /// Find generated secret content by name matching.
    /// Returns None if no matching generated secret exists or if the generator
    /// only produced public output (no secret).
    pub fn find_generated_secret(&self, name: &str) -> Option<&str> {
        self.generated_secrets
            .iter()
            .find(|(key, _)| SecretName::new(key).name() == name)
            .and_then(|(_, output)| output.secret.as_deref())
    }

    /// Check if a dependency was generated with a specific output type.
    /// Returns (has_secret, has_public).
    pub fn get_generated_output_info(&self, name: &str) -> Option<(bool, bool)> {
        self.generated_secrets
            .iter()
            .find(|(key, _)| SecretName::new(key).name() == name)
            .map(|(_, output)| (output.secret.is_some(), output.public.is_some()))
    }

    /// Build the Nix context (secrets and publics attrsets) for dependencies.
    /// Returns the context string and warnings about missing dependency outputs.
    pub fn build_dependency_context(&self, deps: &[String]) -> Result<String> {
        if deps.is_empty() {
            return Ok("{}".to_string());
        }

        let mut secrets_parts = Vec::new();
        let mut publics_parts = Vec::new();

        for dep in deps {
            let dep_file = self.resolve_dependency_path(dep);
            let dep_name = SecretName::new(&dep_file);
            let dep_key = dep_name.name();
            let name = dep_name.name();

            // Add public content if available
            if let Some(public) = self.get_public_content(&dep_file)? {
                publics_parts.push(format!(
                    r#""{}" = "{}";"#,
                    dep_key,
                    escape_nix_string(&public)
                ));
            }

            // Add secret content if available (from generated_secrets)
            if let Some(secret) = self.find_generated_secret(name) {
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

    /// Validate dependencies and generate helpful error messages.
    /// This should be called when a generator evaluation fails to provide context.
    ///
    /// Returns a detailed error message explaining what dependency outputs are missing.
    pub fn get_dependency_availability_info(&self, deps: &[String]) -> Vec<String> {
        let mut messages = Vec::new();

        for dep in deps {
            let dep_file = self.resolve_dependency_path(dep);
            let dep_name = SecretName::new(&dep_file);
            let name = dep_name.name();
            let dep_key = dep_name.name();

            let has_secret = self.find_generated_secret(name).is_some();
            let has_public = self.get_public_content(&dep_file).ok().flatten().is_some();

            // Check if dependency was generated with only one output type
            if let Some((gen_has_secret, gen_has_public)) =
                self.get_generated_output_info(name)
            {
                if !gen_has_public {
                    messages.push(format!(
                        "Dependency '{}' was generated but only produced a 'secret' output, not 'public'. \
                        If your generator uses publics.\"{}\", the dependency generator needs to return \
                        {{ secret = ...; public = ...; }} instead of just {{ secret = ...; }}",
                        dep_key, dep_key
                    ));
                }
                if !gen_has_secret {
                    messages.push(format!(
                        "Dependency '{}' was generated but only produced a 'public' output, not 'secret'. \
                        If your generator uses secrets.\"{}\", the dependency generator needs to return \
                        {{ secret = ...; public = ...; }} or just {{ secret = ...; }} instead of {{ public = ...; }}",
                        dep_key, dep_key
                    ));
                }
            } else if !has_secret && !has_public {
                messages.push(format!(
                    "Dependency '{}' has not been generated yet and has no .pub file available.\n\
                     \n\
                     To fix: Ensure '{}' either:\n\
                     1. Has a generator that produces output (string or {{ secret/public }}), or\n\
                     2. Has an existing .pub file, or\n\
                     3. If it has hasSecret=false, also set hasPublic=true with a generator that returns {{ public = ...; }}",
                    dep_key, dep_key
                ));
            } else if !has_secret {
                messages.push(format!(
                    "Dependency '{}' only has a .pub file available (no secret content).\n\
                     If your generator uses secrets.\"{}\", you need to regenerate the dependency first",
                    dep_key, dep_key
                ));
            }
        }

        messages
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
