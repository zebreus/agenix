mod cli;
mod crypto;
mod editor;
mod nix;
pub mod output;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::Path;

/// Normalize a rules path for use in Nix expressions.
///
/// This ensures that relative paths without a `.` or `/` prefix are properly
/// interpreted as file paths rather than Nix variable names.
///
/// # Examples
/// - `"secrets.nix"` -> `"./secrets.nix"`
/// - `"./secrets.nix"` -> `"./secrets.nix"` (unchanged)
/// - `"/absolute/path.nix"` -> `"/absolute/path.nix"` (unchanged)
/// - `"../parent/secrets.nix"` -> `"../parent/secrets.nix"` (unchanged)
fn normalize_rules_path(rules_path: &str) -> String {
    let path = Path::new(rules_path);

    // If it's an absolute path, return as-is
    if path.is_absolute() {
        return rules_path.to_string();
    }

    // If it already starts with ./ or ../, return as-is
    if rules_path.starts_with("./") || rules_path.starts_with("../") {
        return rules_path.to_string();
    }

    // Otherwise, prepend ./ to make it a relative path
    format!("./{}", rules_path)
}

/// Parse CLI arguments and execute the requested action.
///
/// This is the single public entrypoint used by the binary and tests.
///
/// # Errors
/// Returns an error if required dependencies (`age`, `nix-instantiate`) are missing,
/// if parsing arguments fails, or if any operation (rekey, decrypt, edit) fails.
pub fn run<I, T>(iter: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args = cli::Args::parse_from(iter);

    // Set global verbosity/quiet flags
    output::set_verbose(args.verbose);
    output::set_quiet(args.quiet);

    // Normalize the rules path to ensure proper Nix import
    let rules = normalize_rules_path(&args.rules);

    verbose!("Using rules file: {}", rules);
    if !args.identity.is_empty() {
        verbose!("Using {} explicit identity file(s)", args.identity.len());
    }
    if args.no_system_identities {
        verbose!("System identities disabled");
    }
    if args.dry_run {
        verbose!("Dry-run mode enabled");
    }

    match args.command {
        Some(cli::Command::Rekey { secrets, partial }) => editor::rekey_files(
            &rules,
            &secrets,
            &args.identity,
            args.no_system_identities,
            partial,
            args.dry_run,
        )
        .context("Failed to rekey files"),
        Some(cli::Command::Generate {
            force,
            no_dependencies,
            secrets,
        }) => editor::generate_secrets(&rules, force, args.dry_run, !no_dependencies, &secrets)
            .context("Failed to generate secrets"),
        Some(cli::Command::Decrypt { file, output }) => editor::decrypt_file(
            &rules,
            &file,
            output.as_deref(),
            &args.identity,
            args.no_system_identities,
        )
        .with_context(|| format!("Failed to decrypt {file}")),
        Some(cli::Command::Edit {
            file,
            editor,
            force,
        }) => editor::edit_file(
            &rules,
            &file,
            editor.as_deref(),
            &args.identity,
            args.no_system_identities,
            force,
            args.dry_run,
        )
        .with_context(|| format!("Failed to edit {file}")),
        Some(cli::Command::Encrypt { file, force }) => {
            editor::encrypt_file(&rules, &file, force, args.dry_run)
                .with_context(|| format!("Failed to encrypt {file}"))
        }
        Some(cli::Command::List { detailed }) => {
            editor::list_secrets(&rules, detailed, &args.identity, args.no_system_identities)
                .context("Failed to list secrets")
        }
        Some(cli::Command::Check { secrets }) => {
            editor::check_secrets(&rules, &secrets, &args.identity, args.no_system_identities)
                .context("Failed to check secrets")
        }
        Some(cli::Command::Completions { shell }) => {
            cli::print_completions(shell, &mut cli::build_cli());
            Ok(())
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_rules_path_relative() {
        assert_eq!(normalize_rules_path("secrets.nix"), "./secrets.nix");
        assert_eq!(normalize_rules_path("foo/bar.nix"), "./foo/bar.nix");
    }

    #[test]
    fn test_normalize_rules_path_already_relative() {
        assert_eq!(normalize_rules_path("./secrets.nix"), "./secrets.nix");
        assert_eq!(normalize_rules_path("../secrets.nix"), "../secrets.nix");
        assert_eq!(
            normalize_rules_path("./subdir/secrets.nix"),
            "./subdir/secrets.nix"
        );
    }

    #[test]
    fn test_normalize_rules_path_absolute() {
        assert_eq!(
            normalize_rules_path("/etc/agenix/secrets.nix"),
            "/etc/agenix/secrets.nix"
        );
        assert_eq!(
            normalize_rules_path("/home/user/secrets.nix"),
            "/home/user/secrets.nix"
        );
    }
}
