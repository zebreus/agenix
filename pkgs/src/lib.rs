mod cli;
mod crypto;
mod editor;
mod nix;
pub mod output;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::path::Path;

/// Check if the secrets.nix file exists and provide a helpful error message if not.
///
/// This gives users a clear hint about what to do when the default `secrets.nix`
/// doesn't exist in the current directory.
fn check_secrets_nix_exists(secrets_nix_path: &str) -> Result<()> {
    let path = Path::new(secrets_nix_path);
    if !path.exists() {
        return Err(anyhow!(
            "secrets.nix not found: {}\nHint: cd to a directory with secrets.nix, or use --secrets-nix to specify the path",
            secrets_nix_path
        ));
    }
    Ok(())
}

/// Normalize a secrets.nix path for use in Nix expressions.
///
/// This ensures that relative paths without a `.` or `/` prefix are properly
/// interpreted as file paths rather than Nix variable names.
///
/// # Examples
/// - `"secrets.nix"` -> `"./secrets.nix"`
/// - `"./secrets.nix"` -> `"./secrets.nix"` (unchanged)
/// - `"/absolute/path.nix"` -> `"/absolute/path.nix"` (unchanged)
/// - `"../parent/secrets.nix"` -> `"../parent/secrets.nix"` (unchanged)
fn normalize_secrets_nix_path(secrets_nix_path: &str) -> String {
    let path = Path::new(secrets_nix_path);

    // If it's an absolute path, return as-is
    if path.is_absolute() {
        return secrets_nix_path.to_string();
    }

    // If it already starts with ./ or ../, return as-is
    if secrets_nix_path.starts_with("./") || secrets_nix_path.starts_with("../") {
        return secrets_nix_path.to_string();
    }

    // Otherwise, prepend ./ to make it a relative path
    format!("./{}", secrets_nix_path)
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

    // Normalize the secrets.nix path to ensure proper Nix import
    let secrets_nix = normalize_secrets_nix_path(&args.secrets_nix);

    verbose!("Using secrets.nix: {}", secrets_nix);
    if !args.identity.is_empty() {
        verbose!("Using {} explicit identity file(s)", args.identity.len());
    }
    if args.no_system_identities {
        verbose!("System identities disabled");
    }
    if args.dry_run {
        verbose!("Dry-run mode enabled");
    }

    // Check if secrets.nix exists (for all commands except completions and no command)
    if args.command.is_some() && !matches!(args.command, Some(cli::Command::Completions { .. })) {
        check_secrets_nix_exists(&secrets_nix)?;
    }

    match args.command {
        Some(cli::Command::Rekey { secrets, partial }) => editor::rekey_files(
            &secrets_nix,
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
        }) => editor::generate_secrets(
            &secrets_nix,
            force,
            args.dry_run,
            !no_dependencies,
            &secrets,
        )
        .context("Failed to generate secrets"),
        Some(cli::Command::Decrypt {
            file,
            output,
            public,
        }) => {
            let op = if public {
                "read public file"
            } else {
                "decrypt"
            };
            if public {
                editor::read_public_file(&secrets_nix, &file, output.as_deref())
            } else {
                editor::decrypt_file(
                    &secrets_nix,
                    &file,
                    output.as_deref(),
                    &args.identity,
                    args.no_system_identities,
                )
            }
            .with_context(|| format!("Failed to {} {}", op, file))
        }
        Some(cli::Command::Edit {
            file,
            editor,
            force,
            public,
        }) => {
            let op = if public { "edit public file" } else { "edit" };
            if public {
                editor::edit_public_file(
                    &secrets_nix,
                    &file,
                    editor.as_deref(),
                    force,
                    args.dry_run,
                )
            } else {
                editor::edit_file(
                    &secrets_nix,
                    &file,
                    editor.as_deref(),
                    &args.identity,
                    args.no_system_identities,
                    force,
                    args.dry_run,
                )
            }
            .with_context(|| format!("Failed to {} {}", op, file))
        }
        Some(cli::Command::Encrypt {
            file,
            input,
            force,
            public,
        }) => {
            let op = if public {
                "write public file"
            } else {
                "encrypt"
            };
            if public {
                editor::write_public_file(
                    &secrets_nix,
                    &file,
                    input.as_deref(),
                    force,
                    args.dry_run,
                )
            } else {
                editor::encrypt_file(&secrets_nix, &file, input.as_deref(), force, args.dry_run)
            }
            .with_context(|| format!("Failed to {} {}", op, file))
        }
        Some(cli::Command::List { status, secrets }) => editor::list_secrets(
            &secrets_nix,
            status,
            &secrets,
            &args.identity,
            args.no_system_identities,
        )
        .context("Failed to list secrets"),
        Some(cli::Command::Check { secrets }) => editor::check_secrets(
            &secrets_nix,
            &secrets,
            &args.identity,
            args.no_system_identities,
        )
        .context("Failed to check secrets"),
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
    fn test_normalize_secrets_nix_path_relative() {
        assert_eq!(normalize_secrets_nix_path("secrets.nix"), "./secrets.nix");
        assert_eq!(normalize_secrets_nix_path("foo/bar.nix"), "./foo/bar.nix");
    }

    #[test]
    fn test_normalize_secrets_nix_path_already_relative() {
        assert_eq!(normalize_secrets_nix_path("./secrets.nix"), "./secrets.nix");
        assert_eq!(
            normalize_secrets_nix_path("../secrets.nix"),
            "../secrets.nix"
        );
        assert_eq!(
            normalize_secrets_nix_path("./subdir/secrets.nix"),
            "./subdir/secrets.nix"
        );
    }

    #[test]
    fn test_normalize_secrets_nix_path_absolute() {
        assert_eq!(
            normalize_secrets_nix_path("/etc/agenix/secrets.nix"),
            "/etc/agenix/secrets.nix"
        );
        assert_eq!(
            normalize_secrets_nix_path("/home/user/secrets.nix"),
            "/home/user/secrets.nix"
        );
    }

    #[test]
    fn test_check_secrets_nix_exists_missing() {
        let result = check_secrets_nix_exists("/nonexistent/path/secrets.nix");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("secrets.nix not found"),
            "Error should mention secrets.nix not found: {}",
            err_msg
        );
        assert!(
            err_msg.contains("Hint:"),
            "Error should contain a hint: {}",
            err_msg
        );
        assert!(
            err_msg.contains("cd to a directory with secrets.nix"),
            "Hint should suggest changing directory: {}",
            err_msg
        );
        assert!(
            err_msg.contains("--secrets-nix"),
            "Hint should mention --secrets-nix flag: {}",
            err_msg
        );
    }

    #[test]
    fn test_check_secrets_nix_exists_present() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "{{}}").unwrap();
        temp_file.flush().unwrap();

        let result = check_secrets_nix_exists(temp_file.path().to_str().unwrap());
        assert!(result.is_ok());
    }
}
