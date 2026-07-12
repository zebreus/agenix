mod cli;
mod crypto;
mod nix;
pub mod output;

use clap::Parser;
use rootcause::Report;
use rootcause::prelude::*;
use rootcause::report_collection::ReportCollection;
use std::io::Write;

/// Parse CLI arguments and execute the requested command.
///
/// This is the single public entrypoint used by the binary and tests.
pub fn run<I, T>(iter: I) -> Result<(), Report>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args = cli::Args::parse_from(iter);
    output::set_verbose(args.verbose);
    output::set_quiet(args.quiet);

    let config = |operation| nix::Config {
        rules_path: args.secrets_nix.clone().into(),
        identities: args.identity.clone(),
        no_system_identities: args.no_system_identities,
        operation,
    };

    match args.command {
        Some(cli::Command::Generate {
            force,
            no_dependencies,
            secrets,
        }) => {
            nix::init(config(nix::Operation::Generate {
                targets: secrets,
                force,
                dependents: !no_dependencies,
            }))?;
            nix::generate()?;
            if args.dry_run {
                log!("Dry run: not writing any files");
                Ok(())
            } else {
                nix::flush()
            }
        }
        Some(cli::Command::Check { secrets }) => {
            nix::init(config(nix::Operation::Read))?;
            let names = if secrets.is_empty() {
                nix::list_names()?
            } else {
                secrets
            };
            let mut reports = ReportCollection::new();
            for name in &names {
                if let Err(e) = nix::check_entry(name) {
                    reports.push(e.into_cloneable());
                }
            }
            if reports.is_empty() {
                log!("All checks passed");
                Ok(())
            } else {
                Err(reports.context("Check failed").into())
            }
        }
        Some(cli::Command::Decrypt {
            secret,
            output,
            public,
        }) => {
            nix::init(config(nix::Operation::Read))?;
            let content = if public {
                nix::get_public(&secret)?
            } else {
                nix::get_secret(&secret)?
            };
            match output {
                Some(path) => Ok(std::fs::write(&path, content)
                    .context(format!("Failed to write {path}"))?),
                None => Ok(std::io::stdout()
                    .write_all(&content)
                    .context("Failed to write to stdout")?),
            }
        }
        Some(cli::Command::List { status, secrets }) => {
            nix::init(config(nix::Operation::Read))?;
            let names = if secrets.is_empty() {
                nix::list_names()?
            } else {
                secrets
            };
            for name in &names {
                if status {
                    println!("{name}\t{}", status_code(nix::status(name)?));
                } else {
                    println!("{name}");
                }
            }
            Ok(())
        }
        // The remaining commands are rebuilt on the resolution engine one by
        // one; see docs/core-design.md.
        Some(
            cli::Command::Rekey { .. } | cli::Command::Edit { .. } | cli::Command::Encrypt { .. },
        ) => todo!("not yet rebuilt on the resolution engine"),
        Some(cli::Command::Completions { shell }) => {
            cli::print_completions(shell, &mut cli::build_cli());
            Ok(())
        }
        None => Ok(()),
    }
}

/// Script-friendly status code for `list --status`.
fn status_code(status: nix::EntryStatus) -> &'static str {
    use nix::PartStatus::{Available, CannotDecrypt, Missing};
    match (status.secret, status.public) {
        (Some(CannotDecrypt), _) => "NO_DECRYPT",
        (Some(Missing), _) => "MISSING",
        (Some(Available), Some(Missing)) => "PUB_MISSING",
        (Some(Available), _) => "EXISTS",
        (None, Some(Missing)) => "PUB_MISSING",
        (None, Some(_)) => "PUBLIC_ONLY",
        (None, None) => "NOTHING",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use nix::{EntryStatus, PartStatus};
    use tempfile::TempDir;

    /// A secrets directory with one encrypted secret and its identity,
    /// exercised through the real CLI entrypoint.
    struct Cli {
        dir: TempDir,
        rules: String,
        identity: String,
    }

    impl Cli {
        fn new() -> Cli {
            let dir = tempfile::tempdir().unwrap();
            let identity = age::x25519::Identity::generate();
            let identity_path = dir.path().join("identity.txt");
            std::fs::write(
                &identity_path,
                format!("{}\n", identity.to_string().expose_secret()),
            )
            .unwrap();

            let rules = dir.path().join("secrets.nix");
            std::fs::write(
                &rules,
                r#"{ "token" = { publicKeys = [ "{PUB}" ]; hasPublic = true; }; }"#
                    .replace("{PUB}", &identity.to_public().to_string()),
            )
            .unwrap();

            let ciphertext =
                crypto::encrypt(b"token-plaintext", &[identity.to_public().to_string()], false)
                    .unwrap();
            std::fs::write(dir.path().join("token.age"), ciphertext).unwrap();
            std::fs::write(dir.path().join("token.pub"), b"token-public").unwrap();

            Cli {
                rules: rules.to_str().unwrap().to_string(),
                identity: identity_path.to_str().unwrap().to_string(),
                dir,
            }
        }

        fn run(&self, args: &[&str]) -> Result<(), Report> {
            let base = [
                "agenix",
                "--secrets-nix",
                &self.rules,
                "--identity",
                &self.identity,
                "--no-system-identities",
            ];
            run(base.iter().copied().chain(args.iter().copied()))
        }
    }

    #[test]
    fn decrypt_writes_secret_to_output_file() {
        let cli = Cli::new();
        let out = cli.dir.path().join("out.txt");
        cli.run(&["decrypt", "token", "--output", out.to_str().unwrap()])
            .unwrap();
        assert_eq!(std::fs::read(out).unwrap(), b"token-plaintext");
    }

    #[test]
    fn decrypt_public_writes_pub_content() {
        let cli = Cli::new();
        let out = cli.dir.path().join("out.txt");
        cli.run(&["decrypt", "--public", "token", "--output", out.to_str().unwrap()])
            .unwrap();
        assert_eq!(std::fs::read(out).unwrap(), b"token-public");
    }

    #[test]
    fn decrypt_unknown_secret_fails() {
        let cli = Cli::new();
        let out = cli.dir.path().join("out.txt");
        assert!(
            cli.run(&["decrypt", "nope", "--output", out.to_str().unwrap()])
                .is_err()
        );
        assert!(!out.exists());
    }

    #[test]
    fn status_codes_cover_all_part_combinations() {
        use PartStatus::{Available, CannotDecrypt, Missing};
        let code = |secret, public| status_code(EntryStatus { secret, public });
        assert_eq!(code(Some(Available), None), "EXISTS");
        assert_eq!(code(Some(Available), Some(Available)), "EXISTS");
        assert_eq!(code(Some(Available), Some(Missing)), "PUB_MISSING");
        assert_eq!(code(Some(Missing), None), "MISSING");
        assert_eq!(code(Some(Missing), Some(Available)), "MISSING");
        assert_eq!(code(Some(CannotDecrypt), None), "NO_DECRYPT");
        assert_eq!(code(None, Some(Available)), "PUBLIC_ONLY");
        assert_eq!(code(None, Some(Missing)), "PUB_MISSING");
        assert_eq!(code(None, None), "NOTHING");
    }
}
