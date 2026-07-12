mod cli;
mod crypto;
mod nix;
pub mod output;

use clap::Parser;
use rootcause::report_collection::ReportCollection;
use rootcause::{Report, prelude::*, report};
use std::io::{Read, Write};

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
            persist(args.dry_run)
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
        Some(cli::Command::Encrypt {
            secret,
            input,
            force,
            public,
        }) => {
            nix::init(config(nix::Operation::Read))?;
            let info = nix::entry_info(&secret)?;
            let exists = if public { info.public } else { info.secret };
            if exists == Some(true) && !force {
                let file = if public { "pub" } else { "age" };
                return Err(report!(
                    "{secret}.{file} already exists. Use --force to overwrite it."
                ));
            }

            let content = match input {
                Some(path) => {
                    std::fs::read(&path).context(format!("Failed to read {path}"))?
                }
                None => {
                    let mut content = vec![];
                    std::io::stdin()
                        .read_to_end(&mut content)
                        .context("Failed to read from stdin")?;
                    content
                }
            };
            if public {
                nix::set_public(&secret, content)?;
            } else {
                nix::set_secret(&secret, content)?;
            }
            counterpart_note(&secret, public, info);
            persist(args.dry_run)
        }
        Some(cli::Command::Edit {
            secret,
            editor,
            force,
            public,
        }) => {
            nix::init(config(nix::Operation::Read))?;
            let info = nix::entry_info(&secret)?;
            let exists = if public { info.public } else { info.secret };
            let read_part = if public {
                nix::get_public
            } else {
                nix::get_secret
            };

            let current = match exists {
                Some(true) => match read_part(&secret) {
                    Ok(content) => content,
                    Err(e) if force => {
                        log!("Warning: could not read the current value, starting empty:\n{e:?}");
                        vec![]
                    }
                    Err(e) => return Err(e),
                },
                Some(false) => vec![],
                None => {
                    let part = if public { "public" } else { "secret" };
                    return Err(report!("'{secret}' does not have a {part} part"));
                }
            };

            let mut tmp = tempfile::Builder::new()
                .prefix(&format!("{secret}."))
                .tempfile()
                .context("Failed to create temporary file")?;
            tmp.write_all(&current)
                .context("Failed to write temporary file")?;
            tmp.flush().context("Failed to write temporary file")?;
            run_editor(editor.as_deref().unwrap_or("vi"), tmp.path())?;
            let edited = std::fs::read(tmp.path()).context("Failed to read edited content")?;

            if exists == Some(true) && edited == current {
                log!("Content unchanged, nothing to do");
                return Ok(());
            }
            if public {
                nix::set_public(&secret, edited)?;
            } else {
                nix::set_secret(&secret, edited)?;
            }
            counterpart_note(&secret, public, info);
            persist(args.dry_run)
        }
        Some(cli::Command::Rekey { partial, secrets }) => {
            nix::init(config(nix::Operation::Read))?;
            let names = if secrets.is_empty() {
                nix::list_names()?
            } else {
                secrets
            };
            let mut rekeyed = 0usize;
            let mut skipped = vec![];
            for name in &names {
                match nix::rekey_entry(name) {
                    Ok(true) => rekeyed += 1,
                    Ok(false) => {}
                    Err(e) if partial => skipped.push(format!("{:?}", e)),
                    Err(e) => {
                        return Err(e
                            .context(format!(
                                "Cannot rekey '{name}'. No secrets were modified. Use \
                                 --partial to rekey only the secrets that can be decrypted."
                            ))
                            .into_dyn_any());
                    }
                }
            }
            for warning in &skipped {
                log!("Warning: skipped {warning}");
            }
            persist(args.dry_run)?;
            log!(
                "Rekeyed {rekeyed} {}",
                output::pluralize_secret(rekeyed)
            );
            Ok(())
        }
        Some(cli::Command::Completions { shell }) => {
            cli::print_completions(shell, &mut cli::build_cli());
            Ok(())
        }
        None => Ok(()),
    }
}

/// Write all pending values to disk, or just say so in dry-run mode.
fn persist(dry_run: bool) -> Result<(), Report> {
    if dry_run {
        log!("Dry run: not writing any files");
        Ok(())
    } else {
        nix::flush()
    }
}

/// After setting one part of an entry, point out that the other part is not
/// updated automatically and may no longer match.
fn counterpart_note(name: &str, set_public: bool, info: nix::EntryInfo) {
    let (counterpart, this, other) = if set_public {
        (info.secret, "public", "secret")
    } else {
        (info.public, "secret", "public")
    };
    if counterpart.is_some() {
        log!("Note: '{name}' also has a {other} part; make sure it still matches the new {this}.");
    }
}

/// Run the user's editor on a file. The command may contain arguments
/// ("code --wait"); the file path is passed as a positional argument.
fn run_editor(editor: &str, path: &std::path::Path) -> Result<(), Report> {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(path)
        .status()
        .context(format!("Failed to run editor: {editor}"))?;
    if !status.success() {
        return Err(report!("Editor exited with {status}"));
    }
    Ok(())
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
                r#"{
                  "token" = { publicKeys = [ "{PUB}" ]; hasPublic = true; };
                  "fresh" = { publicKeys = [ "{PUB}" ]; };
                  "sealed" = { publicKeys = [ "{PUB}" ]; };
                }"#
                .replace("{PUB}", &identity.to_public().to_string()),
            )
            .unwrap();

            let ciphertext =
                crypto::encrypt(b"token-plaintext", &[identity.to_public().to_string()], false)
                    .unwrap();
            std::fs::write(dir.path().join("token.age"), ciphertext).unwrap();
            std::fs::write(dir.path().join("token.pub"), b"token-public").unwrap();

            // A secret no identity of this fixture can decrypt.
            let other = age::x25519::Identity::generate();
            let sealed =
                crypto::encrypt(b"lost", &[other.to_public().to_string()], false).unwrap();
            std::fs::write(dir.path().join("sealed.age"), sealed).unwrap();

            Cli {
                rules: rules.to_str().unwrap().to_string(),
                identity: identity_path.to_str().unwrap().to_string(),
                dir,
            }
        }

        fn read(&self, file: &str) -> Vec<u8> {
            std::fs::read(self.dir.path().join(file)).unwrap()
        }

        /// Decrypt a secret file with the fixture identity.
        fn decrypt_file(&self, file: &str) -> Vec<u8> {
            crypto::decrypt(&self.read(file), &[self.identity.clone()], true).unwrap()
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
    fn encrypt_new_secret_from_input_file() {
        let cli = Cli::new();
        let input = cli.dir.path().join("input.txt");
        std::fs::write(&input, b"fresh-content").unwrap();
        cli.run(&["encrypt", "fresh", "--input", input.to_str().unwrap()])
            .unwrap();
        assert_eq!(cli.decrypt_file("fresh.age"), b"fresh-content");
    }

    #[test]
    fn encrypt_refuses_existing_secret_without_force() {
        let cli = Cli::new();
        let input = cli.dir.path().join("input.txt");
        std::fs::write(&input, b"new").unwrap();
        let before = cli.read("token.age");
        assert!(
            cli.run(&["encrypt", "token", "--input", input.to_str().unwrap()])
                .is_err()
        );
        assert_eq!(cli.read("token.age"), before);

        cli.run(&["encrypt", "token", "--force", "--input", input.to_str().unwrap()])
            .unwrap();
        assert_eq!(cli.decrypt_file("token.age"), b"new");
    }

    #[test]
    fn encrypt_public_writes_pub_file() {
        let cli = Cli::new();
        let input = cli.dir.path().join("input.txt");
        std::fs::write(&input, b"new-public").unwrap();
        cli.run(&[
            "encrypt",
            "token",
            "--public",
            "--force",
            "--input",
            input.to_str().unwrap(),
        ])
        .unwrap();
        assert_eq!(cli.read("token.pub"), b"new-public");
    }

    /// A fake editor script that writes fixed content to the file it is
    /// given.
    fn fake_editor(cli: &Cli, content: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let script = cli.dir.path().join("fake-editor.sh");
        std::fs::write(&script, format!("#!/bin/sh\nprintf '%s' '{content}' > \"$1\"\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script.to_str().unwrap().to_string()
    }

    #[test]
    fn edit_replaces_secret_content() {
        let cli = Cli::new();
        let editor = fake_editor(&cli, "edited-secret");
        cli.run(&["edit", "token", "--editor", &editor]).unwrap();
        assert_eq!(cli.decrypt_file("token.age"), b"edited-secret");
        // The public part is untouched.
        assert_eq!(cli.read("token.pub"), b"token-public");
    }

    #[test]
    fn edit_creates_missing_secret() {
        let cli = Cli::new();
        let editor = fake_editor(&cli, "created");
        cli.run(&["edit", "fresh", "--editor", &editor]).unwrap();
        assert_eq!(cli.decrypt_file("fresh.age"), b"created");
    }

    #[test]
    fn edit_unchanged_content_writes_nothing() {
        let cli = Cli::new();
        let before = cli.read("token.age");
        cli.run(&["edit", "token", "--editor", "true"]).unwrap();
        assert_eq!(cli.read("token.age"), before);
    }

    #[test]
    fn edit_undecryptable_secret_requires_force() {
        let cli = Cli::new();
        let editor = fake_editor(&cli, "replaced");
        assert!(cli.run(&["edit", "sealed", "--editor", &editor]).is_err());
        cli.run(&["edit", "sealed", "--force", "--editor", &editor])
            .unwrap();
        assert_eq!(cli.decrypt_file("sealed.age"), b"replaced");
    }

    #[test]
    fn rekey_without_partial_is_all_or_nothing() {
        let cli = Cli::new();
        let token_before = cli.read("token.age");
        let sealed_before = cli.read("sealed.age");
        // "sealed" cannot be decrypted: strict rekey must fail without
        // touching anything.
        assert!(cli.run(&["rekey"]).is_err());
        assert_eq!(cli.read("token.age"), token_before);
        assert_eq!(cli.read("sealed.age"), sealed_before);
    }

    #[test]
    fn rekey_partial_rewrites_what_it_can() {
        let cli = Cli::new();
        let token_before = cli.read("token.age");
        let sealed_before = cli.read("sealed.age");
        let pub_before = cli.read("token.pub");
        cli.run(&["rekey", "--partial", "token", "sealed"]).unwrap();
        // token is re-encrypted (fresh nonce -> different bytes), sealed is
        // skipped, and the public part is never touched.
        assert_ne!(cli.read("token.age"), token_before);
        assert_eq!(cli.decrypt_file("token.age"), b"token-plaintext");
        assert_eq!(cli.read("sealed.age"), sealed_before);
        assert_eq!(cli.read("token.pub"), pub_before);
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
