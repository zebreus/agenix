mod cli;
mod crypto;
mod nix;
pub mod output;

use clap::Parser;
use rootcause::Report;
use rootcause::report_collection::ReportCollection;

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
        // The remaining commands are rebuilt on the resolution engine one by
        // one; see docs/core-design.md.
        Some(
            cli::Command::Rekey { .. }
            | cli::Command::Decrypt { .. }
            | cli::Command::Edit { .. }
            | cli::Command::Encrypt { .. }
            | cli::Command::List { .. },
        ) => todo!("not yet rebuilt on the resolution engine"),
        Some(cli::Command::Completions { shell }) => {
            cli::print_completions(shell, &mut cli::build_cli());
            Ok(())
        }
        None => Ok(()),
    }
}
