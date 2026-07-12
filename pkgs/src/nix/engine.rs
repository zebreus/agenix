//! The secret resolution engine.
//!
//! One engine instance serves a whole CLI invocation: [`init`] configures it,
//! commands ask for values via [`get_secret`]/[`get_public`], and [`flush`]
//! persists everything that was generated. The engine is the only component
//! that reads or writes secret files.
//!
//! Resolution is lazy and re-entrant: generators receive
//! `builtins.getSecret`/`builtins.getPublic` thunks that call back into the
//! engine, so Nix's laziness drives the resolution order and cycles surface
//! as [`PartState::WorkInProgress`]. The engine is strictly single-threaded
//! (state lives in a thread-local).

use super::eval::{eval_nix_expression, value_to_string_array};
use super::generator::call_generator;
use super::public_key::PublicKeyString;
use super::raw_secret_entry::{Part, RawSecretEntry, get_raw_secret_entry, validate_name};
use crate::crypto;
use rootcause::report_collection::ReportCollection;
use rootcause::{Report, prelude::*, report};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// What the current invocation does with the entries.
#[derive(Debug, Clone)]
pub enum Operation {
    /// Read-only: nothing is ever generated or written.
    Read,
    /// The generate command. Empty `targets` means all entries.
    Generate {
        targets: Vec<String>,
        force: bool,
        /// Generate missing dependencies on demand and regenerate entries
        /// that declare a regenerated target as a dependency
        /// (false with --no-dependencies).
        dependents: bool,
    },
}

pub struct Config {
    pub rules_path: PathBuf,
    pub identities: Vec<String>,
    pub no_system_identities: bool,
    pub operation: Operation,
}

/// What the engine is allowed to do with one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryMode {
    /// Only read what is on disk.
    ReadOnly,
    /// Generate only when no file of the entry exists yet.
    GenerateIfMissing,
    /// Generate when the entry is incomplete, overwriting a partial pair.
    Generate,
    /// Always generate, overwriting existing files.
    ForceGenerate,
}

/// Whether one part of an entry is present and usable (for `list --status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartStatus {
    /// The file exists (and, for secrets, is decryptable).
    Available,
    /// The file does not exist.
    Missing,
    /// The secret file exists but no identity can decrypt it.
    CannotDecrypt,
}

/// Status of an entry's parts. None means the entry declares that part
/// does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryStatus {
    pub secret: Option<PartStatus>,
    pub public: Option<PartStatus>,
}

/// Resolution state of one part of an entry. Absence from the state map
/// means the part has not been resolved yet.
#[derive(Clone, Debug)]
enum PartState {
    /// On disk, still ciphertext.
    Encrypted(Vec<u8>),
    /// Available as plaintext (public file content or decrypted secret).
    PlainText(Vec<u8>),
    /// Produced by a generator this run; not yet on disk.
    NewlyGenerated(Vec<u8>),
    /// This entry's generator is currently running.
    WorkInProgress,
    /// Expected but neither on disk nor generatable.
    Missing,
    /// The entry declares this part does not exist.
    NotNeeded,
}

pub struct Engine {
    /// Absolute path to secrets.nix.
    rules_path: PathBuf,
    /// The directory containing secrets.nix and all secret files.
    dir: PathBuf,
    identities: Vec<String>,
    no_system_identities: bool,
    /// All entry names (attrNames order, i.e. sorted).
    names: Vec<String>,
    modes: HashMap<String, EntryMode>,
    /// Entries the generate command must resolve.
    agenda: Vec<String>,
    entries: RefCell<HashMap<String, Rc<RawSecretEntry>>>,
    parts: RefCell<HashMap<(String, Part), PartState>>,
}

impl Engine {
    fn new(config: Config) -> Result<Engine, Report> {
        let rules_path = std::path::absolute(&config.rules_path)
            .context("Failed to make the secrets.nix path absolute")?;
        if !rules_path.is_file() {
            return Err(report!(
                "No rules file found at {}. Create a secrets.nix or point at \
                 one with --secrets-nix.",
                rules_path.display()
            ));
        }
        let dir = rules_path
            .parent()
            .expect("an absolute file path has a parent")
            .to_path_buf();

        let names = load_names(&rules_path)?;
        let mut reports = ReportCollection::new();
        for name in &names {
            if let Err(e) = validate_name(name) {
                reports.push(e.into_cloneable());
            }
        }
        if !reports.is_empty() {
            return Err(reports.context("secrets.nix contains invalid names").into());
        }

        let mut engine = Engine {
            rules_path,
            dir,
            identities: config.identities,
            no_system_identities: config.no_system_identities,
            names,
            modes: HashMap::new(),
            agenda: vec![],
            entries: RefCell::new(HashMap::new()),
            parts: RefCell::new(HashMap::new()),
        };
        (engine.modes, engine.agenda) = engine.plan(&config.operation)?;
        Ok(engine)
    }

    /// Compute per-entry modes and the generation agenda for an operation.
    /// This encodes the CLI matrix from docs/core-design.md.
    fn plan(
        &self,
        operation: &Operation,
    ) -> Result<(HashMap<String, EntryMode>, Vec<String>), Report> {
        let all = |mode: EntryMode| -> HashMap<String, EntryMode> {
            self.names.iter().map(|n| (n.clone(), mode)).collect()
        };

        let Operation::Generate {
            targets,
            force,
            dependents,
        } = operation
        else {
            return Ok((all(EntryMode::ReadOnly), vec![]));
        };

        if targets.is_empty() {
            let mode = if *force {
                EntryMode::ForceGenerate
            } else {
                EntryMode::GenerateIfMissing
            };
            return Ok((all(mode), self.names.clone()));
        }

        for target in targets {
            if !self.names.contains(target) {
                return Err(report!(
                    "Cannot generate '{target}': no such entry in secrets.nix"
                ));
            }
        }

        let others = if *dependents {
            EntryMode::GenerateIfMissing
        } else {
            EntryMode::ReadOnly
        };
        let mut modes = all(others);
        let target_mode = if *force {
            EntryMode::ForceGenerate
        } else {
            EntryMode::Generate
        };
        for target in targets {
            modes.insert(target.clone(), target_mode);
        }
        let mut agenda = targets.clone();

        if *dependents {
            // Regenerating an entry also regenerates everything that declares
            // it as a dependency. Which targets will regenerate is known up
            // front (forced, or incomplete on disk); the cascade joins the
            // agenda with ForceGenerate and Nix laziness keeps the dataflow
            // order correct.
            let mut regenerated: HashSet<String> = HashSet::new();
            for target in targets {
                if *force || !self.complete_on_disk(target)? {
                    regenerated.insert(target.clone());
                }
            }
            loop {
                let mut grew = false;
                for name in &self.names {
                    if regenerated.contains(name) {
                        continue;
                    }
                    let depends_on_regenerated = self
                        .entry(name)?
                        .dependencies
                        .iter()
                        .any(|dep| regenerated.contains(dep));
                    if depends_on_regenerated {
                        regenerated.insert(name.clone());
                        modes.insert(name.clone(), EntryMode::ForceGenerate);
                        agenda.push(name.clone());
                        grew = true;
                    }
                }
                if !grew {
                    break;
                }
            }
        }

        Ok((modes, agenda))
    }

    /// Whether every needed part of an entry exists on disk.
    fn complete_on_disk(&self, name: &str) -> Result<bool, Report> {
        let entry = self.entry(name)?;
        Ok([Part::Secret, Part::Public]
            .iter()
            .all(|&part| !entry.has(part) || self.part_path(name, part).exists()))
    }

    /// Load (and cache) the effective secrets.nix entry for `name`.
    fn entry(&self, name: &str) -> Result<Rc<RawSecretEntry>, Report> {
        if let Some(entry) = self.entries.borrow().get(name) {
            return Ok(entry.clone());
        }
        if !self.names.iter().any(|n| n == name) {
            return Err(report!("No entry named '{name}' in secrets.nix"));
        }
        let entry = Rc::new(get_raw_secret_entry(&self.rules_path, name)?);
        self.entries
            .borrow_mut()
            .insert(name.to_string(), entry.clone());
        Ok(entry)
    }

    fn mode(&self, name: &str) -> EntryMode {
        *self
            .modes
            .get(name)
            .expect("every known name has a planned mode")
    }

    fn part_path(&self, name: &str, part: Part) -> PathBuf {
        self.dir.join(part.file_name(name))
    }

    fn state(&self, name: &str, part: Part) -> Option<PartState> {
        self.parts.borrow().get(&(name.to_string(), part)).cloned()
    }

    fn set_state(&self, name: &str, part: Part, state: PartState) {
        self.parts
            .borrow_mut()
            .insert((name.to_string(), part), state);
    }

    /// Resolve one part of an entry to a final [`PartState`]: load it from
    /// disk, generate it, or mark it missing/not needed.
    fn resolve(&self, name: &str, part: Part) -> Result<(), Report> {
        match self.state(name, part) {
            Some(PartState::WorkInProgress) => {
                return Err(report!(
                    "Circular dependency: the generator of '{name}' (directly \
                     or indirectly) needs its own output"
                ));
            }
            Some(_) => return Ok(()),
            None => {}
        }

        let entry = self.entry(name)?;
        if !entry.has(part) {
            self.set_state(name, part, PartState::NotNeeded);
            return Ok(());
        }

        if self.should_generate(name, &entry)? {
            return self.generate_entry(name, &entry);
        }

        let path = self.part_path(name, part);
        let state = match read_optional(&path)? {
            // Secret files hold ciphertext, public files plaintext.
            Some(bytes) => match part {
                Part::Secret => PartState::Encrypted(bytes),
                Part::Public => PartState::PlainText(bytes),
            },
            None => PartState::Missing,
        };
        self.set_state(name, part, state);
        Ok(())
    }

    /// Whether resolving `name` runs its generator. Both parts always reach
    /// the same decision: it only depends on the entry, its mode, and the
    /// on-disk state, none of which change during a run.
    fn should_generate(&self, name: &str, entry: &RawSecretEntry) -> Result<bool, Report> {
        if !entry.has_generator {
            return Ok(false);
        }
        match self.mode(name) {
            EntryMode::ReadOnly => Ok(false),
            EntryMode::ForceGenerate => Ok(true),
            EntryMode::Generate => Ok(!self.complete_on_disk(name)?),
            EntryMode::GenerateIfMissing => {
                if self.complete_on_disk(name)? {
                    return Ok(false);
                }
                let (present, missing): (Vec<Part>, Vec<Part>) = [Part::Secret, Part::Public]
                    .into_iter()
                    .filter(|&part| entry.has(part))
                    .partition(|&part| self.part_path(name, part).exists());
                if let (Some(present), Some(missing)) = (present.first(), missing.first()) {
                    return Err(report!(
                        "Refusing to generate '{name}': {missing} is missing but \
                         {present} exists, and regenerating would overwrite it. \
                         Target it explicitly (agenix generate {name}) or use --force.",
                        missing = missing.file_name(name),
                        present = present.file_name(name),
                    ));
                }
                Ok(true)
            }
        }
    }

    /// Run the generator of `name` and store the result for both parts.
    fn generate_entry(&self, name: &str, entry: &RawSecretEntry) -> Result<(), Report> {
        self.set_state(name, Part::Secret, PartState::WorkInProgress);
        self.set_state(name, Part::Public, PartState::WorkInProgress);

        let result = call_generator(&self.rules_path, &self.dir, name, &self.names);
        let output = match result {
            Ok(output) => output,
            Err(e) => {
                // Reset so later resolves re-attempt and report the real
                // error instead of a bogus cycle.
                let mut parts = self.parts.borrow_mut();
                parts.remove(&(name.to_string(), Part::Secret));
                parts.remove(&(name.to_string(), Part::Public));
                return Err(e.context(format!("Failed to generate '{name}'")).into_dyn_any());
            }
        };

        for (part, produced, declaration) in [
            (Part::Secret, output.secret, "hasSecret"),
            (Part::Public, output.public, "hasPublic"),
        ] {
            let state = match (entry.has(part), produced) {
                (true, Some(value)) => PartState::NewlyGenerated(value.into_bytes()),
                (false, None) => PartState::NotNeeded,
                (needed, _) => {
                    let (did, expected) = if needed {
                        ("did not produce", "true")
                    } else {
                        ("produced", "false")
                    };
                    return Err(report!(
                        "The generator of '{name}' {did} a {declaration_part} \
                         value, but the entry has {declaration} = {expected}. \
                         Fix the declaration or the generator.",
                        declaration_part = match part {
                            Part::Secret => "secret",
                            Part::Public => "public",
                        },
                    ));
                }
            };
            self.set_state(name, part, state);
        }
        Ok(())
    }

    /// Decrypt a part's ciphertext and cache the plaintext.
    fn decrypt(&self, name: &str, part: Part, ciphertext: &[u8]) -> Result<Vec<u8>, Report> {
        let plaintext = crypto::decrypt(ciphertext, &self.identities, self.no_system_identities)?;
        self.set_state(name, part, PartState::PlainText(plaintext.clone()));
        Ok(plaintext)
    }

    /// Resolve one part all the way to plaintext bytes, decrypting on the
    /// way if necessary.
    fn get(&self, name: &str, part: Part) -> Result<Vec<u8>, Report> {
        self.resolve(name, part)?;
        let state = self
            .state(name, part)
            .expect("resolve always leaves a state");
        let file = part.file_name(name);

        match state {
            PartState::PlainText(bytes) | PartState::NewlyGenerated(bytes) => Ok(bytes),
            PartState::Encrypted(ciphertext) => {
                Ok(self.decrypt(name, part, &ciphertext).context(format!(
                    "Cannot decrypt {file} with the available identities. \
                     Provide a matching identity with --identity."
                ))?)
            }
            PartState::Missing => {
                let hint = if self.entry(name)?.has_generator {
                    format!("It can be created with: agenix generate {name}")
                } else {
                    format!("Create it with: agenix edit {name}")
                };
                Err(report!("{file} does not exist. {hint}"))
            }
            PartState::NotNeeded => Err(report!(
                "'{name}' does not have a {kind} part (has{declaration} = false)",
                kind = match part {
                    Part::Secret => "secret",
                    Part::Public => "public",
                },
                declaration = match part {
                    Part::Secret => "Secret",
                    Part::Public => "Public",
                },
            )),
            PartState::WorkInProgress => Err(report!(
                "Circular dependency: the generator of '{name}' (directly or \
                 indirectly) needs its own output"
            )),
        }
    }

    /// Status of both parts of an entry, without failing on missing or
    /// undecryptable files.
    fn status(&self, name: &str) -> Result<EntryStatus, Report> {
        Ok(EntryStatus {
            secret: self.part_status(name, Part::Secret)?,
            public: self.part_status(name, Part::Public)?,
        })
    }

    /// Status of one part; None if the entry declares it does not exist.
    fn part_status(&self, name: &str, part: Part) -> Result<Option<PartStatus>, Report> {
        if !self.entry(name)?.has(part) {
            return Ok(None);
        }
        self.resolve(name, part)?;
        let status = match self
            .state(name, part)
            .expect("resolve always leaves a state")
        {
            PartState::PlainText(_) | PartState::NewlyGenerated(_) => PartStatus::Available,
            PartState::Encrypted(ciphertext) => match self.decrypt(name, part, &ciphertext) {
                Ok(_) => PartStatus::Available,
                Err(_) => PartStatus::CannotDecrypt,
            },
            PartState::Missing => PartStatus::Missing,
            PartState::NotNeeded | PartState::WorkInProgress => {
                unreachable!("part is declared and no generator is running")
            }
        };
        Ok(Some(status))
    }

    /// Resolve every entry on the generation agenda.
    fn generate(&self) -> Result<(), Report> {
        for name in &self.agenda {
            for part in [Part::Secret, Part::Public] {
                self.resolve(name, part)
                    .context(format!("Failed to resolve '{name}'"))?;
            }
        }
        Ok(())
    }

    /// The recipient strings a secret is encrypted for: direct public keys
    /// verbatim, references resolved through the referenced entry's public
    /// part.
    fn recipients(&self, name: &str) -> Result<Vec<String>, Report> {
        self.entry(name)?
            .public_keys
            .iter()
            .map(|key| match key {
                PublicKeyString::Direct(key) => Ok(key.clone()),
                PublicKeyString::Reference(referenced) => {
                    if !self.names.iter().any(|n| n == referenced) {
                        return Err(report!(
                            "The publicKeys of '{name}' contain \"{referenced}\", \
                             which is neither a public key nor the name of \
                             another entry in secrets.nix"
                        ));
                    }
                    let bytes = self.get(referenced, Part::Public).context(format!(
                        "Failed to resolve the public key reference '{referenced}' \
                         in the publicKeys of '{name}'"
                    ))?;
                    Ok(String::from_utf8(bytes)
                        .map_err(|_| {
                            report!("The public part of '{referenced}' is not valid UTF-8")
                        })?
                        .trim()
                        .to_string())
                }
            })
            .collect()
    }

    /// Check one entry and report all problems at once.
    fn check(&self, name: &str) -> Result<(), Report> {
        let mut reports = ReportCollection::new();

        match self.entry(name) {
            Err(e) => reports.push(e.into_cloneable()),
            Ok(entry) => {
                if !entry.has_secret && !entry.has_public {
                    reports.push(
                        report!(
                            "'{name}' declares neither a secret nor a public part; \
                             it produces nothing"
                        )
                        .into_cloneable(),
                    );
                }
                for part in [Part::Secret, Part::Public] {
                    if entry.has(part) {
                        if let Err(e) = self.get(name, part) {
                            reports.push(e.into_cloneable());
                        }
                    } else if self.part_path(name, part).exists() {
                        reports.push(
                            report!(
                                "{file} exists on disk but '{name}' declares it does \
                                 not exist. Delete the file or fix the declaration.",
                                file = part.file_name(name),
                            )
                            .into_cloneable(),
                        );
                    }
                }
                if entry.has_secret {
                    match self.recipients(name) {
                        Err(e) => reports.push(e.into_cloneable()),
                        Ok(recipients) if recipients.is_empty() => reports.push(
                            report!(
                                "'{name}' has a secret part but no publicKeys to \
                                 encrypt it for"
                            )
                            .into_cloneable(),
                        ),
                        Ok(_) => {}
                    }
                }
            }
        }

        if reports.is_empty() {
            Ok(())
        } else {
            Err(reports.context(format!("Check failed for '{name}'")).into())
        }
    }

    /// Write everything that was generated this run to disk, transactionally:
    /// encrypt all secrets first, then write temp files, then rename them all
    /// into place. A failure at any step leaves the secrets directory
    /// untouched.
    fn flush(&self) -> Result<(), Report> {
        let generated: Vec<(String, Part, Vec<u8>)> = self
            .parts
            .borrow()
            .iter()
            .filter_map(|((name, part), state)| match state {
                PartState::NewlyGenerated(data) => Some((name.clone(), *part, data.clone())),
                _ => None,
            })
            .collect();

        // Encrypt everything before touching the disk.
        let mut files: Vec<(PathBuf, Vec<u8>)> = vec![];
        for (name, part, data) in generated {
            let bytes = match part {
                Part::Public => data,
                Part::Secret => {
                    let entry = self.entry(&name)?;
                    crypto::encrypt(&data, &self.recipients(&name)?, entry.armored)
                        .context(format!("Failed to encrypt '{name}'"))?
                }
            };
            files.push((self.part_path(&name, part), bytes));
        }

        // Stage temp files, then commit with renames.
        let mut staged: Vec<(PathBuf, &PathBuf)> = vec![];
        let result = files.iter().try_for_each(|(path, bytes)| -> Result<(), Report> {
            let file_name = path.file_name().expect("part paths have file names");
            let tmp = path.with_file_name(format!(".{}.agenix-tmp", file_name.display()));
            std::fs::write(&tmp, bytes)
                .context(format!("Failed to write {}", tmp.display()))?;
            staged.push((tmp, path));
            Ok(())
        });
        let result = result.and_then(|()| {
            staged.iter().try_for_each(|(tmp, path)| -> Result<(), Report> {
                std::fs::rename(tmp, path)
                    .context(format!("Failed to move {} into place", path.display()))?;
                Ok(())
            })
        });
        if result.is_err() {
            for (tmp, _) in &staged {
                let _ = std::fs::remove_file(tmp);
            }
        }
        result
    }
}

/// All entry names defined in the rules file.
fn load_names(rules_path: &Path) -> Result<Vec<String>, Report> {
    let rules_path_str = rules_path
        .to_str()
        .ok_or_else(|| report!("Path to secrets.nix is not valid UTF-8"))?;
    let nix_expr = format!(
        r#"let names = builtins.attrNames (import {rules_path_str});
        in builtins.deepSeq names names"#
    );
    let dir = rules_path.parent().unwrap_or_else(|| Path::new("."));
    let output = eval_nix_expression(&nix_expr, dir)
        .context(format!("Failed to read {rules_path_str}"))?;
    value_to_string_array(&output)
}

/// Read a file, mapping "not found" to None.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, Report> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(report!("Failed to read {}: {e}", path.display())),
    }
}

thread_local! {
    /// The engine of the current invocation. Thread-local because the
    /// getSecret/getPublic builtins re-enter the engine from inside Nix
    /// evaluations the engine itself started.
    static ENGINE: RefCell<Option<Rc<Engine>>> = const { RefCell::new(None) };
}

/// Initialize the engine for this invocation. Must be called before any
/// other engine function.
pub fn init(config: Config) -> Result<(), Report> {
    let engine = Engine::new(config)?;
    ENGINE.with(|slot| *slot.borrow_mut() = Some(Rc::new(engine)));
    Ok(())
}

fn engine() -> Result<Rc<Engine>, Report> {
    ENGINE
        .with(|slot| slot.borrow().clone())
        .ok_or_else(|| report!("Engine not initialized — call nix::init first"))
}

/// The plaintext of a secret, loading, decrypting, or generating it as the
/// configured operation allows.
pub fn get_secret(name: &str) -> Result<Vec<u8>, Report> {
    engine()?.get(name, Part::Secret)
}

/// The content of a public part, loading or generating it as the configured
/// operation allows.
pub fn get_public(name: &str) -> Result<Vec<u8>, Report> {
    engine()?.get(name, Part::Public)
}

/// All entry names, sorted.
pub fn list_names() -> Result<Vec<String>, Report> {
    Ok(engine()?.names.clone())
}

/// Resolve every entry the configured operation wants generated.
pub fn generate() -> Result<(), Report> {
    engine()?.generate()
}

/// Check one entry, reporting all problems at once.
pub fn check_entry(name: &str) -> Result<(), Report> {
    engine()?.check(name)
}

/// Status of an entry's parts, without failing on missing or undecryptable
/// files.
pub fn status(name: &str) -> Result<EntryStatus, Report> {
    engine()?.status(name)
}

/// Persist everything that was generated this run. Transactional: on error
/// the secrets directory is left untouched.
pub fn flush() -> Result<(), Report> {
    engine()?.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use tempfile::TempDir;

    /// A secrets directory with a secrets.nix and an age identity.
    /// `{PUB}` in the rules is replaced with the identity's public key.
    struct Fixture {
        dir: TempDir,
        identity_path: String,
        public_key: String,
    }

    impl Fixture {
        fn new(rules: &str) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let identity = age::x25519::Identity::generate();
            let public_key = identity.to_public().to_string();
            let identity_path = dir.path().join("identity.txt");
            std::fs::write(
                &identity_path,
                format!("{}\n", identity.to_string().expose_secret()),
            )
            .unwrap();

            std::fs::write(
                dir.path().join("secrets.nix"),
                rules.replace("{PUB}", &public_key),
            )
            .unwrap();
            Fixture {
                dir,
                identity_path: identity_path.to_str().unwrap().to_string(),
                public_key,
            }
        }

        fn init(&self, operation: Operation) -> Result<(), Report> {
            init(Config {
                rules_path: self.dir.path().join("secrets.nix"),
                identities: vec![self.identity_path.clone()],
                no_system_identities: true,
                operation,
            })
        }

        fn init_generate_all(&self) {
            self.init(Operation::Generate {
                targets: vec![],
                force: false,
                dependents: true,
            })
            .unwrap();
        }

        fn path(&self, file: &str) -> PathBuf {
            self.dir.path().join(file)
        }

        fn read(&self, file: &str) -> Vec<u8> {
            std::fs::read(self.path(file)).unwrap()
        }

        /// Decrypt a flushed .age file with the fixture identity.
        fn decrypt_file(&self, file: &str) -> Vec<u8> {
            crypto::decrypt(&self.read(file), &[self.identity_path.clone()], true).unwrap()
        }
    }

    fn error_text(report: Report) -> String {
        format!("{report:?}")
    }

    #[test]
    fn implicit_password_generation_and_flush() {
        let fx = Fixture::new(r#"{ "mypassword" = { publicKeys = [ "{PUB}" ]; }; }"#);
        fx.init_generate_all();
        generate().unwrap();

        let secret = get_secret("mypassword").unwrap();
        assert_eq!(secret.len(), 32);

        flush().unwrap();
        assert_eq!(fx.decrypt_file("mypassword.age"), secret);
        assert!(!fx.path("mypassword.pub").exists());
    }

    #[test]
    fn explicit_generator_with_declared_public() {
        let fx = Fixture::new(
            r#"{
              "token" = {
                publicKeys = [ "{PUB}" ];
                hasPublic = true;
                generator = _: { secret = "sec"; public = "pub"; };
              };
            }"#,
        );
        fx.init_generate_all();
        generate().unwrap();
        assert_eq!(get_public("token").unwrap(), b"pub");

        flush().unwrap();
        assert_eq!(fx.read("token.pub"), b"pub");
        assert_eq!(fx.decrypt_file("token.age"), b"sec");
    }

    #[test]
    fn generator_output_must_match_declared_shape() {
        // hasPublic defaults to false, but the generator produces a public.
        let fx = Fixture::new(
            r#"{
              "token" = {
                publicKeys = [ "{PUB}" ];
                generator = _: { secret = "s"; public = "p"; };
              };
            }"#,
        );
        fx.init_generate_all();
        let error = error_text(generate().unwrap_err());
        assert!(error.contains("hasPublic"), "unhelpful error: {error}");
    }

    #[test]
    fn lazy_dependency_through_get_secret() {
        let fx = Fixture::new(
            r#"{
              "basepassword" = { publicKeys = [ "{PUB}" ]; };
              "derived" = {
                publicKeys = [ "{PUB}" ];
                generator = { secrets, ... }: { secret = "derived-" + secrets.basepassword; };
              };
            }"#,
        );
        fx.init_generate_all();
        generate().unwrap();

        let base = get_secret("basepassword").unwrap();
        let mut expected = b"derived-".to_vec();
        expected.extend_from_slice(&base);
        assert_eq!(get_secret("derived").unwrap(), expected);

        flush().unwrap();
        assert_eq!(fx.decrypt_file("derived.age"), expected);
    }

    #[test]
    fn cycle_is_detected() {
        let fx = Fixture::new(
            r#"{
              "a" = {
                publicKeys = [ "{PUB}" ];
                generator = { secrets, ... }: { secret = secrets.a; };
              };
            }"#,
        );
        fx.init_generate_all();
        let error = error_text(generate().unwrap_err());
        assert!(error.contains("Circular"), "unhelpful error: {error}");
    }

    #[test]
    fn read_only_decrypts_existing_secret() {
        let fx = Fixture::new(r#"{ "existing" = { publicKeys = [ "{PUB}" ]; }; }"#);
        let ciphertext = crypto::encrypt(b"hello", &[fx.public_key.clone()], false).unwrap();
        std::fs::write(fx.path("existing.age"), ciphertext).unwrap();

        fx.init(Operation::Read).unwrap();
        assert_eq!(get_secret("existing").unwrap(), b"hello");
    }

    #[test]
    fn missing_secret_has_helpful_error() {
        let fx = Fixture::new(r#"{ "absent" = { publicKeys = [ "{PUB}" ]; }; }"#);
        fx.init(Operation::Read).unwrap();
        let error = error_text(get_secret("absent").unwrap_err());
        assert!(error.contains("does not exist"), "unhelpful error: {error}");
        assert!(error.contains("agenix edit"), "unhelpful error: {error}");
    }

    #[test]
    fn undecryptable_secret_has_helpful_error() {
        let fx = Fixture::new(r#"{ "sealed" = { publicKeys = [ "{PUB}" ]; }; }"#);
        let other = age::x25519::Identity::generate();
        let ciphertext =
            crypto::encrypt(b"x", &[other.to_public().to_string()], false).unwrap();
        std::fs::write(fx.path("sealed.age"), ciphertext).unwrap();

        fx.init(Operation::Read).unwrap();
        let error = error_text(get_secret("sealed").unwrap_err());
        assert!(error.contains("Cannot decrypt"), "unhelpful error: {error}");
    }

    #[test]
    fn refuses_to_complete_partial_pair_untargeted() {
        // Implicit ssh keypair entry with only the .age half on disk:
        // regenerating would silently replace the existing secret.
        let fx = Fixture::new(r#"{ "host_ed25519" = { publicKeys = [ "{PUB}" ]; }; }"#);
        std::fs::write(fx.path("host_ed25519.age"), b"old").unwrap();

        fx.init_generate_all();
        let error = error_text(generate().unwrap_err());
        assert!(error.contains("Refusing"), "unhelpful error: {error}");
        assert!(error.contains("--force"), "unhelpful error: {error}");
        assert_eq!(fx.read("host_ed25519.age"), b"old");
    }

    #[test]
    fn targeting_a_partial_pair_regenerates_it() {
        let fx = Fixture::new(r#"{ "host_ed25519" = { publicKeys = [ "{PUB}" ]; }; }"#);
        std::fs::write(fx.path("host_ed25519.age"), b"old").unwrap();

        fx.init(Operation::Generate {
            targets: vec!["host_ed25519".into()],
            force: false,
            dependents: true,
        })
        .unwrap();
        generate().unwrap();
        flush().unwrap();

        assert_ne!(fx.read("host_ed25519.age"), b"old");
        let public = fx.read("host_ed25519.pub");
        assert!(public.starts_with(b"ssh-ed25519 "));
        assert!(fx.decrypt_file("host_ed25519.age").starts_with(b"-----BEGIN"));
    }

    #[test]
    fn dry_run_resolves_without_writing() {
        let fx = Fixture::new(r#"{ "mypassword" = { publicKeys = [ "{PUB}" ]; }; }"#);
        fx.init_generate_all();
        generate().unwrap();
        assert_eq!(get_secret("mypassword").unwrap().len(), 32);
        // No flush: nothing may hit the disk.
        assert!(!fx.path("mypassword.age").exists());
    }

    #[test]
    fn public_key_reference_encrypts_for_referenced_entry() {
        let fx = Fixture::new(
            r#"{
              "ca_x25519" = { publicKeys = [ "{PUB}" ]; };
              "leaf" = { publicKeys = [ "ca_x25519" ]; generator = _: "leafsecret"; };
            }"#,
        );
        fx.init_generate_all();
        generate().unwrap();
        flush().unwrap();

        // leaf.age must be decryptable with the generated ca identity.
        let ca_identity = fx.decrypt_file("ca_x25519.age");
        let ca_identity_path = fx.path("ca-identity.txt");
        std::fs::write(&ca_identity_path, ca_identity).unwrap();
        let leaf = crypto::decrypt(
            &fx.read("leaf.age"),
            &[ca_identity_path.to_str().unwrap().to_string()],
            true,
        )
        .unwrap();
        assert_eq!(leaf, b"leafsecret");
    }

    #[test]
    fn check_reports_all_problems_at_once() {
        let fx = Fixture::new(
            r#"{
              "nofile" = { publicKeys = [ "{PUB}" ]; };
              "nokeys" = { publicKeys = [ ]; };
            }"#,
        );
        fx.init(Operation::Read).unwrap();

        let error = error_text(check_entry("nofile").unwrap_err());
        assert!(error.contains("does not exist"), "unhelpful error: {error}");

        let error = error_text(check_entry("nokeys").unwrap_err());
        assert!(error.contains("publicKeys"), "unhelpful error: {error}");
        assert!(error.contains("does not exist"), "should also report the missing file: {error}");
    }

    #[test]
    fn check_reports_files_contradicting_declarations() {
        let fx = Fixture::new(
            r#"{ "stray" = { publicKeys = [ "{PUB}" ]; hasSecret = false; }; }"#,
        );
        // hasSecret = false implies a public-only entry; provide the .pub but
        // also a contradicting .age file.
        std::fs::write(fx.path("stray.pub"), b"some public data").unwrap();
        std::fs::write(fx.path("stray.age"), b"should not be here").unwrap();

        fx.init(Operation::Read).unwrap();
        let error = error_text(check_entry("stray").unwrap_err());
        assert!(error.contains("stray.age"), "unhelpful error: {error}");
        assert!(error.contains("declares"), "unhelpful error: {error}");
    }

    #[test]
    fn status_distinguishes_available_missing_and_undecryptable() {
        let fx = Fixture::new(
            r#"{
              "good" = { publicKeys = [ "{PUB}" ]; };
              "absent" = { publicKeys = [ "{PUB}" ]; };
              "sealed" = { publicKeys = [ "{PUB}" ]; };
              "pubonly" = { hasSecret = false; };
              "pubmissing" = { hasSecret = false; };
            }"#,
        );
        let good = crypto::encrypt(b"x", &[fx.public_key.clone()], false).unwrap();
        std::fs::write(fx.path("good.age"), good).unwrap();
        let other = age::x25519::Identity::generate();
        let sealed = crypto::encrypt(b"x", &[other.to_public().to_string()], false).unwrap();
        std::fs::write(fx.path("sealed.age"), sealed).unwrap();
        std::fs::write(fx.path("pubonly.pub"), b"public data").unwrap();

        fx.init(Operation::Read).unwrap();
        use PartStatus::{Available, CannotDecrypt, Missing};
        let of = |name| status(name).unwrap();
        assert_eq!(of("good"), EntryStatus { secret: Some(Available), public: None });
        assert_eq!(of("absent"), EntryStatus { secret: Some(Missing), public: None });
        assert_eq!(of("sealed"), EntryStatus { secret: Some(CannotDecrypt), public: None });
        assert_eq!(of("pubonly"), EntryStatus { secret: None, public: Some(Available) });
        assert_eq!(of("pubmissing"), EntryStatus { secret: None, public: Some(Missing) });
    }

    #[test]
    fn invalid_names_are_rejected_at_init() {
        let fx = Fixture::new(r#"{ "foo.age" = { publicKeys = [ "{PUB}" ]; }; }"#);
        let error = error_text(fx.init(Operation::Read).unwrap_err());
        assert!(error.contains(".age"), "unhelpful error: {error}");
        assert!(error.contains("foo"), "unhelpful error: {error}");
    }

    #[test]
    fn unknown_generate_target_is_rejected() {
        let fx = Fixture::new(r#"{ "real" = { publicKeys = [ "{PUB}" ]; }; }"#);
        let error = error_text(
            fx.init(Operation::Generate {
                targets: vec!["nope".into()],
                force: true,
                dependents: true,
            })
            .unwrap_err(),
        );
        assert!(error.contains("nope"), "unhelpful error: {error}");
    }

    #[test]
    fn force_regenerates_existing_secrets() {
        let fx = Fixture::new(r#"{ "mypassword" = { publicKeys = [ "{PUB}" ]; }; }"#);
        fx.init_generate_all();
        generate().unwrap();
        flush().unwrap();
        let first = fx.read("mypassword.age");

        fx.init(Operation::Generate {
            targets: vec![],
            force: true,
            dependents: true,
        })
        .unwrap();
        generate().unwrap();
        flush().unwrap();
        assert_ne!(fx.read("mypassword.age"), first);
    }

    #[test]
    fn regenerating_a_target_cascades_to_declared_dependents() {
        let fx = Fixture::new(
            r#"{
              "mypassword" = { publicKeys = [ "{PUB}" ]; };
              "dependent" = {
                publicKeys = [ "{PUB}" ];
                dependencies = [ "mypassword" ];
                generator = { secrets, ... }: { secret = "dep-" + secrets.mypassword; };
              };
              "bystander" = { publicKeys = [ "{PUB}" ]; generator = _: builtins.randomString 8; };
            }"#,
        );
        fx.init_generate_all();
        generate().unwrap();
        flush().unwrap();
        let old_dependent = fx.read("dependent.age");
        let old_bystander = fx.read("bystander.age");

        // Force-regenerate only the password: the declared dependent must
        // follow, the bystander must not.
        fx.init(Operation::Generate {
            targets: vec!["mypassword".into()],
            force: true,
            dependents: true,
        })
        .unwrap();
        generate().unwrap();
        flush().unwrap();

        assert_ne!(fx.read("dependent.age"), old_dependent);
        assert_eq!(fx.read("bystander.age"), old_bystander);

        // The regenerated dependent must be derived from the new password.
        fx.init(Operation::Read).unwrap();
        let mut expected = b"dep-".to_vec();
        expected.extend_from_slice(&get_secret("mypassword").unwrap());
        assert_eq!(get_secret("dependent").unwrap(), expected);
    }

    #[test]
    fn no_dependencies_disables_the_cascade() {
        let fx = Fixture::new(
            r#"{
              "mypassword" = { publicKeys = [ "{PUB}" ]; };
              "dependent" = {
                publicKeys = [ "{PUB}" ];
                dependencies = [ "mypassword" ];
                generator = { secrets, ... }: { secret = "dep-" + secrets.mypassword; };
              };
            }"#,
        );
        fx.init_generate_all();
        generate().unwrap();
        flush().unwrap();
        let old_dependent = fx.read("dependent.age");

        fx.init(Operation::Generate {
            targets: vec!["mypassword".into()],
            force: true,
            dependents: false,
        })
        .unwrap();
        generate().unwrap();
        flush().unwrap();
        assert_eq!(fx.read("dependent.age"), old_dependent);
    }
}
