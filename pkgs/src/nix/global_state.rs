//! Nix expression evaluation utilities.
//!
//! Provides functions for evaluating Nix expressions and converting Nix values
//! to Rust types.

use crate::nix::generator::GeneratorInput;
use crate::nix::generator::call_generator;
use crate::nix::get_all_files;
use crate::nix::public_key::PublicKeyString;
use crate::nix::raw_secret_entry::RawSecretEntry;
use crate::nix::raw_secret_entry::get_raw_secret_entry;
use rootcause::Report;
use rootcause::prelude::ResultExt;
use rootcause::report;
use rootcause::report_collection::ReportCollection;
use std::collections::HashMap;
use std::env::current_dir;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub enum SecretType {
    /// Loaded from file but was not yet encrypted
    Encrypted(Vec<u8>),
    /// Loaded from file and decrypted
    PlainText(Vec<u8>),
    /// The value was newly generated during this run and is not yet persisted
    NewlyGenerated(Vec<u8>),
    /// The secret is currently being generated
    WorkInProgress,
    /// The secret is missing and cannot be generated
    Missing,
    /// Not expected to exist
    NotNeeded,
    /// State is not known yet
    Unknown,
}

#[derive(Clone, Debug)]
pub struct SecretThing {
    secret: SecretType,
    public: SecretType,
}
impl Default for SecretType {
    fn default() -> Self {
        SecretType::Unknown
    }
}
impl Default for SecretThing {
    fn default() -> Self {
        SecretThing {
            secret: SecretType::Unknown,
            public: SecretType::Unknown,
        }
    }
}
impl SecretThing {
    pub fn new() -> Self {
        Default::default()
    }
}

enum EntryMode {
    // Don't write the files at all. This is the only mode that allows having incomplete secret/public pairs.
    ReadOnly,
    // Generate if secret and public are missing
    GenerateIfMissing,
    // Generate if not complete.
    Generate,
    // Always generate and overwrite existing files.
    ForceGenerate,
}

// Horrible global state to manage secrets during basically everything
// Used to track what secrets exist, are being generated, etc.
// Toxic mixture of configuration, logic, and cache
pub struct GlobalState {
    secret_data: Mutex<std::collections::HashMap<String, SecretThing>>,
    // The names of entries that we are allowed to generate
    entry_modes: HashMap<String, EntryMode>,
    // Path to the secrets.nix file as it was supplied on the cli
    secrets_nix_path: PathBuf,
    // Working directory for the secrets.nix path
    current_dir: PathBuf,
    // Absolute path to the secrets.nix directory
    secrets_nix_dir: PathBuf,
    // The entries known so far
    entries: Mutex<std::collections::HashMap<String, RawSecretEntry>>,
    // All known secret names
    names: Vec<String>,
}

impl GlobalState {
    fn new(generate: bool, overwrite: bool, secrets_nix_path: &Path) -> Result<Self, Report> {
        let all_names = get_all_files(secrets_nix_path)
            .context("Failed to get a list of all entries in secrets.nix")?;
        let mut entry_modes = HashMap::new();
        for name in &all_names {
            let mode = if !generate {
                EntryMode::ReadOnly
            } else if overwrite {
                EntryMode::ForceGenerate
            } else {
                EntryMode::GenerateIfMissing
            };
            entry_modes.insert(name.to_string(), mode);
        }
        Ok(GlobalState {
            secret_data: Mutex::new(std::collections::HashMap::new()),
            entry_modes: HashMap::new(),
            secrets_nix_path: secrets_nix_path.to_path_buf(),
            current_dir: current_dir()?,
            secrets_nix_dir: std::path::absolute(secrets_nix_path)
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf(),
            entries: Mutex::new(std::collections::HashMap::new()),
            names: all_names,
        })
        // TODO: Assert existance of the secrets.nix and secrets_nix_dir
    }
    /// Try hard to get the secret thing and generate if necessary
    ///
    /// For generating the secret and public are set to WorkInProgress and
    /// then the generator function is called which
    ///
    /// For now it's unclear whether this is encrypted or decrypted.
    fn get_secret(&self, name: &str) -> Result<SecretType, Report> {
        if !self.names.contains(&name.to_string()) {
            return Err(report!("Secret {name} not found in secrets.nix"));
        }

        let mut secret_data = self.secret_data.lock().unwrap();
        let secret = match secret_data.get_mut(&name.to_string()) {
            Some(secret) => secret,
            None => {
                secret_data.insert(name.to_string(), SecretThing::new());
                secret_data.get_mut(&name.to_string()).unwrap()
            }
        };

        let secret = match &secret.secret {
            SecretType::NewlyGenerated(_) | SecretType::PlainText(_) | SecretType::Encrypted(_) => {
                secret.secret.clone()
            }
            SecretType::WorkInProgress => {
                return Err(report!("Circular dependency detected for secret {name}"));
            }
            SecretType::Missing => {
                return Err(report!("Secret {name} is missing and cannot be generated"));
            }
            SecretType::NotNeeded => {
                return Err(report!("Secret {name} is not needed"));
            }
            SecretType::Unknown => {
                drop(secret_data);
                self.resolve_secret(name)?;

                // Assert that the secret is actually resolved
                let secret_data = self.secret_data.lock().unwrap();
                let secret = secret_data.get(&name.to_string()).unwrap();
                assert!(!matches!(secret.secret, SecretType::Unknown));

                self.get_secret(name)?
            }
        };

        // TODO: Move these checks somewhere else
        let entry = self.entries.lock().unwrap();
        let Some(entry) = entry.get(name) else {
            return Err(report!(
                "Tried to get the secret for {name}, but it does not have an entry in secrets.nix"
            ));
        };
        if Some(false) == entry.has_secret {
            return Err(report!(
                "Secret {name} is marked as not having a secret part"
            ));
        };

        Ok(secret)
    }
    /// Like get_secret but for public part
    fn get_public(&self, name: &str) -> Result<SecretType, Report> {
        let mut secret_data = self.secret_data.lock().unwrap();
        let Some(secret) = secret_data.get_mut(&name.to_string()) else {
            panic!("Secret {name} not found");
        };

        let public = match &secret.public {
            SecretType::NewlyGenerated(_) | SecretType::PlainText(_) | SecretType::Encrypted(_) => {
                secret.public.clone()
            }
            SecretType::WorkInProgress => {
                return Err(report!(
                    "Circular dependency detected for public part of {name}"
                ));
            }
            SecretType::Missing => {
                return Err(report!(
                    "Public part of {name} is missing and cannot be generated"
                ));
            }
            SecretType::NotNeeded => {
                return Err(report!("Public part of {name} is not needed"));
            }
            SecretType::Unknown => {
                drop(secret_data);
                self.resolve_secret(name).unwrap();

                // Assert that the public is actually resolved
                let secret_data = self.secret_data.lock().unwrap();
                let secret = secret_data.get(&name.to_string()).unwrap();
                assert!(!matches!(secret.public, SecretType::Unknown));

                self.get_public(name)?
            }
        };

        // TODO: Move these checks somewhere else
        let entry = self.entries.lock().unwrap();
        let Some(entry) = entry.get(name) else {
            return Err(report!(
                "Tried to get the secret for {name}, but it does not have an entry in secrets.nix"
            ));
        };
        if Some(false) == entry.has_public {
            return Err(report!(
                "Secret {name} is marked as not having a secret part"
            ));
        };

        Ok(public)
    }

    /// Resolve the entire entry as far as possible
    /// Returns an error if something goes wrong
    fn resolve_entry(&self, name: &str) -> Result<(), Report> {
        self.resolve_secret(name)?;
        self.resolve_public(name)?;
        Ok(())
    }

    /// Generate, load, or retrieve the secret thing as needed.
    /// The goal is to resolve it as much as possible.
    ///
    fn resolve_secret(&self, name: &str) -> Result<(), Report> {
        if !self.names.contains(&name.to_string()) {
            return Err(report!("Entry {name} not found in secrets.nix"));
        }

        let mut secret_data = self.secret_data.lock().unwrap();
        let Some(secret) = secret_data.get_mut(&name.to_string()) else {
            return Err(report!("Secret {name} not found at all"));
        };

        match &secret.secret {
            SecretType::Unknown => (),
            secret => {
                return Ok(());
            }
        }

        // Load the secret entry and check if we need to have it at all
        let entry = self.load_entry(name)?;

        let not_needed = entry.has_secret == Some(false);
        let can_generate = self.can_generate(name);
        let can_overwrite = self.can_overwrite(name);
        let always_generate = self.always_generate(name);

        // // Try to load from disk

        if !can_generate {
            if not_needed {
                secret.secret = SecretType::NotNeeded;
                return Ok(());
            }

            let file = self.read_secret_file(name)?;
            if let Some(content) = file {
                // File exists, load it
                secret.secret = SecretType::Encrypted(content);
                return Ok(());
            }
            // Cannot generate and file does not exist
            return Err(report!("Secret {name} is missing."));
        }

        if always_generate {
            drop(secret_data);
            self.generate_entry(name)?;
            return Ok(());
        }

        match &secret.public {
            SecretType::Unknown => {
                secret.secret = if not_needed {
                    SecretType::NotNeeded
                } else {
                    let file = self.read_secret_file(name)?;
                    if let Some(content) = file {
                        // File exists, load it
                        SecretType::Encrypted(content)
                    } else {
                        SecretType::Missing
                    }
                };

                // resolve_public will call into generate.
                drop(secret_data);
                return self.resolve_public(name);
            }
            SecretType::NotNeeded => {
                if not_needed {
                    secret.secret = SecretType::NotNeeded;
                    // Both not needed
                    return Ok(());
                }
                // generate if there is no file for self
                let file = self.read_secret_file(name)?;
                if let Some(content) = file {
                    secret.secret = SecretType::Encrypted(content);
                    return Ok(());
                }

                drop(secret_data);
                self.generate_entry(name)?;
                return Ok(());
            }
            SecretType::Missing => {
                let file = self.read_secret_file(name)?;
                if file.is_some() && !can_overwrite {
                    return Err(report!(
                        "Secret {name} exists on disk but the entry is marked as missing and cannot be overwritten"
                    ));
                }

                drop(secret_data);
                self.generate_entry(name)?;
                return Ok(());
            }
            SecretType::PlainText(_) | SecretType::Encrypted(_) => {
                if not_needed {
                    secret.secret = SecretType::NotNeeded;
                    return Ok(());
                }

                let file = self.read_secret_file(name)?;
                if let Some(content) = file {
                    // File exists, load it
                    SecretType::Encrypted(content);
                    return Ok(());
                }
                if !can_overwrite {
                    return Err(report!(
                        "Public {name} exists on disk but the entry is marked as missing and cannot be overwritten"
                    ));
                }
                drop(secret_data);
                self.generate_entry(name)?;
                return Ok(());
            }
            SecretType::NewlyGenerated(items) => {
                // Already generated, nothing to do
                return Ok(());
            }
            SecretType::WorkInProgress => {
                return Err(report!("Circular dependency detected for secret {name}"));
            }
        }
        // self.resolve_public();

        // If not overwriting, we need to check the public before generating
    }

    /// Generate, load, or retrieve the secret thing as needed.
    /// The goal is to resolve it as much as possible.
    ///
    fn resolve_public(&self, name: &str) -> Result<(), Report> {
        if !self.names.contains(&name.to_string()) {
            return Err(report!("Entry {name} not found in secrets.nix"));
        }

        let mut secret_data = self.secret_data.lock().unwrap();
        let Some(secret) = secret_data.get_mut(&name.to_string()) else {
            return Err(report!("Secret {name} not found at all"));
        };

        match &secret.public {
            SecretType::Unknown => (),
            secret => {
                return Ok(());
            }
        }

        // Load the secret entry and check if we need to have it at all
        let entry = self.load_entry(name)?;

        let not_needed = entry.has_public == Some(false);
        let can_generate = self.can_generate(name);
        let can_overwrite = self.can_overwrite(name);
        let always_generate = self.always_generate(name);

        // // Try to load from disk

        if !can_generate {
            if not_needed {
                secret.public = SecretType::NotNeeded;
                return Ok(());
            }

            let file = self.read_secret_file(name)?;
            if let Some(content) = file {
                // File exists, load it
                secret.public = SecretType::PlainText(content);
                return Ok(());
            }
            // Cannot generate and file does not exist
            return Err(report!("Public {name} is missing."));
        }

        if always_generate {
            drop(secret_data);
            self.generate_entry(name)?;
            return Ok(());
        }

        match &secret.secret {
            SecretType::Unknown => {
                secret.public = if not_needed {
                    SecretType::NotNeeded
                } else {
                    let file = self.read_secret_file(name)?;
                    if let Some(content) = file {
                        // File exists, load it
                        SecretType::PlainText(content)
                    } else {
                        SecretType::Missing
                    }
                };

                // resolve_public will call into generate.
                drop(secret_data);
                return self.resolve_secret(name);
            }
            SecretType::NotNeeded => {
                if not_needed {
                    secret.public = SecretType::NotNeeded;
                    // Both not needed
                    return Ok(());
                }
                // generate if there is no file for self
                let file = self.read_secret_file(name)?;
                if let Some(content) = file {
                    secret.public = SecretType::Encrypted(content);
                    return Ok(());
                }

                drop(secret_data);
                self.generate_entry(name)?;
                return Ok(());
            }
            SecretType::Missing => {
                let file = self.read_secret_file(name)?;
                if file.is_some() && !can_overwrite {
                    return Err(report!(
                        "Public {name} exists on disk but the matching secret is missing but we cant generate it because that might overwrite the public"
                    ));
                }

                drop(secret_data);
                self.generate_entry(name)?;
                return Ok(());
            }
            SecretType::PlainText(_) | SecretType::Encrypted(_) => {
                if not_needed {
                    secret.public = SecretType::NotNeeded;
                    return Ok(());
                }

                let file = self.read_secret_file(name)?;
                if let Some(content) = file {
                    // File exists, load it
                    SecretType::Encrypted(content);
                    return Ok(());
                }
                if !can_overwrite {
                    return Err(report!(
                        "Public {name} exists on disk but the entry is marked as missing and cannot be overwritten"
                    ));
                }
                drop(secret_data);
                self.generate_entry(name)?;
                return Ok(());
            }
            SecretType::NewlyGenerated(_) => {
                // Already generated, nothing to do
                return Ok(());
            }
            SecretType::WorkInProgress => {
                return Err(report!("Circular dependency detected for secret {name}"));
            }
        }
        // self.resolve_public();

        // If not overwriting, we need to check the public before generating
    }

    /// Will be called by resolve_secret and resolve_public if they can't find the value and want to generate it
    /// This will check
    fn maybe_generate(&self, name: &str) -> Result<(), Report> {
        let secret_data = self.secret_data.lock().unwrap();
        let Some(secret) = secret_data.get(&name.to_string()) else {
            return Err(report!("Secret {name} not found at all"));
        };
        match (&secret.secret, &secret.public) {
            (
                SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
                SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
            ) => {
                // Already generated
                return Ok(());
            }
            _ => {
                // Continue
                ()
            }
        };
        drop(secret_data);

        if !self.can_generate(name) {
            return Ok(());
        }

        self.generate_entry(name)
    }

    /// Generate the entry.
    /// We assume that both resolve_secret and resolve_public have been called before?
    fn generate_entry(&self, name: &str) -> Result<(), Report> {
        // Mark as work in progress to avoid cycles

        let mut secret_data = self.secret_data.lock().unwrap();
        let Some(secret) = secret_data.get_mut(&name.to_string()) else {
            return Err(report!("Secret {name} not found at all"));
        };
        match (&secret.secret, &secret.public) {
            (SecretType::WorkInProgress, _) | (_, SecretType::WorkInProgress) => {
                return Err(report!("Circular dependency detected for secret {name}"));
            }
            (
                SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
                SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
            ) => {
                // Already generated or nothing needed
                return Ok(());
            }
            (
                SecretType::NotNeeded | SecretType::Unknown,
                SecretType::NotNeeded | SecretType::Unknown,
            ) => {
                // Continue
                ()
            }
            _ => {
                return Err(report!(
                    "Secret {name} is already partially generated or loaded"
                ));
            }
        };

        secret.secret = match &secret.secret {
            SecretType::Unknown => SecretType::WorkInProgress,
            SecretType::NotNeeded => SecretType::NotNeeded,
            _ => panic!("Unexpected state"),
        };
        secret.public = match &secret.public {
            SecretType::Unknown => SecretType::WorkInProgress,
            SecretType::NotNeeded => SecretType::NotNeeded,
            _ => panic!("Unexpected state"),
        };
        drop(secret_data);

        let result = call_generator(
            &self.secrets_nix_path,
            &self.current_dir,
            name,
            GeneratorInput {
                known_entries: self.names.clone(),
            },
        )?;

        let mut secret_data = self.secret_data.lock().unwrap();
        let secret_entry = self.load_entry(name)?;
        let Some(secret) = secret_data.get_mut(&name.to_string()) else {
            return Err(report!("Secret {name} not found at all"));
        };
        secret.secret = match (&result.secret, secret_entry.has_secret) {
            (Some(s), Some(true) | None) => SecretType::NewlyGenerated(s.clone().into_bytes()),
            (None, Some(false) | None) => SecretType::NotNeeded, // Newly fig
            (Some(_), Some(false)) => {
                // This is ok, we explicitly don't want to save it even though generator returned it
                SecretType::NotNeeded
            }
            (None, Some(true)) => {
                return Err(report!(
                    "Generator for {name} did not return a secret but the entry has hasSecret=true"
                ));
            }
        };
        secret.public = match (&result.public, secret_entry.has_public) {
            (Some(p), Some(true) | None) => SecretType::NewlyGenerated(p.clone().into_bytes()),
            (None, Some(false) | None) => SecretType::NotNeeded,
            (Some(_), Some(false)) => {
                // This is ok, we explicitly don't want to save it even though generator returned it
                SecretType::NotNeeded
            }
            (None, Some(true)) => {
                return Err(report!(
                    "Generator for {name} did not return a public but the entry has hasPublic=true"
                ));
            }
        };
        Ok(())
    }

    // Call the generator function

    fn can_generate(&self, name: &str) -> bool {
        self.entry_modes.get(name).map_or(false, |mode| {
            matches!(
                mode,
                EntryMode::GenerateIfMissing | EntryMode::Generate | EntryMode::ForceGenerate
            )
        })
    }
    fn can_overwrite(&self, name: &str) -> bool {
        self.entry_modes.get(name).map_or(false, |mode| {
            matches!(mode, EntryMode::Generate | EntryMode::ForceGenerate)
        })
    }
    fn always_generate(&self, name: &str) -> bool {
        self.entry_modes
            .get(name)
            .map_or(false, |mode| matches!(mode, EntryMode::ForceGenerate))
    }
    // pub fn always_generate(&self, name: &str) -> bool {
    //     self.entry_modes
    //         .get(name)
    //         .map_or(false, |mode| matches!(mode, EntryMode::ForceGenerate))
    // }

    /// Load the raw secrets.nix entry for the given name
    fn load_entry(&self, name: &str) -> Result<RawSecretEntry, Report> {
        if !self.names.contains(&name.to_string()) {
            return Err(report!("Entry {name} not found in secrets.nix"));
        }

        if let Some(entry) = self.entries.lock().unwrap().get(name) {
            return Ok(entry.clone());
        }

        let entry = get_raw_secret_entry(&self.secrets_nix_path, name)
            .context(format!("Failed to load secret entry for {name}"))?;
        let mut entries = self.entries.lock().unwrap();
        entries.insert(name.to_string(), entry.clone());
        Ok(entry)
    }

    // /// Generate new values for the secret. Does not touch the existing state
    // ///
    // pub fn generate_secret(&self, name: &str) -> Result<SecretThing, Report> {
    //     call_generator(name)
    // }

    /// Get the full path to the secret file (.age)
    fn secret_file_path(&self, name: &str) -> PathBuf {
        self.secrets_nix_dir.join(format!("{}.age", &name))
    }
    fn read_secret_file(&self, name: &str) -> Result<Option<Vec<u8>>, Report> {
        let path = self.secret_file_path(name);
        if !path.exists() {
            return Ok(None);
        }

        match std::fs::read(&path) {
            Ok(c) => Ok(Some(c)),
            Err(e) => Err({
                let err = match e.kind() {
                        std::io::ErrorKind::NotFound => {
                            return Ok(None);
                        }
                        std::io::ErrorKind::PermissionDenied => {
                             report!("Permission denied to read the secret file but it is expected to be accessible. Check file permissions.").into_dyn_any()
                        }
                        _ => {
                               report!("{}", e.to_string())
                        },
                      };
                err
                    .context("Secret file is expected to exist and be accesible. Set hasSecret=false to change this behaviour").into_dyn_any()
            }),
        }
    }

    /// Get the full path to the public file (.pub)
    fn public_file_path(&self, name: &str) -> PathBuf {
        self.secrets_nix_dir.join(format!("{}.pub", &name))
    }
    fn read_public_file(&self, name: &str) -> Result<Option<Vec<u8>>, Report> {
        let path = self.public_file_path(name);
        match std::fs::read(&path) {
            Ok(c) => Ok(Some(c)),
            Err(e) => Err({
                let err = match e.kind() {
                        std::io::ErrorKind::NotFound => {
                            return Ok(None);
                        }
                        std::io::ErrorKind::PermissionDenied => {
                             report!("Permission denied to read the secret file but it is expected to be accessible. Check file permissions.").into_dyn_any()
                        }
                        _ => {
                               report!("{}", e.to_string())
                        },
                      };
                err
                    .context("Secret file is expected to exist and be accesible. Set hasSecret=false to change this behaviour").into_dyn_any()
            }),
        }
    }

    fn check_entry(&self, name: &str) -> Result<(), Report> {
        // Proactively check if there is anything wrong with this secret's configuration
        let mut reports = ReportCollection::new();

        match self.resolve_secret(name) {
            Err(e) => {
                reports.push(e.into_cloneable());
            }
            Ok(_) => {}
        }
        match self.resolve_public(name) {
            Err(e) => {
                reports.push(e.into_cloneable());
            }
            Ok(_) => {}
        }

        let entry = self.load_entry(name);
        match entry {
            Err(e) => {
                reports.push(e.into_cloneable());
            }
            Ok(entry) => {
                // Validate that at least one output is expected
                if entry.has_secret == Some(false) && entry.has_public == Some(false) {
                    let error = report!("The secret is set to neither have a secret file nor a public file. Set either hasSecret=true or hasPublic=true.").into_cloneable();
                    reports.push(error);
                }

                if entry.has_secret == None && self.secret_file_path(name).exists() {
                    let error = report!("A secret file exists but hasSecret is not set to true. Set hasSecret=true or delete the file").into_cloneable();
                    reports.push(error);
                }
                if entry.has_public == None && self.public_file_path(name).exists() {
                    let error = report!("A public file exists but hasPublic is not set to true. Set hasPublic=true or delete the file").into_cloneable();
                    reports.push(error);
                }
                match self.get_public_keys(name) {
                    Err(e) => {
                        reports.push(e.into_cloneable());
                    }
                    Ok(keys) => {
                        if keys.is_empty() && entry.has_secret == Some(true) {
                            let error = report!("There are no public keys specified for {name} but hasSecret is set to true").into_cloneable();
                            reports.push(error);
                        }
                    }
                };
            }
        }

        if reports.is_empty() {
            Ok(())
        } else {
            Err(reports.context(format!("Check failed for {name}")).into())
        }
    }

    fn list_secrets(&self) -> Vec<String> {
        self.names.clone()
    }

    fn get_public_keys(&self, name: &str) -> Result<Vec<String>, Report> {
        let entry = self.load_entry(name)?;
        let mut reports = ReportCollection::new();
        let mut keys = Vec::new();
        for key in &entry.public_keys {
            match key {
                PublicKeyString::Direct(key) => {
                    keys.push(key.clone());
                }
                PublicKeyString::Reference(keyname) => {
                    if !self.names.contains(keyname) {
                        let error = report!("{name} uses the public output of {keyname} as its public key but {keyname} is not in secrets.nix").into_cloneable();
                        reports.push(error);
                        continue;
                    }
                    let public = match self.get_public(name) {
                        Err(e) => {
                            reports.push(e.into_cloneable());
                            continue;
                        }
                        Ok(p) => p,
                    };
                    match public {
                        SecretType::PlainText(data) | SecretType::NewlyGenerated(data) => {
                            let key_str = String::from_utf8(data).map_err(|e| {
                                report!("Public key from {keyname} is not valid UTF-8: {}", e)
                            })?;
                            keys.push(key_str);
                        }
                        _ => {
                            let error = report!("{name} uses the public output of {keyname} as its public key but there is no such file").into_cloneable();
                            reports.push(error);
                            continue;
                        }
                    }
                }
            }
        }
        if reports.is_empty() {
            Ok(keys)
        } else {
            Err(reports
                .context(format!("Failed to get public keys for secret {name}"))
                .into())
        }
    }
}

static GLOBAL_STATE: LazyLock<RwLock<Option<GlobalState>>> = LazyLock::new(|| RwLock::new(None));

/// Load or generate the secret with the given name
pub fn get_secret(name: &str) -> Result<SecretType, Report> {
    let global_state = GLOBAL_STATE.read().unwrap();
    let global_state = global_state
        .as_ref()
        .ok_or_else(|| report!("Global state not initialized"))?;
    global_state.get_secret(name)
}

/// Load or generate the public part with the given name
pub fn get_public(name: &str) -> Result<SecretType, Report> {
    let global_state = GLOBAL_STATE.read().unwrap();
    let global_state = global_state
        .as_ref()
        .ok_or_else(|| report!("Global state not initialized"))?;
    global_state.get_public(name)
}

/// Load or generate the public part with the given name
pub fn get_entry(name: &str) -> Result<RawSecretEntry, Report> {
    let global_state = GLOBAL_STATE.read().unwrap();
    let global_state = global_state
        .as_ref()
        .ok_or_else(|| report!("Global state not initialized"))?;
    global_state.load_entry(name)
}

pub fn resolve_secret(name: &str) -> Result<(), Report> {
    let global_state = GLOBAL_STATE.read().unwrap();
    let global_state = global_state
        .as_ref()
        .ok_or_else(|| report!("Global state not initialized"))?;
    global_state.resolve_secret(name)
}

pub fn check_entry(name: &str) -> Result<(), Report> {
    let global_state = GLOBAL_STATE.read().unwrap();
    let global_state = global_state
        .as_ref()
        .ok_or_else(|| report!("Global state not initialized"))?;
    global_state.check_entry(name)
}

pub fn list_secrets() -> Result<Vec<String>, Report> {
    let global_state = GLOBAL_STATE.read().unwrap();
    let global_state = global_state
        .as_ref()
        .ok_or_else(|| report!("Global state not initialized"))?;
    Ok(global_state.list_secrets())
}
