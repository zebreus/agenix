//! Nix expression evaluation utilities.
//!
//! Provides functions for evaluating Nix expressions and converting Nix values
//! to Rust types.

use anyhow::{Context, Result, anyhow};
use cosmian_crypto_core::Secret;
use rootcause::IntoReport;
use rootcause::Report;
use rootcause::markers::SendSync;
use rootcause::prelude::ResultExt;
use rootcause::report;
use rootcause::report_collection::ReportCollection;
use snix_eval::EvaluationBuilder;
use snix_eval::Value;
use std::any::Any;
use std::collections::HashMap;
use std::env::current_dir;
use std::path::Path;
use std::path::PathBuf;
use std::str::Bytes;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::RwLock;

use crate::nix::global_state::GlobalState;
use crate::nix::generator::GeneratorInput;
use crate::nix::generator::call_generator;
use crate::nix::raw_secret_entry::RawSecretEntry;
use crate::nix::raw_secret_entry::get_raw_secret_entry;

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

// // Horrible global state to manage secrets during basically everything
// // Used to track what secrets exist, are being generated, etc.
// // Toxic mixture of configuration, logic, and cache
// pub struct GlobalState {
//     secret_data: Mutex<std::collections::HashMap<String, SecretThing>>,
//     // The names of entries that we are allowed to generate
//     entry_modes: HashMap<String, EntryMode>,
//     // Path to the secrets.nix file as it was supplied on the cli
//     secrets_nix_path: PathBuf,
//     // Working directory for the secrets.nix path
//     current_dir: PathBuf,
//     // Absolute path to the secrets.nix directory
//     secrets_nix_dir: PathBuf,
//     // The entries known so far
//     entries: Mutex<std::collections::HashMap<String, RawSecretEntry>>,
//     // All known secret names
//     names: Vec<String>,
// }

// impl GlobalState {
//     pub fn new(generate: bool, overwrite: bool, secrets_nix_path: &Path) -> Result<Self, Report> {
//         let all_names = get_all_files(secrets_nix_path)
//             .context("Failed to get a list of all entries in secrets.nix")?;
//         let mut entry_modes = HashMap::new();
//         for name in &all_names {
//             let mode = if !generate {
//                 EntryMode::ReadOnly
//             } else if overwrite {
//                 EntryMode::ForceGenerate
//             } else {
//                 EntryMode::GenerateIfMissing
//             };
//             entry_modes.insert(name.to_string(), mode);
//         }
//         Ok(GlobalState {
//             secret_data: Mutex::new(std::collections::HashMap::new()),
//             entry_modes: HashMap::new(),
//             secrets_nix_path: secrets_nix_path.to_path_buf(),
//             current_dir: current_dir()?,
//             secrets_nix_dir: std::path::absolute(secrets_nix_path)
//                 .unwrap()
//                 .parent()
//                 .unwrap()
//                 .to_path_buf(),
//             entries: Mutex::new(std::collections::HashMap::new()),
//             names: all_names,
//         })
//         // TODO: Assert existance of the secrets.nix and secrets_nix_dir
//     }
//     /// Try hard to get the secret thing and generate if necessary
//     ///
//     /// For generating the secret and public are set to WorkInProgress and
//     /// then the generator function is called which
//     ///
//     /// For now it's unclear whether this is encrypted or decrypted.
//     pub fn get_secret(&self, name: &str) -> Result<SecretType, Report> {
//         if !self.names.contains(&name.to_string()) {
//             return Err(report!("Secret {name} not found in secrets.nix"));
//         }

//         let mut secret_data = self.secret_data.lock().unwrap();
//         let secret = match secret_data.get_mut(&name.to_string()) {
//             Some(secret) => secret,
//             None => {
//                 secret_data.insert(name.to_string(), SecretThing::new());
//                 secret_data.get_mut(&name.to_string()).unwrap()
//             }
//         };

//         let secret = match &secret.secret {
//             SecretType::NewlyGenerated(_) | SecretType::PlainText(_) | SecretType::Encrypted(_) => {
//                 secret.secret.clone()
//             }
//             SecretType::WorkInProgress => {
//                 return Err(report!("Circular dependency detected for secret {name}"));
//             }
//             SecretType::Missing => {
//                 return Err(report!("Secret {name} is missing and cannot be generated"));
//             }
//             SecretType::NotNeeded => {
//                 return Err(report!("Secret {name} is not needed"));
//             }
//             SecretType::Unknown => {
//                 drop(secret_data);
//                 self.resolve_secret(name)?;

//                 // Assert that the secret is actually resolved
//                 let secret_data = self.secret_data.lock().unwrap();
//                 let secret = secret_data.get(&name.to_string()).unwrap();
//                 assert!(!matches!(secret.secret, SecretType::Unknown));

//                 self.get_secret(name)?
//             }
//         };

//         // TODO: Move these checks somewhere else
//         let entry = self.entries.lock().unwrap();
//         let Some(entry) = entry.get(name) else {
//             return Err(report!(
//                 "Tried to get the secret for {name}, but it does not have an entry in secrets.nix"
//             ));
//         };
//         if Some(false) == entry.has_secret {
//             return Err(report!(
//                 "Secret {name} is marked as not having a secret part"
//             ));
//         };

//         Ok(secret)
//     }
//     /// Like get_secret but for public part
//     pub fn get_public(&self, name: &str) -> Result<SecretType, Report> {
//         let mut secret_data = self.secret_data.lock().unwrap();
//         let Some(secret) = secret_data.get_mut(&name.to_string()) else {
//             panic!("Secret {name} not found");
//         };

//         let public = match &secret.public {
//             SecretType::NewlyGenerated(_) | SecretType::PlainText(_) | SecretType::Encrypted(_) => {
//                 secret.public.clone()
//             }
//             SecretType::WorkInProgress => {
//                 return Err(report!(
//                     "Circular dependency detected for public part of {name}"
//                 ));
//             }
//             SecretType::Missing => {
//                 return Err(report!(
//                     "Public part of {name} is missing and cannot be generated"
//                 ));
//             }
//             SecretType::NotNeeded => {
//                 return Err(report!("Public part of {name} is not needed"));
//             }
//             SecretType::Unknown => {
//                 drop(secret_data);
//                 self.resolve_secret(name).unwrap();

//                 // Assert that the public is actually resolved
//                 let secret_data = self.secret_data.lock().unwrap();
//                 let secret = secret_data.get(&name.to_string()).unwrap();
//                 assert!(!matches!(secret.public, SecretType::Unknown));

//                 self.get_public(name)?
//             }
//         };

//         // TODO: Move these checks somewhere else
//         let entry = self.entries.lock().unwrap();
//         let Some(entry) = entry.get(name) else {
//             return Err(report!(
//                 "Tried to get the secret for {name}, but it does not have an entry in secrets.nix"
//             ));
//         };
//         if Some(false) == entry.has_public {
//             return Err(report!(
//                 "Secret {name} is marked as not having a secret part"
//             ));
//         };

//         Ok(public)
//     }

//     /// Generate, load, or retrieve the secret thing as needed.
//     /// The goal is to resolve it as much as possible.
//     ///
//     pub fn resolve_secret(&self, name: &str) -> Result<(), Report> {
//         if !self.names.contains(&name.to_string()) {
//             return Err(report!("Entry {name} not found in secrets.nix"));
//         }

//         let mut secret_data = self.secret_data.lock().unwrap();
//         let Some(secret) = secret_data.get_mut(&name.to_string()) else {
//             return Err(report!("Secret {name} not found at all"));
//         };

//         match &secret.secret {
//             SecretType::Unknown => (),
//             secret => {
//                 panic!(
//                     "Tried to call resolve_secret but it is already resolved: {:?}",
//                     secret
//                 );
//             }
//         }

//         // Load the secret entry and check if we need to have it at all
//         let entry = self.load_secret_entry(name)?;

//         let not_needed = entry.has_secret == Some(false);
//         let can_generate = self.can_generate(name);
//         let can_overwrite = self.can_overwrite(name);
//         let always_generate = self.always_generate(name);

//         // // Try to load from disk

//         if !can_generate {
//             if not_needed {
//                 secret.secret = SecretType::NotNeeded;
//                 return Ok(());
//             }

//             let file = self.read_secret_file(name)?;
//             if let Some(content) = file {
//                 // File exists, load it
//                 secret.secret = SecretType::Encrypted(content);
//                 return Ok(());
//             }
//             // Cannot generate and file does not exist
//             secret.secret = SecretType::Missing;
//             return Ok(());
//         }

//         if always_generate {
//             drop(secret_data);
//             self.generate_entry(name)?;
//             return Ok(());
//         }

//         match &secret.public {
//             SecretType::Unknown => {
//                 secret.secret = if not_needed {
//                     SecretType::NotNeeded
//                 } else {
//                     let file = self.read_secret_file(name)?;
//                     if let Some(content) = file {
//                         // File exists, load it
//                         SecretType::Encrypted(content)
//                     } else {
//                         SecretType::Missing
//                     }
//                 };

//                 // resolve_public will call into generate.
//                 drop(secret_data);
//                 return self.resolve_public(name);
//             }
//             SecretType::NotNeeded => {
//                 if not_needed {
//                     secret.secret = SecretType::NotNeeded;
//                     // Both not needed
//                     return Ok(());
//                 }
//                 // generate if there is no file for self
//                 let file = self.read_secret_file(name)?;
//                 if let Some(content) = file {
//                     secret.secret = SecretType::Encrypted(content);
//                     return Ok(());
//                 }

//                 drop(secret_data);
//                 self.generate_entry(name)?;
//                 return Ok(());
//             }
//             SecretType::Missing => {
//                 let file = self.read_secret_file(name)?;
//                 if file.is_some() && !can_overwrite {
//                     return Err(report!(
//                         "Secret {name} exists on disk but the entry is marked as missing and cannot be overwritten"
//                     ));
//                 }

//                 drop(secret_data);
//                 self.generate_entry(name)?;
//                 return Ok(());
//             }
//             SecretType::PlainText(_) | SecretType::Encrypted(_) => {
//                 if not_needed {
//                     secret.secret = SecretType::NotNeeded;
//                     return Ok(());
//                 }

//                 let file = self.read_secret_file(name)?;
//                 if let Some(content) = file {
//                     // File exists, load it
//                     SecretType::Encrypted(content);
//                     return Ok(());
//                 }
//                 if !can_overwrite {
//                     return Err(report!(
//                         "Public {name} exists on disk but the entry is marked as missing and cannot be overwritten"
//                     ));
//                 }
//                 drop(secret_data);
//                 self.generate_entry(name)?;
//                 return Ok(());
//             }
//             SecretType::NewlyGenerated(items) => {
//                 // Already generated, nothing to do
//                 return Ok(());
//             }
//             SecretType::WorkInProgress => {
//                 return Err(report!("Circular dependency detected for secret {name}"));
//             }
//         }
//         // self.resolve_public();

//         // If not overwriting, we need to check the public before generating
//     }

//     /// Generate, load, or retrieve the secret thing as needed.
//     /// The goal is to resolve it as much as possible.
//     ///
//     pub fn resolve_public(&self, name: &str) -> Result<(), Report> {
//         if !self.names.contains(&name.to_string()) {
//             return Err(report!("Entry {name} not found in secrets.nix"));
//         }

//         let mut secret_data = self.secret_data.lock().unwrap();
//         let Some(secret) = secret_data.get_mut(&name.to_string()) else {
//             return Err(report!("Secret {name} not found at all"));
//         };

//         match &secret.public {
//             SecretType::Unknown => (),
//             secret => {
//                 panic!(
//                     "Tried to call resolve_public but it is already resolved: {:?}",
//                     secret
//                 );
//             }
//         }

//         // Load the secret entry and check if we need to have it at all
//         let entry = self.load_secret_entry(name)?;

//         let not_needed = entry.has_secret == Some(false);
//         let can_generate = self.can_generate(name);
//         let can_overwrite = self.can_overwrite(name);
//         let always_generate = self.always_generate(name);

//         // // Try to load from disk

//         if !can_generate {
//             if not_needed {
//                 secret.public = SecretType::NotNeeded;
//                 return Ok(());
//             }

//             let file = self.read_secret_file(name)?;
//             if let Some(content) = file {
//                 // File exists, load it
//                 secret.public = SecretType::Encrypted(content);
//                 return Ok(());
//             }
//             // Cannot generate and file does not exist
//             secret.public = SecretType::Missing;
//             return Ok(());
//         }

//         if always_generate {
//             drop(secret_data);
//             self.generate_entry(name)?;
//             return Ok(());
//         }

//         match &secret.secret {
//             SecretType::Unknown => {
//                 secret.public = if not_needed {
//                     SecretType::NotNeeded
//                 } else {
//                     let file = self.read_secret_file(name)?;
//                     if let Some(content) = file {
//                         // File exists, load it
//                         SecretType::Encrypted(content)
//                     } else {
//                         SecretType::Missing
//                     }
//                 };

//                 // resolve_public will call into generate.
//                 drop(secret_data);
//                 return self.resolve_secret(name);
//             }
//             SecretType::NotNeeded => {
//                 if not_needed {
//                     secret.public = SecretType::NotNeeded;
//                     // Both not needed
//                     return Ok(());
//                 }
//                 // generate if there is no file for self
//                 let file = self.read_secret_file(name)?;
//                 if let Some(content) = file {
//                     secret.public = SecretType::Encrypted(content);
//                     return Ok(());
//                 }

//                 drop(secret_data);
//                 self.generate_entry(name)?;
//                 return Ok(());
//             }
//             SecretType::Missing => {
//                 let file = self.read_secret_file(name)?;
//                 if file.is_some() && !can_overwrite {
//                     return Err(report!(
//                         "Public {name} exists on disk but the matching secret is missing but we cant generate it because that might overwrite the public"
//                     ));
//                 }

//                 drop(secret_data);
//                 self.generate_entry(name)?;
//                 return Ok(());
//             }
//             SecretType::PlainText(_) | SecretType::Encrypted(_) => {
//                 if not_needed {
//                     secret.public = SecretType::NotNeeded;
//                     return Ok(());
//                 }

//                 let file = self.read_secret_file(name)?;
//                 if let Some(content) = file {
//                     // File exists, load it
//                     SecretType::Encrypted(content);
//                     return Ok(());
//                 }
//                 if !can_overwrite {
//                     return Err(report!(
//                         "Public {name} exists on disk but the entry is marked as missing and cannot be overwritten"
//                     ));
//                 }
//                 drop(secret_data);
//                 self.generate_entry(name)?;
//                 return Ok(());
//             }
//             SecretType::NewlyGenerated(_) => {
//                 // Already generated, nothing to do
//                 return Ok(());
//             }
//             SecretType::WorkInProgress => {
//                 return Err(report!("Circular dependency detected for secret {name}"));
//             }
//         }
//         // self.resolve_public();

//         // If not overwriting, we need to check the public before generating
//     }

//     /// Will be called by resolve_secret and resolve_public if they can't find the value and want to generate it
//     /// This will check
//     pub fn maybe_generate(&self, name: &str) -> Result<(), Report> {
//         let secret_data = self.secret_data.lock().unwrap();
//         let Some(secret) = secret_data.get(&name.to_string()) else {
//             return Err(report!("Secret {name} not found at all"));
//         };
//         match (&secret.secret, &secret.public) {
//             (
//                 SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
//                 SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
//             ) => {
//                 // Already generated
//                 return Ok(());
//             }
//             _ => {
//                 // Continue
//                 ()
//             }
//         };
//         drop(secret_data);

//         if !self.can_generate(name) {
//             return Ok(());
//         }

//         self.generate_entry(name)
//     }

//     /// Generate the entry.
//     /// We assume that both resolve_secret and resolve_public have been called before?
//     pub fn generate_entry(&self, name: &str) -> Result<(), Report> {
//         // Mark as work in progress to avoid cycles

//         let mut secret_data = self.secret_data.lock().unwrap();
//         let Some(secret) = secret_data.get_mut(&name.to_string()) else {
//             return Err(report!("Secret {name} not found at all"));
//         };
//         match (&secret.secret, &secret.public) {
//             (SecretType::WorkInProgress, _) | (_, SecretType::WorkInProgress) => {
//                 return Err(report!("Circular dependency detected for secret {name}"));
//             }
//             (
//                 SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
//                 SecretType::NewlyGenerated(_) | SecretType::NotNeeded,
//             ) => {
//                 // Already generated or nothing needed
//                 return Ok(());
//             }
//             (
//                 SecretType::NotNeeded | SecretType::Unknown,
//                 SecretType::NotNeeded | SecretType::Unknown,
//             ) => {
//                 // Continue
//                 ()
//             }
//             _ => {
//                 return Err(report!(
//                     "Secret {name} is already partially generated or loaded"
//                 ));
//             }
//         };

//         secret.secret = match &secret.secret {
//             SecretType::Unknown => SecretType::WorkInProgress,
//             SecretType::NotNeeded => SecretType::NotNeeded,
//             _ => panic!("Unexpected state"),
//         };
//         secret.public = match &secret.public {
//             SecretType::Unknown => SecretType::WorkInProgress,
//             SecretType::NotNeeded => SecretType::NotNeeded,
//             _ => panic!("Unexpected state"),
//         };
//         drop(secret_data);

//         let result = call_generator(
//             &self.secrets_nix_path,
//             &self.current_dir,
//             name,
//             GeneratorInput {
//                 known_entries: self.names.clone(),
//             },
//         )?;

//         let mut secret_data = self.secret_data.lock().unwrap();
//         let secret_entry = self.load_secret_entry(name)?;
//         let Some(secret) = secret_data.get_mut(&name.to_string()) else {
//             return Err(report!("Secret {name} not found at all"));
//         };
//         secret.secret = match (&result.secret, secret_entry.has_secret) {
//             (Some(s), Some(true) | None) => SecretType::NewlyGenerated(s.clone().into_bytes()),
//             (None, Some(false) | None) => SecretType::NotNeeded, // Newly fig
//             (Some(_), Some(false)) => {
//                 // This is ok, we explicitly don't want to save it even though generator returned it
//                 SecretType::NotNeeded
//             }
//             (None, Some(true)) => {
//                 return Err(report!(
//                     "Generator for {name} did not return a secret but the entry has hasSecret=true"
//                 ));
//             }
//         };
//         secret.public = match (&result.public, secret_entry.has_public) {
//             (Some(p), Some(true) | None) => SecretType::NewlyGenerated(p.clone().into_bytes()),
//             (None, Some(false) | None) => SecretType::NotNeeded,
//             (Some(_), Some(false)) => {
//                 // This is ok, we explicitly don't want to save it even though generator returned it
//                 SecretType::NotNeeded
//             }
//             (None, Some(true)) => {
//                 return Err(report!(
//                     "Generator for {name} did not return a public but the entry has hasPublic=true"
//                 ));
//             }
//         };
//         Ok(())
//     }

//     // Call the generator function

//     pub fn can_generate(&self, name: &str) -> bool {
//         self.entry_modes.get(name).map_or(false, |mode| {
//             matches!(
//                 mode,
//                 EntryMode::GenerateIfMissing | EntryMode::Generate | EntryMode::ForceGenerate
//             )
//         })
//     }
//     pub fn can_overwrite(&self, name: &str) -> bool {
//         self.entry_modes.get(name).map_or(false, |mode| {
//             matches!(mode, EntryMode::Generate | EntryMode::ForceGenerate)
//         })
//     }
//     pub fn always_generate(&self, name: &str) -> bool {
//         self.entry_modes
//             .get(name)
//             .map_or(false, |mode| matches!(mode, EntryMode::ForceGenerate))
//     }
//     // pub fn always_generate(&self, name: &str) -> bool {
//     //     self.entry_modes
//     //         .get(name)
//     //         .map_or(false, |mode| matches!(mode, EntryMode::ForceGenerate))
//     // }

//     /// Load the raw secrets.nix entry for the given name
//     pub fn load_secret_entry(&self, name: &str) -> Result<RawSecretEntry, Report> {
//         if !self.names.contains(&name.to_string()) {
//             return Err(report!("Entry {name} not found in secrets.nix"));
//         }

//         if let Some(entry) = self.entries.lock().unwrap().get(name) {
//             return Ok(entry.clone());
//         }

//         let entry = get_raw_secret_entry(&self.secrets_nix_path, name)
//             .context(format!("Failed to load secret entry for {name}"))?;
//         let mut entries = self.entries.lock().unwrap();
//         entries.insert(name.to_string(), entry.clone());
//         Ok(entry)
//     }

//     // /// Generate new values for the secret. Does not touch the existing state
//     // ///
//     // pub fn generate_secret(&self, name: &str) -> Result<SecretThing, Report> {
//     //     call_generator(name)
//     // }

//     /// Get the full path to the secret file (.age)
//     fn secret_file_path(&self, name: &str) -> PathBuf {
//         self.secrets_nix_dir.join(format!("{}.age", &name))
//     }
//     fn read_secret_file(&self, name: &str) -> Result<Option<Vec<u8>>, Report> {
//         let path = self.secret_file_path(name);
//         if !path.exists() {
//             return Ok(None);
//         }

//         match std::fs::read(&path) {
//             Ok(c) => Ok(Some(c)),
//             Err(e) => Err({
//                 let err = match e.kind() {
//                         std::io::ErrorKind::NotFound => {
//                             return Ok(None);
//                         }
//                         std::io::ErrorKind::PermissionDenied => {
//                              report!("Permission denied to read the secret file but it is expected to be accessible. Check file permissions.").into_dyn_any()
//                         }
//                         _ => {
//                                report!("{}", e.to_string())
//                         },
//                       };
//                 err
//                     .context("Secret file is expected to exist and be accesible. Set hasSecret=false to change this behaviour").into_dyn_any()
//             }),
//         }
//     }

//     /// Get the full path to the public file (.pub)
//     fn public_file_path(&self, name: &str) -> PathBuf {
//         self.secrets_nix_dir.join(format!("{}.pub", &name))
//     }
//     fn read_public_file(&self, name: &str) -> Result<Option<Vec<u8>>, Report> {
//         let path = self.public_file_path(name);
//         match std::fs::read(&path) {
//             Ok(c) => Ok(Some(c)),
//             Err(e) => Err({
//                 let err = match e.kind() {
//                         std::io::ErrorKind::NotFound => {
//                             return Ok(None);
//                         }
//                         std::io::ErrorKind::PermissionDenied => {
//                              report!("Permission denied to read the secret file but it is expected to be accessible. Check file permissions.").into_dyn_any()
//                         }
//                         _ => {
//                                report!("{}", e.to_string())
//                         },
//                       };
//                 err
//                     .context("Secret file is expected to exist and be accesible. Set hasSecret=false to change this behaviour").into_dyn_any()
//             }),
//         }
//     }
// }

pub static GLOBAL_STATE: LazyLock<RwLock<Option<GlobalState>>> =
    LazyLock::new(|| RwLock::new(None));

pub fn eval_nix_expression(expr: &str, path: &Path) -> Result<Value, Report> {
    let path = std::path::absolute(path).unwrap();

    let builder = EvaluationBuilder::new_impure();
    let evaluation = builder
        .add_builtins(crate::nix::builtins::impure_builtins::builtins())
        .build();
    let sourcemap = evaluation.source_map();

    let result = evaluation.evaluate(expr, Some(path));

    // Capture formatted errors and warnings instead of printing directly
    let error_messages: Vec<String> = result
        .errors
        .iter()
        .map(snix_eval::Error::fancy_format_str)
        .collect();

    let warning_messages: Vec<String> = result
        .warnings
        .iter()
        .map(|warning| warning.fancy_format_str(&sourcemap))
        .collect();

    let Some(result) = result.value else {
        // Include captured errors and warnings in the anyhow error
        let mut errors: ReportCollection<dyn Any, SendSync> = ReportCollection::new();

        for error in &error_messages {
            errors.push(report!("{}", error).into_cloneable());
        }
        for warning in &warning_messages {
            errors.push(report!("{}", warning).into_cloneable());
        }

        return Err(errors
            .context("Failed to evaluate Nix expression")
            .into_dyn_any());
    };

    // If there are warnings but evaluation succeeded, we could optionally log them
    // For now, we'll just proceed silently with warnings

    Ok(result)
}

pub fn value_to_string_array(value: &Value) -> Result<Vec<String>, Report> {
    match value {
        Value::List(arr) => arr
            .into_iter()
            .map(|v| value_to_string(v))
            .collect::<Result<Vec<_>, _>>(),
        Value::Thunk(thunk) => {
            // Extract value from evaluated thunk
            let inner = thunk.value();
            value_to_string_array(&inner)
        }
        wrong_value => {
            Err(report!("Expected list of strings").attach(format!("got: {wrong_value:?}")))
        }
    }
}

pub fn value_to_optional_string_array(value: &Value) -> Result<Option<Vec<String>>, Report> {
    match value {
        Value::List(arr) => Ok(Some(
            arr.into_iter()
                .map(|v| value_to_string(v))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::AttrNotFound => Ok(None),
        Value::Null => Ok(None),
        Value::Thunk(thunk) => {
            // Extract value from evaluated thunk
            let inner = thunk.value();
            value_to_optional_string_array(&inner)
        }
        wrong_value => {
            Err(report!("Expected list of strings or null").attach(format!("got: {wrong_value:?}")))
        }
    }
}

pub fn value_to_string(value: &Value) -> Result<String, Report> {
    match value {
        Value::String(s) => Ok(s.as_str().map(std::string::ToString::to_string)?),
        Value::Thunk(thunk) => {
            let inner = &thunk.value();
            value_to_string(inner)
        }
        wrong_value => Err(report!("Expected string").attach(format!("got: {wrong_value:?}"))),
    }
}

pub fn value_to_optional_bool(value: &Value) -> Result<Option<bool>, Report> {
    match value {
        Value::Bool(b) => Ok(Some(*b)),
        Value::AttrNotFound => Ok(None),
        Value::Null => Ok(None),
        Value::Thunk(thunk) => {
            // Extract value from evaluated thunk
            let inner = thunk.value();
            value_to_optional_bool(&inner)
        }
        wrong_value => {
            Err(report!("Expected boolean or null").attach(format!("got: {wrong_value:?}")))
        }
    }
}

pub fn value_to_bool(value: &Value) -> Result<bool, Report> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::Thunk(thunk) => {
            // Extract value from evaluated thunk
            let inner = thunk.value();
            value_to_bool(&inner)
        }
        wrong_value => Err(report!("Expected boolean").attach(format!("got: {wrong_value:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::current_dir;

    // Test to verify error message formatting is captured in anyhow
    #[test]
    fn test_formatted_error_capture() -> Result<()> {
        // This test verifies that Nix errors are properly captured with formatting
        let result = eval_nix_expression("import /nonexistent/path/to/rules.nix", &current_dir()?);

        match result {
            Err(err) => {
                let error_string = err.to_string();

                // The error should contain our formatted Nix error message
                assert!(error_string.contains("Failed to evaluate Nix expression"));
                assert!(error_string.contains("Errors:"));
                assert!(error_string.contains("No such file or directory"));

                Ok(())
            }
            Ok(_) => {
                // This should not succeed with a nonexistent file
                panic!("Expected an error but got success");
            }
        }
    }
}
