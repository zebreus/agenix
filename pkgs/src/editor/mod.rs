//! File editing and secret management operations.
//!
//! This module provides functions for editing, decrypting, rekeying, and generating
//! encrypted secret files with temporary file handling and editor integration.
//!
//! # Module Structure
//!
//! - [`context`] - Secret context for bundling common parameters
//! - [`secret_name`] - Secret name normalization and handling
//! - [`dependency_resolver`] - Dependency resolution for secret generation
//! - [`edit`] - File editing and decryption operations
//! - [`rekey`] - Rekey operations for encrypted secrets
//! - [`generate`] - Secret generation operations

pub mod context;
pub mod dependency_resolver;
pub mod edit;
pub mod generate;
pub mod rekey;
pub mod secret_name;

// Re-export main public functions for backwards compatibility
pub use edit::{decrypt_file, edit_file};
pub use generate::generate_secrets;
pub use rekey::rekey_files;

// Re-export commonly used types
pub use context::SecretContext;
pub use dependency_resolver::DependencyResolver;
pub use generate::ProcessResult;
pub use secret_name::SecretName;
