//! Nix evaluation and the secret resolution engine.
//!
//! The public surface is the engine API: initialize with [`init`], read
//! values with [`get_secret`]/[`get_public`], run generation with
//! [`generate`], and persist results with [`flush`]. Everything else
//! (evaluation, entry semantics, generators, builtins) is internal.

mod builtins;
mod engine;
mod eval;
mod generator;
mod keypair;
mod public_key;
mod raw_secret_entry;

pub use engine::{Config, Operation, check_entry, flush, generate, init, list_names};
