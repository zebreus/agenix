// Module declarations
pub mod evaluation;
pub mod generator;
pub mod keypair;
pub mod rules;
pub mod value_conversion;

#[cfg(test)]
mod tests;

// Re-export public APIs
pub use evaluation::eval_nix_expression;
pub use generator::{GeneratorOutput, generate_secret, generate_secret_with_public};
pub use keypair::{generate_age_x25519_keypair, generate_ed25519_keypair};
pub use rules::{get_all_files, get_public_keys, should_armor};
