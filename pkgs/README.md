# Agenix Rust Implementation

Pure Rust implementation of agenix - edit and rekey age secret files using Nix expressions.

## Dependencies

This is a pure Rust implementation with the following main dependencies:

- `age` (Rust crate) - Standalone Rust implementation of the age encryption format, supporting both age and SSH keys
- `snix-eval` - Pure Rust Nix expression evaluator for reading secrets configuration
- `clap` - Command-line argument parsing
- `serde_json` - JSON parsing for Nix evaluation results

## Key Features

- **Pure Rust implementation**: No external dependencies on shell scripts, `jq`, or `nix-instantiate`
- **Native age library**: Uses the Rust age crate for all encryption/decryption operations
- **Type-safe Nix evaluation**: Evaluates Nix expressions using the pure Rust `snix-eval` library
- **Comprehensive error handling**: Detailed error messages with proper context
- **Extensive test coverage**: Unit and integration tests covering all major functionality

## Capabilities

This tool provides the following functionality:

- **Edit secrets**: Open encrypted secrets in your preferred editor, with automatic encryption/decryption
- **Decrypt secrets**: Output decrypted content to stdout or save to a file
- **Rekey secrets**: Re-encrypt all secrets when recipients change
- **Flexible encryption**: Support for both ASCII-armored and binary age file formats
- **Multiple key types**: Automatically handles age keys (age1...) and SSH keys (RSA, ed25519)
- **Configurable rules**: Define encryption recipients and settings in a Nix file
- **Identity management**: Use custom SSH/age identities or auto-detect from `~/.ssh/`

## Usage

```bash
# Edit a secret (creates if doesn't exist)
agenix -e secret.age

# Edit with custom rules file
agenix -e secret.age --rules /path/to/secrets.nix

# Decrypt to stdout
agenix -d secret.age

# Decrypt to a file
agenix -d secret.age -o decrypted.txt

# Decrypt with specific identity
agenix -d secret.age -i ~/.ssh/id_rsa

# Rekey all secrets (re-encrypt with current recipients)
agenix -r

# Use custom editor
agenix -e secret.age --editor nano

# Verbose output
agenix -v -e secret.age
```

## CLI Options

- `-e, --edit <FILE>` - Edit FILE using $EDITOR
- `-d, --decrypt <FILE>` - Decrypt FILE to STDOUT (or to --output)
- `-o, --output <FILE>` - Write decrypt output to FILE instead of STDOUT
- `-i, --identity <PRIVATE_KEY>` - Identity to use when decrypting
- `-r, --rekey` - Re-encrypt all secrets with specified recipients
- `--rules <FILE>` - Path to Nix rules file (default: ./secrets.nix, can also use RULES env var)
- `--editor <EDITOR>` - Editor to use (default: $EDITOR or vi/cat depending on TTY)
- `-v, --verbose` - Verbose output
- `-h, --help` - Print help
- `-V, --version` - Print version

## Build & Test

```bash
# Build the project
nix build

# Or with cargo (requires snix-eval to be available)
cargo build --release

# Run tests
cargo test

# Run tests with Nix (includes integration tests)
nix build .#checks.x86_64-linux.default
```

## Rules File Format

The rules file is a Nix expression that defines which public keys can decrypt each secret:

```nix
{
  "secret1.age" = {
    publicKeys = [ 
      "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqiXi9DyVJGcL8pE4+bKqe3FP8"
    ];
    armor = true;  # Use ASCII-armored output (optional, default: false)
  };
  "secret2.age" = {
    publicKeys = [ 
      "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
    ];
  };
}
```
