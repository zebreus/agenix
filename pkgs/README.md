# Agenix Rust Implementation

Pure Rust implementation of agenix - edit and rekey age secret files using Nix expressions.

## Dependencies

- `age` - Age encryption tool (hardcoded into binary during Nix build)
- `snix-eval` - Pure Rust Nix expression evaluator (replaces `nix-instantiate`)

## Improvements over shell version

- No `jq` dependency (uses `serde_json` for JSON parsing)
- No `nix-instantiate` dependency (uses pure Rust `snix-eval` library)
- Native Rust binary (no bash required)
- Better error handling with detailed error messages
- Type-safe Nix expression evaluation
- Comprehensive test coverage

## Features

- Edit encrypted secrets with your preferred editor
- Decrypt secrets to stdout or a file
- Rekey all secrets with updated recipients
- Support for both armored (ASCII) and binary age encryption
- Automatic detection of SSH keys (RSA, ed25519) and age keys
- Custom rules file support via `--rules` flag or `RULES` environment variable
- Flexible identity management with `--identity` flag

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
