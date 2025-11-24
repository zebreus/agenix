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
- `-g, --generate` - Generate secrets using generator functions from rules file
- `--rules <FILE>` - Path to Nix rules file (default: ./secrets.nix, can also use RULES env var)
- `--editor <EDITOR>` - Editor to use (default: $EDITOR or vi/cat depending on TTY)
- `-v, --verbose` - Verbose output
- `-h, --help` - Print help
- `-V, --version` - Print version

### Environment Variables

- `EDITOR` - Editor to use when editing secrets (default: vi)
- `RULES` - Path to Nix file specifying recipient public keys (default: ./secrets.nix)

If STDIN is not interactive, EDITOR will be set to "cp /dev/stdin", allowing you to pipe content directly.

## Generator Functions

Generator functions allow you to automatically create secrets. They can produce public output alongside the encrypted secret, which is useful for generating SSH keypairs or other scenarios where you need both a private secret and a public value.

### Basic Generators

When a generator function returns a string, only the `.age` file is created:

```nix
{
  "api-token.age" = {
    publicKeys = [ "age1..." ];
    generator = {}: builtins.randomString 32;
  };
}
```

### Generators with Public Output

When a generator function returns an attrset with both `secret` and `public` keys, the secret is encrypted to a `.age` file and the public value is written to a `.pub` file:

```nix
{
  # Generator with public output - returns an attrset
  "ssh-key.age" = {
    publicKeys = [ "age1..." ];
    generator = builtins.sshKey;
  };
  
  # Generator with metadata
  "database-password.age" = {
    publicKeys = [ "age1..." ];
    generator = {}: 
      let password = builtins.randomString 32;
      in {
        secret = password;
        public = "Generated on $(date)";
      };
  };
}
```

Generate the secrets:

```bash
agenix --generate
```

This creates:
- `ssh-key.age` (encrypted private key) and `ssh-key.age.pub` (public key)
- `database-password.age` (encrypted password) and `database-password.age.pub` (metadata)

### Available Builtin Generators

- `builtins.randomString <length>` - Generate a random alphanumeric string
- `builtins.sshKey` or `builtins.sshKey {}` - Generate an SSH Ed25519 keypair (returns `{secret, public}`)
- `builtins.ageKey` or `builtins.ageKey {}` - Generate an age x25519 keypair (returns `{secret, public}`)

### Automatic Generator Selection

If no explicit `generator` is provided, agenix automatically selects an appropriate generator based on the secret file's ending (case-insensitive):

| File ending | Generator | Output |
|-------------|-----------|--------|
| `*ed25519.age` | `builtins.sshKey` | SSH Ed25519 keypair with `.pub` file |
| `*ssh.age` | `builtins.sshKey` | SSH Ed25519 keypair with `.pub` file |
| `*ssh_key.age` | `builtins.sshKey` | SSH Ed25519 keypair with `.pub` file |
| `*x25519.age` | `builtins.ageKey` | age x25519 keypair with `.pub` file |
| `*password.age` | `builtins.randomString 32` | 32-character random password |
| `*passphrase.age` | `builtins.randomString 32` | 32-character random password |

Example:

```nix
{
  # Automatically generates SSH Ed25519 keypair
  "server-ed25519.age" = {
    publicKeys = [ "age1..." ];
  };
  
  # Automatically generates age x25519 keypair
  "identity-x25519.age" = {
    publicKeys = [ "age1..." ];
  };
  
  # Automatically generates 32-character random password
  "database-password.age" = {
    publicKeys = [ "age1..." ];
  };
  
  # No automatic generation (no matching ending)
  "api-token.age" = {
    publicKeys = [ "age1..." ];
  };
  
  # Explicit generator overrides automatic selection
  "custom-password.age" = {
    publicKeys = [ "age1..." ];
    generator = {}: "my-custom-value";
  };
}
```

### Referencing Generated Public Keys

When you generate secrets with public output (like SSH keys), you can reference the public key in the `publicKeys` field of other secrets. Simply use the secret name (with or without the `.age` suffix) instead of the actual public key:

```nix
{
  # Generate an SSH keypair for deployment
  "deploy-key.age" = {
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    generator = {}: builtins.sshKey {};
  };
  
  # Use the deploy key's public key for another secret
  "authorized-keys.age" = {
    publicKeys = [ 
      "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
      "deploy-key"  # References the public key from deploy-key.age.pub
    ];
  };
  
  # Also works with automatic generators
  "server-ssh.age" = {
    publicKeys = [ "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" ];
    # Automatically generates SSH key due to naming
  };
  
  "backup-authorized-keys.age" = {
    publicKeys = [ 
      "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
      "server-ssh.age"  # Can also use with .age suffix
    ];
  };
}
```

After generating secrets with `agenix --generate`, the `.pub` files are created alongside the `.age` files. When encrypting or rekeying secrets, agenix automatically resolves secret name references to their corresponding public keys from the `.pub` files.

This makes it easy to:
- Use generated SSH keys for authentication while encrypting config secrets
- Share generated age keys between multiple secrets
- Maintain consistency when rotating keys (just regenerate and rekey)

## Rekeying

If you change the public keys in your rules file, you should rekey your secrets:

```bash
agenix --rekey
```

To rekey a secret, you must be able to decrypt it. Because of randomness in age's encryption algorithms, the files always change when rekeyed, even if the identities do not.

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
