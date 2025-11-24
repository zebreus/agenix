# Example: Generator Dependencies

This example demonstrates how generator functions can reference the contents of other secrets (both secret and public outputs), even if they haven't been generated yet.

## Overview

Generator functions now receive two parameters via an attribute set:
- `secrets`: An attrset mapping secret names (without .age suffix) to their generated secret content
- `publics`: An attrset mapping secret names (without .age suffix) to their generated public content

## Files

- `secrets.nix` - Configuration showing various dependency patterns

## How it works

1. **Dependency Resolution**: When you run `agenix --generate`, secrets are generated in multiple passes:
   - First pass: Generate secrets with no dependencies
   - Subsequent passes: Generate secrets that depend on previously-generated secrets
   - Continues until all secrets are generated or a circular dependency is detected

2. **Automatic Generators**: Some secrets use automatic generators based on their filename:
   - `deploy-key.age` - Automatically generates an SSH Ed25519 keypair
   - `db-password.age` - Automatically generates a 32-character random password

3. **Custom Generators**: Other secrets use custom generator functions:
   - `ssh-authorized-keys.age` - References the deploy key's public output
   - `app-config.age` - References both the database password (secret) and deploy key (public)
   - `optional-config.age` - Shows how to handle optional dependencies with fallbacks

## Generator Function Signatures

Generators must accept an attribute set parameter. Use one of these patterns:

```nix
# Access both secrets and publics
generator = { secrets, publics, ... }: ...

# Access only secrets
generator = { secrets, ... }: ...

# Access only publics  
generator = { publics, ... }: ...

# Ignore the context (for simple generators)
generator = { ... }: ...
```

The `...` is important - it allows the generator to ignore any extra parameters.

## Usage

```bash
# Generate all secrets
agenix --generate --rules ./secrets.nix

# This will create:
# - deploy-key.age (encrypted private key)
# - deploy-key.age.pub (public key in plain text)
# - db-password.age (encrypted random password)
# - ssh-authorized-keys.age (encrypted authorized_keys file with deploy key)
# - app-config.age (encrypted config referencing both password and deploy key)
# - optional-config.age (encrypted config with optional dependencies)
```

## Dependency Order

The secrets will be generated in this order (approximately):
1. `deploy-key.age` - No dependencies
2. `db-password.age` - No dependencies
3. `ssh-authorized-keys.age` - Depends on deploy-key's public output
4. `app-config.age` - Depends on deploy-key's public output and db-password's secret
5. `optional-config.age` - Has optional dependencies, will use fallbacks if needed

## Benefits

- **DRY**: Don't repeat yourself - generate secrets once and reference them everywhere
- **Consistency**: Ensures related secrets (like SSH keypairs) are always in sync
- **Flexibility**: Use secrets and their public outputs in configuration files
- **Safety**: Circular dependencies are detected and reported

## Migration from Old Style

If you have existing generators using the old `{ }:` pattern, update them to use `{ ... }:`:

```nix
# Old style (will cause errors)
generator = { }: "my-secret";

# New style (backward compatible)
generator = { ... }: "my-secret";

# New style with dependencies
generator = { secrets, publics, ... }: "derived-${secrets.other}";
```
