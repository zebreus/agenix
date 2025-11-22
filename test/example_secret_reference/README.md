# Example: Secret Reference in publicKeys

This example demonstrates how to reference generated public keys from other secrets.

## Files

- `secrets.nix` - Configuration showing secret name references in publicKeys

## How it works

1. The `deploy-key.age` secret has a generator that produces both a private and public key
2. When generated, this creates both `deploy-key.age` (encrypted private key) and `deploy-key.age.pub` (public key)
3. Other secrets like `authorized-keys.age` can reference "deploy-key" in their publicKeys list
4. During encryption/rekeying, agenix automatically resolves "deploy-key" to the actual public key from `deploy-key.age.pub`

## Usage

```bash
# Generate the secrets (creates deploy-key.age and deploy-key.age.pub)
agenix --generate --rules ./secrets.nix

# The .pub file now contains the public key
cat deploy-key.age.pub
# Output: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeployKeyPublicExample

# Encrypt or rekey secrets - the reference will be resolved automatically
agenix --rekey --rules ./secrets.nix
```

## Benefits

- **Ergonomic**: Just use the secret name instead of copying the public key
- **Consistent**: The public key is always in sync with the secret
- **Maintainable**: When you regenerate a key, just rekey the dependent secrets
