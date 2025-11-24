# Example: Secret Reference in publicKeys and Generators

This example demonstrates how to reference generated public keys from other secrets in both `publicKeys` and in generator functions.

## Files

- `secrets.nix` - Configuration showing secret name references in publicKeys and generators

## How it works

### Public Key References (Existing Feature)

1. The `deploy-key.age` secret has a generator that produces both a private and public key
2. When generated, this creates both `deploy-key.age` (encrypted private key) and `deploy-key.age.pub` (public key)
3. Other secrets like `authorized-keys.age` can reference "deploy-key" in their publicKeys list
4. During encryption/rekeying, agenix automatically resolves "deploy-key" to the actual public key from `deploy-key.age.pub`

### Generator Dependencies (New Feature)

Generators can now reference both secret and public contents of other secrets via the `dependencies` attribute:

1. Define dependencies in the secret configuration using the `dependencies` attribute
2. Access dependent secrets' values in the generator:
   - `secrets.<name>` - the secret content (for just-generated secrets)
   - `publics.<name>` - the public content (always available if secret has public output)
3. Generator functions can accept `{ secrets }`, `{ publics }`, `{ secrets, publics }`, `{ }`, or any subset
4. The system automatically tries different parameter combinations if the generator doesn't accept all arguments
5. Secrets are generated in dependency order automatically
6. Clear error messages if dependencies cannot be resolved

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

## Example with Dependencies

```nix
{
  # Generate an SSH key
  "deploy-key.age" = {
    publicKeys = [ user1 system1 ];
    generator = builtins.sshKey;
  };
  
  # Create an authorized_keys file that includes the deploy key
  "authorized-keys.age" = {
    publicKeys = [ user1 system1 ];
    dependencies = [ "deploy-key" ];
    generator = { publics }: 
      # Access the public key from deploy-key
      publics."deploy-key" + "\n" + "ssh-ed25519 AAAA... other-key";
  };
  
  # Example using both secrets and publics
  "config.age" = {
    publicKeys = [ user1 system1 ];
    dependencies = [ "deploy-key" ];
    generator = { secrets, publics }: 
      # Access both secret and public content
      ''
        Secret hash: ${builtins.hashString "sha256" secrets."deploy-key"}
        Public key: ${publics."deploy-key"}
      '';
  };
}
```

## Benefits

- **Ergonomic**: Just use the secret name instead of copying the public key
- **Consistent**: The public key is always in sync with the secret
- **Maintainable**: When you regenerate a key, just rekey the dependent secrets
- **Composable**: Build complex secrets from simpler ones
