# NixOS Module UX Testing

This directory contains comprehensive UX tests for the agenix NixOS module. The goal is to test real-world scenarios and identify any usability issues.

## Test Scenarios

### Scenario 1: Self-hosted Gitea with Database Secrets
Tests setting up a self-hosted Gitea instance with:
- PostgreSQL database with password managed by agenix
- Gitea admin credentials managed by agenix
- SSH host keys for the service

### Scenario 2: SSH Deployment Key Management
Tests managing SSH keys for deployment purposes:
- Generate SSH key pairs using agenix
- Install public keys to authorized_keys
- Use private keys for service authentication

### Scenario 3: Multi-Service Secret Sharing
Tests scenarios where multiple services need access to shared secrets:
- Shared database credentials
- API tokens used by multiple services
- Proper permission management

### Scenario 4: Home Manager User Secrets
Tests user-level secret management:
- User SSH keys
- Application tokens
- Git credentials

## Running the Tests

```bash
# Run the UX test
nix build .#checks.x86_64-linux.ux-testing

# Run the VM interactively
nix run .#checks.x86_64-linux.ux-testing.driver
```

## UX Findings and Recommendations

This section will be updated with findings from the UX test.

### Findings

#### Positive Aspects
1. **Simple integration**: Adding the module to a NixOS configuration is straightforward
2. **Declarative secrets**: Secrets are declared alongside the services that use them
3. **Automatic decryption**: Secrets are automatically decrypted at system activation
4. **SSH key integration**: Using existing SSH keys is convenient

#### Usability Issues Identified

1. **Secret path discovery**: Need to understand `config.age.secrets.<name>.path` pattern
   - **Recommendation**: Add more examples in documentation showing path usage
   
2. **Initial secret creation workflow**: First-time users may not understand the full flow
   - **Recommendation**: Add a quickstart guide with step-by-step instructions
   
3. **Error messages**: When secrets fail to decrypt, error messages could be clearer
   - **Recommendation**: Improve error messages to guide users to common fixes
   
4. **Public key management**: The relationship between secrets and public keys could be clearer
   - **Recommendation**: Add examples showing public key usage patterns

5. **Permission management**: Understanding mode, owner, and group settings requires trial
   - **Recommendation**: Add a permissions reference table with common scenarios

### Workflow Observations

#### Setting up a new project
1. Add agenix to flake inputs - straightforward
2. Import the module - clear from documentation
3. Define secrets in configuration - intuitive
4. Create secrets.nix - requires understanding the format
5. Generate/edit secrets - CLI is easy to use once understood

#### Pain Points
- First-time setup requires reading multiple documentation sections
- Understanding the relationship between secrets.nix, encrypted files, and module configuration
- Testing secret decryption before full deployment

### Recommendations for Improvement

1. **Interactive wizard**: Create an `agenix init` command that guides users through initial setup
2. **Validation command**: Add `agenix check` to validate secrets.nix and encrypted files
3. **Example templates**: Provide ready-to-use templates for common scenarios
4. **Better error messages**: Include suggestions in error messages
5. **Documentation improvements**: 
   - Add a troubleshooting section
   - Include more real-world examples
   - Create a migration guide from other secret management tools
