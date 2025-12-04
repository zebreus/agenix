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

This section documents findings from the comprehensive UX testing of the agenix NixOS module.

### Test Results

All test scenarios passed successfully:
✅ **Scenario 1: Self-hosted Gitea with Database Secrets** - Tested managing multiple secrets for a web application
✅ **Scenario 2: SSH Deployment Key Management** - Tested SSH key secrets with specific ownership
✅ **Scenario 3: Multi-Service Secret Sharing** - Tested shared secrets across multiple services with proper permissions

### Positive Aspects

1. **Simple integration**: Adding the module to a NixOS configuration is straightforward
   - Just import the module and define secrets
   - Works seamlessly with existing NixOS services
   
2. **Declarative secrets**: Secrets are declared alongside the services that use them
   - Co-location of secret configuration with service configuration improves maintainability
   - Clear ownership and permission settings
   
3. **Automatic decryption**: Secrets are automatically decrypted at system activation
   - No manual intervention needed after nixos-rebuild
   - Secrets available immediately after activation
   
4. **SSH key integration**: Using existing SSH keys is convenient
   - No need to manage separate age keys
   - Leverage existing infrastructure
   
5. **Flexible ownership**: Easy to set owner, group, and permissions for each secret
   - Works well with system users (isSystemUser = true)
   - Supports different permission models (0400, 0440, etc.)

### Usability Issues Identified

1. **Secret path discovery**: Understanding the relationship between secret name and `config.age.secrets.<name>.path`
   - **Recommendation**: Add prominent examples in documentation showing path usage
   - The default path pattern `/run/agenix/<name>` is intuitive once learned
   
2. **Initial secret creation workflow**: First-time users may not understand the full flow of:
   - Creating secrets.nix
   - Encrypting secrets with agenix CLI
   - Referencing secrets in NixOS configuration
   - **Recommendation**: Add a quickstart guide with step-by-step instructions
   
3. **Error messages**: When secrets fail to decrypt, error messages could guide users better
   - Common issues: wrong public keys in secrets.nix, missing identity files
   - **Recommendation**: Improve error messages to suggest common fixes
   
4. **File reference patterns**: Using `file = ./path` requires understanding Nix path semantics
   - Relative paths work differently in different contexts
   - **Recommendation**: Document path resolution rules clearly
   
5. **Permission management**: Understanding mode, owner, and group settings requires some trial
   - System users (isSystemUser) have different default groups than normal users
   - **Recommendation**: Add a permissions reference table with common scenarios

6. **Testing before deployment**: No easy way to validate configuration without deploying
   - **Recommendation**: Add `agenix check` command to validate secrets.nix and encrypted files
   - Could detect missing secrets, wrong permissions, unencrypted files, etc.

### Workflow Observations

#### Setting up a new project (Estimated: 15-30 minutes for first-time users)

1. Add agenix to flake inputs - straightforward (2 min)
2. Import the module - clear from documentation (2 min)
3. Understand secrets.nix format - requires reading documentation (10 min)
4. Create secrets.nix with public keys - manual process (5 min)
5. Generate/edit secrets using CLI - easy once understood (5 min)
6. Define secrets in configuration - intuitive (5 min)
7. Deploy and verify - standard NixOS workflow (10 min)

**Key insight**: The hardest part is understanding the relationship between:
- Public keys in secrets.nix
- Encrypted .age files
- Secret declarations in NixOS configuration  
- Decrypted files at runtime

#### Pain Points Discovered

1. **First-time setup friction**: Requires reading multiple documentation sections
   - No single "getting started" guide
   - Examples are scattered
   
2. **Public key management**: Finding and copying SSH public keys can be tedious
   - Especially for multiple hosts
   - **Recommendation**: Add helper commands to extract public keys from hosts
   
3. **Debugging decryption failures**: Limited visibility into why decryption fails
   - Could be wrong public key, missing identity file, corrupted secret, etc.
   - **Recommendation**: Add verbose mode to show which identity files are tried

4. **Multi-environment setups**: Managing secrets for dev/staging/prod requires planning
   - No built-in support for environment-specific secrets
   - **Recommendation**: Add examples for multi-environment patterns

### Recommendations for Improvement

#### High Priority

1. **Interactive wizard**: Create an `agenix init` command that:
   - Guides users through initial setup
   - Creates secrets.nix template
   - Helps find and add SSH public keys
   - Creates example secret

2. **Validation command**: Add `agenix check` to:
   - Validate secrets.nix syntax
   - Check that all defined secrets have corresponding .age files
   - Verify .age files are properly encrypted
   - Detect common configuration errors

3. **Better error messages**: Include suggestions in error messages:
   - "Secret failed to decrypt" → "Check that the host's SSH key is in secrets.nix publicKeys"
   - "File not found" → "Run 'agenix edit <name>' to create this secret"

#### Medium Priority

4. **Example templates**: Provide ready-to-use templates for:
   - Web application with database
   - Multi-tier application with shared secrets
   - Development/production environments
   - Home Manager setup

5. **Documentation improvements**:
   - Add a troubleshooting section with common issues
   - Create a migration guide from other secret management tools
   - Add more real-world examples beyond basic usage
   - Include performance considerations (how many secrets is reasonable?)

#### Lower Priority

6. **Helper commands**:
   - `agenix keyscan` to extract SSH public keys from hosts
   - `agenix list` to show all defined secrets and their status
   - `agenix rekey` to re-encrypt secrets with new keys

7. **Testing support**:
   - Built-in support for test fixtures
   - Example of how to test services that use secrets
   - CI/CD integration examples

### Success Metrics

Based on the testing, these scenarios work well:

✅ **Multiple secrets for one service** (e.g., database password, admin password, secret key)
✅ **Secrets with specific ownership** (different users/groups per secret)
✅ **Shared secrets** (same secret accessed by multiple services)
✅ **Fine-grained permissions** (0400, 0440, 0600, etc.)
✅ **Integration with existing NixOS modules** (services can reference secret paths)

### Conclusion

The agenix NixOS module provides a solid foundation for declarative secret management. The main areas for improvement are:

1. **Onboarding experience** - Make it easier for new users to get started
2. **Error handling** - Provide more helpful error messages and validation
3. **Documentation** - Add more examples and troubleshooting guidance

The module successfully handles all common use cases tested, and the declarative approach fits well with NixOS philosophy.
