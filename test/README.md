# Agenix Test Infrastructure

This directory contains tests for agenix, organized by what they test.

## Test Organization

### CLI Tests (`cli.nix`)
Tests the agenix command-line interface as a **blackbox**:
- Tests only the binary interface (commands and their outputs)
- Independent of the agenix package implementation
- Can be used to verify alternative agenix CLI implementations
- Tests: `--help`, `--decrypt`, `--edit`, `--rekey`, etc.

**Key principle**: The test accepts any package that provides an `agenix` binary with the expected interface. It does not depend on or inspect the package implementation details.

### NixOS Module Tests (`integration.nix`)
Tests the NixOS module (`modules/age.nix`):
- Secret decryption and mounting at system activation
- Integration with NixOS system configuration
- Secret path management and permissions
- Tests files with special names (e.g., leading hyphens)

### Darwin Module Tests (`integration_darwin.nix`)
Tests the NixOS/Darwin module on macOS systems:
- System-level secret decryption on Darwin
- Darwin-specific activation scripts

### Home Manager Module Tests (`integration_hm_darwin.nix`)
Tests the home-manager module (`modules/age-home.nix`):
- User-level secret decryption
- Integration with home-manager configuration
- User-specific secret paths

## Helper Files

### `install_ssh_host_keys.nix`
Helper for Linux tests that sets up SSH keys needed for testing.

### `install_ssh_host_keys_darwin.nix`
Helper for Darwin tests that sets up SSH keys needed for testing.

## Running Tests

### Run all tests:
```bash
nix flake check
```

### Run specific test:
```bash
# CLI tests (Linux x86_64)
nix build .#checks.x86_64-linux.cli

# CLI tests (Linux ARM64)
nix build .#checks.aarch64-linux.cli

# CLI tests (Darwin x86_64)
nix build .#checks.x86_64-darwin.cli

# CLI tests (Darwin ARM64)
nix build .#checks.aarch64-darwin.cli

# NixOS module tests
nix build .#checks.x86_64-linux.integration

# Darwin module tests
nix build .#checks.x86_64-darwin.integration
nix build .#checks.aarch64-darwin.integration
```

## Design Principles

1. **Separation of Concerns**: CLI tests are separate from module tests
2. **Blackbox Testing**: CLI is tested only through its public interface
3. **Implementation Agnostic**: CLI tests work with any implementation that provides the expected binary interface
4. **Focused Testing**: Each test file has a clear, specific purpose
