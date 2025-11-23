# CLI Test Scripts

This directory contains individual test scripts for the agenix CLI. Each script tests a specific aspect of the CLI functionality.

## Structure

- **common_setup.sh**: Shared setup and utility functions for all test scripts
- **test_*.sh**: Individual test scripts for specific CLI features

## Test Scripts

1. **test_help.sh** - Tests the help command output
2. **test_decrypt.sh** - Tests basic decryption functionality
3. **test_decrypt_explicit_identity.sh** - Tests decryption with explicit identity flag
4. **test_decrypt_secret2.sh** - Tests decryption of user-specific secrets
5. **test_edit_stdin.sh** - Tests editing secrets via stdin (non-interactive)
6. **test_rekey.sh** - Tests rekeying secrets while preserving content
7. **test_decrypt_armored.sh** - Tests decryption of armored secrets
8. **test_decrypt_leading_hyphen.sh** - Tests handling of filenames with leading hyphens
9. **test_explicit_identity_with_bogus.sh** - Tests explicit identity override when bogus keys are present
10. **test_age_interop.sh** - Tests interoperability between age CLI and agenix
11. **test_generate_secrets.sh** - Tests secret generation with explicit generators
12. **test_generate_public.sh** - Tests secret generation with public output
13. **test_auto_generate.sh** - Tests automatic generator selection based on secret name patterns
14. **test_temp_cleanup.sh** - Tests temporary file cleanup

## Running Tests

Tests are run automatically via `test/cli.nix` which:
1. Sets up the test environment (SSH keys, example secrets, etc.)
2. Runs each test script in order
3. Reports success or failure

To run the tests manually:
```bash
nix build .#checks.x86_64-linux.cli
```

## Environment Variables

The test runner sets up these environment variables:
- `HOME` - Test home directory
- `TMPDIR` - Temporary directory for test artifacts
- `TEST_USER_KEY` - Path to the test user's SSH key

## Adding New Tests

To add a new test:
1. Create a new script in this directory following the naming pattern `test_*.sh`
2. Source `common_setup.sh` at the beginning
3. Add the script name to the `testScripts` list in `test/cli.nix`

Note: The build will fail if there are `test_*.sh` scripts in this directory that are not included in the `testScripts` list.
