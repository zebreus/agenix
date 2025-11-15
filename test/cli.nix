# CLI Test Suite for agenix
#
# This test suite treats the agenix CLI as a blackbox, testing only the
# binary interface (commands and outputs). It can be used to verify any
# implementation of the agenix CLI, not just the default one.
#
# To use with an alternative implementation:
#   import ./test/cli.nix {
#     inherit nixpkgs;
#     pkgs = import nixpkgs { };
#     system = "x86_64-linux";
#     agenixPkg = myAlternativeAgenixImplementation;
#   }
#
{
  nixpkgs ? <nixpkgs>,
  pkgs ? import nixpkgs {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
  # Accept any package that provides an 'agenix' binary
  # This makes the test work with any CLI implementation
  agenixPkg ? pkgs.callPackage ../pkgs/agenix.nix { },
}:
pkgs.runCommand "agenix-cli-test"
  {
    nativeBuildInputs = [
      agenixPkg
      pkgs.age
      pkgs.diffutils
      pkgs.coreutils
      # pkgs.faketty # does not work
      # pkgs.stdoutisatty # does not work
      # pkgs.unixtools.script # only added for non-darwin as seen in test 6
    ];
  }
  ''
    set -euo pipefail

    # Test setup - create home directory and SSH keys
    export HOME="$TMPDIR/home"
    export TMPDIR="$TMPDIR/agenix-cli-test-tmp"
    mkdir -p $TMPDIR
    mkdir -p "$HOME/.ssh"
    cp ${../example_keys/user1.pub} "$HOME/.ssh/id_ed25519.pub"
    cp ${../example_keys/user1} "$HOME/.ssh/id_ed25519"
    chmod 644 "$HOME/.ssh/id_ed25519.pub"
    chmod 600 "$HOME/.ssh/id_ed25519"

    # Copy example secrets for testing
    cp -r ${../example} "$HOME/secrets"
    chmod -R u+rw "$HOME/secrets"

    cd "$HOME/secrets"

    echo "=== Test 1: Help command ==="
    # Temporarily disable pipefail for help command which can trigger SIGPIPE
    set +o pipefail
    help_output=$(agenix --help 2>&1)
    set -o pipefail
    if echo "$help_output" | grep -q "agenix - edit and rekey age secret files"; then
      echo "✓ Help command works"
    else
      echo "✗ Help command failed"
      exit 1
    fi

    echo "=== Test 2: Decrypt command ==="
    decrypted=$(agenix -d secret1.age)
    if [ "$decrypted" = "hello" ]; then
      echo "✓ Decrypt command works"
    else
      echo "✗ Decrypt failed: expected 'hello', got '$decrypted'"
      exit 1
    fi

    echo "=== Test 3: Decrypt with explicit identity ==="
    decrypted=$(agenix -d secret1.age -i "$HOME/.ssh/id_ed25519")
    if [ "$decrypted" = "hello" ]; then
      echo "✓ Decrypt with identity works"
    else
      echo "✗ Decrypt with identity failed"
      exit 1
    fi

    echo "=== Test 4: Decrypt secret2 (user-specific) ==="
    decrypted=$(agenix -d secret2.age)
    expected="world!"
    if [ "$decrypted" = "$expected" ]; then
      echo "✓ Decrypt secret2 works"
    else
      echo "✗ Decrypt secret2 failed: expected '$expected', got '$decrypted'"
      exit 1
    fi

    echo "=== Test 5: Edit via stdin (non-interactive) ==="
    echo "test-content-12345" | agenix -e secret1.age
    decrypted=$(agenix -d secret1.age)
    if [ "$decrypted" = "test-content-12345" ]; then
      echo "✓ Edit via stdin works"
    else
      echo "✗ Edit via stdin failed: got '$decrypted'"
      exit 1
    fi

    echo "=== Test 6: Rekey preserves content ==="
    ${
      if !pkgs.stdenv.isDarwin then
        ''
          # First, reset secret1.age to a known state
          echo "rekey-test-content" | agenix -e secret1.age

          # Verify it was set correctly
          before_decrypt=$(agenix -d secret1.age)
          if [ "$before_decrypt" != "rekey-test-content" ]; then
            echo "✗ Failed to set up secret1.age: got '$before_decrypt'"
            exit 1
          fi

          # Get hash before rekey
          before_hash=$(sha256sum secret1.age | cut -d' ' -f1)

          faketty () {
            ${pkgs.lib.getExe pkgs.unixtools.script} -qefc "$(printf "%q " "$@")" /dev/null
          }

          # Rekey only seems to work properly in a tty, so we use script to fake one
          faketty agenix --rekey

          # Get hash after rekey
          after_hash=$(sha256sum secret1.age | cut -d' ' -f1)
          if [ "$before_hash" != "$after_hash" ]; then
            echo "✓ Rekey changes file hash"
          else
            echo "✗ Rekey did not change file hash"
            exit 1
          fi

          # Verify content is preserved after rekey
          after_decrypt=$(agenix -d secret1.age)
          if [ "$after_decrypt" = "rekey-test-content" ]; then
            echo "✓ Content preserved after rekey"
          else
            echo "✗ Content not preserved after rekey: expected 'rekey-test-content', got '$after_decrypt'"
            exit 1
          fi
        ''
      else
        ''
          echo "Skipping rekey test on Darwin due to tty issues."
        ''
    }

    echo "=== Test 7: Decrypt armored secret ==="
    decrypted=$(agenix -d armored-secret.age)
    expected="Hello World!"
    if [ "$decrypted" = "$expected" ]; then
      echo "✓ Decrypt armored secret works"
    else
      echo "✗ Decrypt armored secret failed: expected '$expected', got '$decrypted'"
      exit 1
    fi

    echo "=== Test 8: Decrypt file with leading hyphen in name ==="
    # -- is not supported, so we need to do it without.
    # TODO: Add a test to verify that -- is not supported.
    decrypted=$(agenix -d -leading-hyphen-filename.age)
    expected="filename started with hyphen"
    if [ "$decrypted" = "$expected" ]; then
      echo "✓ Decrypt file with leading hyphen works"
    else
      echo "✗ Decrypt file with leading hyphen failed"
      exit 1
    fi

    echo "=== Test 9: Edit with explicit identity when bogus key present ==="
    # Set secret1.age to known content
    echo "test-content-12345" | agenix -e secret1.age

    echo "bogus" > "$HOME/.ssh/id_rsa"
    # This should fail without explicit identity
    if agenix -d secret1.age 2>/dev/null; then
      echo "✗ Should have failed with bogus id_rsa"
      exit 1
    fi
    # But should work with explicit identity
    decrypted=$(agenix -d secret1.age -i "$HOME/.ssh/id_ed25519")
    if [ "$decrypted" = "test-content-12345" ]; then
      echo "✓ Explicit identity overrides bogus key"
    else
      echo "✗ Explicit identity did not work with bogus key present"
      exit 1
    fi
    rm "$HOME/.ssh/id_rsa"

    echo "=== Test 10: Ensure temporary files are cleaned up ==="
    echo "secret-temp-test" | agenix -e secret1.age
    if grep -r "secret-temp-test" "$TMPDIR" 2>/dev/null; then
      echo "✗ Temporary files not cleaned up"
      exit 1
    else
      echo "✓ Temporary files properly cleaned up"
    fi

    echo ""
    echo "All CLI tests passed!"
    touch "$out"
  ''
