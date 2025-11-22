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
  pkgs ? import <nixpkgs> {
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
        cp ${./example_keys/user1.pub} "$HOME/.ssh/id_ed25519.pub"
        cp ${./example_keys/user1} "$HOME/.ssh/id_ed25519"
        chmod 644 "$HOME/.ssh/id_ed25519.pub"
        chmod 600 "$HOME/.ssh/id_ed25519"

        # Copy example secrets for testing
        cp -r ${./example} "$HOME/secrets"
        chmod -R u+rw "$HOME/secrets"

        cd "$HOME/secrets"

        echo "=== Test 1: Help command ==="
        # Temporarily disable pipefail for help command which can trigger SIGPIPE
        set +o pipefail
        help_output=$(agenix --help 2>&1)
        set -o pipefail
        if echo "$help_output" | grep -q "edit and rekey age secret files"; then
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

        echo "=== Test 10: Encrypt with age CLI, decrypt with agenix ==="
        # Test interoperability: encrypt with age CLI, decrypt with agenix
        echo "age-interop-test" > "$TMPDIR/test-message.txt"
        age -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" \
            -o "$TMPDIR/interop-secret.age" \
            "$TMPDIR/test-message.txt"
        
        # Create a minimal secrets.nix for this test
        cat > "$TMPDIR/interop-secrets.nix" << 'EOF'
    {
      "interop-secret.age" = { publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ]; };
    }
    EOF

        cd "$TMPDIR"
        decrypted=$(agenix -d interop-secret.age --rules "$TMPDIR/interop-secrets.nix" -i ${./example_keys/user1})
        if [ "$decrypted" = "age-interop-test" ]; then
          echo "✓ Age CLI -> agenix interop works"
        else
          echo "✗ Age CLI -> agenix interop failed: expected 'age-interop-test', got '$decrypted'"
          exit 1
        fi
        cd "$HOME/secrets"

        echo "=== Test 11: Generate secrets ==="
        # Create a temporary directory for generated secrets
        mkdir -p "$TMPDIR/generate-test"
        cd "$TMPDIR/generate-test"

        # Create a rules file with generators
        cat > "generate-secrets.nix" << 'EOF'
    {
      "fixed-secret.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
        generator = {}: "fixed-password-123";
      };
      "random-secret.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
        generator = {}: builtins.randomString 32;
      };
      "no-generator.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
      };
    }
    EOF

        # Run generate command with absolute path
        agenix --generate --rules "$TMPDIR/generate-test/generate-secrets.nix"
        
        # Check that files with generators were created
        if [ -f "fixed-secret.age" ]; then
          echo "✓ Fixed secret generated"
        else
          echo "✗ Fixed secret not generated"
          exit 1
        fi
        
        if [ -f "random-secret.age" ]; then
          echo "✓ Random secret generated"
        else
          echo "✗ Random secret not generated"
          exit 1
        fi
        
        # Check that file without generator was not created
        if [ ! -f "no-generator.age" ]; then
          echo "✓ Secret without generator correctly not created"
        else
          echo "✗ Secret without generator was incorrectly created"
          exit 1
        fi

        # Verify we can decrypt the generated secrets
        decrypted_fixed=$(agenix -d fixed-secret.age --rules "$TMPDIR/generate-test/generate-secrets.nix" -i ${./example_keys/user1})
        if [ "$decrypted_fixed" = "fixed-password-123" ]; then
          echo "✓ Generated fixed secret decrypts correctly"
        else
          echo "✗ Generated fixed secret decryption failed: got '$decrypted_fixed'"
          exit 1
        fi

        cd "$HOME/secrets"

        echo "=== Test 11.5: Generate secrets with public output ==="
        # Create a temporary directory for generated secrets with public output
        mkdir -p "$TMPDIR/generate-public-test"
        cd "$TMPDIR/generate-public-test"

        # Create a rules file with generators that produce public output
        cat > "generate-public-secrets.nix" << 'EOF'
    {
      "string-only.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
        generator = {}: "just-a-secret-string";
      };
      "with-public.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
        generator = {}: { secret = "my-secret-value"; public = "my-public-value"; };
      };
      "secret-only-attrset.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
        generator = {}: { secret = "only-secret-in-attrset"; };
      };
      "ssh-keypair.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
        generator = {}: 
          let keypair = builtins.sshKey {};
          in { secret = keypair.private; public = keypair.public; };
      };
    }
    EOF

        # Run generate command
        agenix --generate --rules "$TMPDIR/generate-public-test/generate-public-secrets.nix"
        
        # Test 1: String-only generator should create .age file but no .pub file
        if [ -f "string-only.age" ]; then
          echo "✓ String-only secret generated"
        else
          echo "✗ String-only secret not generated"
          exit 1
        fi
        
        if [ ! -f "string-only.age.pub" ]; then
          echo "✓ String-only secret has no .pub file (correct)"
        else
          echo "✗ String-only secret has unexpected .pub file"
          exit 1
        fi
        
        # Test 2: Generator with public output should create both .age and .pub files
        if [ -f "with-public.age" ]; then
          echo "✓ Secret with public output generated"
        else
          echo "✗ Secret with public output not generated"
          exit 1
        fi
        
        if [ -f "with-public.age.pub" ]; then
          echo "✓ Public file created for secret with public output"
        else
          echo "✗ Public file not created for secret with public output"
          exit 1
        fi
        
        # Verify the content of the public file
        public_content=$(cat "with-public.age.pub")
        if [ "$public_content" = "my-public-value" ]; then
          echo "✓ Public file contains correct content"
        else
          echo "✗ Public file content incorrect: got '$public_content'"
          exit 1
        fi
        
        # Test 3: Attrset with only secret should not create .pub file
        if [ -f "secret-only-attrset.age" ]; then
          echo "✓ Secret-only attrset generated"
        else
          echo "✗ Secret-only attrset not generated"
          exit 1
        fi
        
        if [ ! -f "secret-only-attrset.age.pub" ]; then
          echo "✓ Secret-only attrset has no .pub file (correct)"
        else
          echo "✗ Secret-only attrset has unexpected .pub file"
          exit 1
        fi
        
        # Test 4: SSH keypair should create both .age and .pub files
        if [ -f "ssh-keypair.age" ]; then
          echo "✓ SSH keypair secret generated"
        else
          echo "✗ SSH keypair secret not generated"
          exit 1
        fi
        
        if [ -f "ssh-keypair.age.pub" ]; then
          echo "✓ SSH keypair public file created"
        else
          echo "✗ SSH keypair public file not created"
          exit 1
        fi
        
        # Verify the SSH public key format
        ssh_public=$(cat "ssh-keypair.age.pub")
        if echo "$ssh_public" | grep -q "^ssh-ed25519 "; then
          echo "✓ SSH public key has correct format"
        else
          echo "✗ SSH public key format incorrect: got '$ssh_public'"
          exit 1
        fi
        
        # Verify we can decrypt the secrets
        decrypted_string=$(agenix -d string-only.age --rules "$TMPDIR/generate-public-test/generate-public-secrets.nix" -i ${./example_keys/user1})
        if [ "$decrypted_string" = "just-a-secret-string" ]; then
          echo "✓ String-only secret decrypts correctly"
        else
          echo "✗ String-only secret decryption failed: got '$decrypted_string'"
          exit 1
        fi
        
        decrypted_with_pub=$(agenix -d with-public.age --rules "$TMPDIR/generate-public-test/generate-public-secrets.nix" -i ${./example_keys/user1})
        if [ "$decrypted_with_pub" = "my-secret-value" ]; then
          echo "✓ Secret with public output decrypts correctly"
        else
          echo "✗ Secret with public output decryption failed: got '$decrypted_with_pub'"
          exit 1
        fi

        cd "$HOME/secrets"

        echo "=== Test 11.75: Automatic generator selection based on secret endings ==="
        # Create a temporary directory for auto-generated secrets
        mkdir -p "$TMPDIR/auto-generate-test"
        cd "$TMPDIR/auto-generate-test"

        # Create a rules file without explicit generators
        cat > "auto-generate-secrets.nix" << 'EOF'
    {
      "server-ed25519.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
      };
      "deploy-ssh.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
      };
      "id_ssh_key.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
      };
      "database-password.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
      };
      "backup-passphrase.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
      };
      "random-secret.age" = {
        publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
      };
    }
    EOF

        # Run generate command
        agenix --generate --rules "$TMPDIR/auto-generate-test/auto-generate-secrets.nix"
        
        # Check that SSH key files were created with .pub files
        if [ -f "server-ed25519.age" ] && [ -f "server-ed25519.age.pub" ]; then
          echo "✓ server-ed25519.age generated with public key"
        else
          echo "✗ server-ed25519.age or its public key not generated"
          exit 1
        fi
        
        if [ -f "deploy-ssh.age" ] && [ -f "deploy-ssh.age.pub" ]; then
          echo "✓ deploy-ssh.age generated with public key"
        else
          echo "✗ deploy-ssh.age or its public key not generated"
          exit 1
        fi
        
        if [ -f "id_ssh_key.age" ] && [ -f "id_ssh_key.age.pub" ]; then
          echo "✓ id_ssh_key.age generated with public key"
        else
          echo "✗ id_ssh_key.age or its public key not generated"
          exit 1
        fi
        
        # Check that password files were created without .pub files
        if [ -f "database-password.age" ] && [ ! -f "database-password.age.pub" ]; then
          echo "✓ database-password.age generated without public key"
        else
          echo "✗ database-password.age incorrectly generated"
          exit 1
        fi
        
        if [ -f "backup-passphrase.age" ] && [ ! -f "backup-passphrase.age.pub" ]; then
          echo "✓ backup-passphrase.age generated without public key"
        else
          echo "✗ backup-passphrase.age incorrectly generated"
          exit 1
        fi
        
        # Check that file without matching ending was not created
        if [ ! -f "random-secret.age" ]; then
          echo "✓ random-secret.age correctly not auto-generated"
        else
          echo "✗ random-secret.age was incorrectly auto-generated"
          exit 1
        fi

        # Verify SSH keys have correct format
        ssh_pub=$(cat "server-ed25519.age.pub")
        if echo "$ssh_pub" | grep -q "^ssh-ed25519 "; then
          echo "✓ SSH public key has correct format"
        else
          echo "✗ SSH public key format incorrect: got '$ssh_pub'"
          exit 1
        fi

        # Verify we can decrypt the auto-generated secrets
        decrypted_ssh=$(agenix -d server-ed25519.age --rules "$TMPDIR/auto-generate-test/auto-generate-secrets.nix" -i ${./example_keys/user1})
        if echo "$decrypted_ssh" | grep -q "BEGIN PRIVATE KEY"; then
          echo "✓ Auto-generated SSH key decrypts correctly"
        else
          echo "✗ Auto-generated SSH key decryption failed"
          exit 1
        fi
        
        decrypted_password=$(agenix -d database-password.age --rules "$TMPDIR/auto-generate-test/auto-generate-secrets.nix" -i ${./example_keys/user1})
        password_len=''${#decrypted_password}
        if [ "$password_len" = "32" ]; then
          echo "✓ Auto-generated password has correct length (32 chars)"
        else
          echo "✗ Auto-generated password has wrong length: got $password_len chars"
          exit 1
        fi

        cd "$HOME/secrets"

        echo "=== Test 12: Ensure temporary files are cleaned up ==="
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
