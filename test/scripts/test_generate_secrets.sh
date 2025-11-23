#!/usr/bin/env bash
# Test 11: Generate secrets

source "$(dirname "$0")/common_setup.sh"

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
# Use TEST_USER_KEY environment variable provided by the test runner
decrypted_fixed=$(agenix -d fixed-secret.age --rules "$TMPDIR/generate-test/generate-secrets.nix" -i "$TEST_USER_KEY")
if [ "$decrypted_fixed" = "fixed-password-123" ]; then
  echo "✓ Generated fixed secret decrypts correctly"
else
  echo "✗ Generated fixed secret decryption failed: got '$decrypted_fixed'"
  exit 1
fi

cd "$HOME/secrets"
