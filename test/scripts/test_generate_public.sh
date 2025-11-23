#!/usr/bin/env bash
# Test 11.5: Generate secrets with public output

source "$(dirname "$0")/common_setup.sh"

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
    generator = builtins.sshKey;
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
# Use TEST_USER_KEY environment variable provided by the test runner
decrypted_string=$(agenix -d string-only.age --rules "$TMPDIR/generate-public-test/generate-public-secrets.nix" -i "$TEST_USER_KEY")
if [ "$decrypted_string" = "just-a-secret-string" ]; then
  echo "✓ String-only secret decrypts correctly"
else
  echo "✗ String-only secret decryption failed: got '$decrypted_string'"
  exit 1
fi

decrypted_with_pub=$(agenix -d with-public.age --rules "$TMPDIR/generate-public-test/generate-public-secrets.nix" -i "$TEST_USER_KEY")
if [ "$decrypted_with_pub" = "my-secret-value" ]; then
  echo "✓ Secret with public output decrypts correctly"
else
  echo "✗ Secret with public output decryption failed: got '$decrypted_with_pub'"
  exit 1
fi

cd "$HOME/secrets"
