#!/usr/bin/env bash
# Test: Generator output variations (public-only, secret-only, both)
# This tests the new functionality that allows generators to return
# just {public = ...} without a secret

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Generator output variations ==="

# Create a temporary directory for generated secrets
mkdir -p "$TMPDIR/generator-variations"
cd "$TMPDIR/generator-variations"

# Create a rules file with various generator output patterns
cat > "generator-variations.nix" << 'EOF'
{
  # Public-only generator - should create .pub file but no .age file
  "public-only.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { public = "my-public-metadata"; };
  };
  
  # Secret-only attrset generator - should create .age file but no .pub file
  "secret-only-attrset.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { secret = "my-secret-only"; };
  };
  
  # String generator - should create .age file but no .pub file
  "string-generator.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: "plain-string-secret";
  };
  
  # Both secret and public - should create both .age and .pub files
  "both-outputs.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { secret = "my-secret"; public = "my-public"; };
  };
  
  # Dependency that uses public from public-only generator
  "uses-public-only.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    dependencies = [ "public-only" ];
    generator = { publics }: "derived-from-" + publics."public-only";
  };
}
EOF

# Run generate command
agenix generate --secrets-nix "$TMPDIR/generator-variations/generator-variations.nix"

# Test 1: Public-only generator creates .pub but not .age
if [ -f "public-only.age.pub" ]; then
  echo "✓ Public-only: .pub file created"
else
  echo "✗ Public-only: .pub file not created"
  exit 1
fi

if [ ! -f "public-only.age" ]; then
  echo "✓ Public-only: .age file NOT created (correct)"
else
  echo "✗ Public-only: .age file was incorrectly created"
  exit 1
fi

# Verify public content
public_content=$(cat "public-only.age.pub")
if [ "$public_content" = "my-public-metadata" ]; then
  echo "✓ Public-only: content is correct"
else
  echo "✗ Public-only: content incorrect: got '$public_content'"
  exit 1
fi

# Test 2: Secret-only attrset generator creates .age but not .pub
if [ -f "secret-only-attrset.age" ]; then
  echo "✓ Secret-only attrset: .age file created"
else
  echo "✗ Secret-only attrset: .age file not created"
  exit 1
fi

if [ ! -f "secret-only-attrset.age.pub" ]; then
  echo "✓ Secret-only attrset: .pub file NOT created (correct)"
else
  echo "✗ Secret-only attrset: .pub file was incorrectly created"
  exit 1
fi

# Verify secret content
decrypted=$(agenix decrypt secret-only-attrset.age --secrets-nix "$TMPDIR/generator-variations/generator-variations.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "my-secret-only" ]; then
  echo "✓ Secret-only attrset: decrypts correctly"
else
  echo "✗ Secret-only attrset: decryption failed: got '$decrypted'"
  exit 1
fi

# Test 3: String generator creates .age but not .pub
if [ -f "string-generator.age" ]; then
  echo "✓ String generator: .age file created"
else
  echo "✗ String generator: .age file not created"
  exit 1
fi

if [ ! -f "string-generator.age.pub" ]; then
  echo "✓ String generator: .pub file NOT created (correct)"
else
  echo "✗ String generator: .pub file was incorrectly created"
  exit 1
fi

decrypted=$(agenix decrypt string-generator.age --secrets-nix "$TMPDIR/generator-variations/generator-variations.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "plain-string-secret" ]; then
  echo "✓ String generator: decrypts correctly"
else
  echo "✗ String generator: decryption failed: got '$decrypted'"
  exit 1
fi

# Test 4: Both outputs creates both files
if [ -f "both-outputs.age" ] && [ -f "both-outputs.age.pub" ]; then
  echo "✓ Both outputs: both files created"
else
  echo "✗ Both outputs: one or both files missing"
  exit 1
fi

decrypted=$(agenix decrypt both-outputs.age --secrets-nix "$TMPDIR/generator-variations/generator-variations.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "my-secret" ]; then
  echo "✓ Both outputs: secret decrypts correctly"
else
  echo "✗ Both outputs: secret decryption failed: got '$decrypted'"
  exit 1
fi

public_content=$(cat "both-outputs.age.pub")
if [ "$public_content" = "my-public" ]; then
  echo "✓ Both outputs: public content is correct"
else
  echo "✗ Both outputs: public content incorrect: got '$public_content'"
  exit 1
fi

# Test 5: Dependency on public-only generator works
if [ -f "uses-public-only.age" ]; then
  echo "✓ Dependency on public-only: .age file created"
else
  echo "✗ Dependency on public-only: .age file not created"
  exit 1
fi

decrypted=$(agenix decrypt uses-public-only.age --secrets-nix "$TMPDIR/generator-variations/generator-variations.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "derived-from-my-public-metadata" ]; then
  echo "✓ Dependency on public-only: correctly uses public from dependency"
else
  echo "✗ Dependency on public-only: incorrect content: got '$decrypted'"
  exit 1
fi

echo "=== All generator output variation tests passed ==="
cd "$HOME/secrets"
