#!/usr/bin/env bash
# Test: Direct expression generators (non-function generators)
# This tests that `generator = "value"` works in addition to `generator = {}: "value"`

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Direct expression generators ==="
# Create a temporary directory for generated secrets
mkdir -p "$TMPDIR/direct-expr-test"
cd "$TMPDIR/direct-expr-test"

# Create a rules file with direct expression generators (no functions)
cat > "direct-expr-secrets.nix" << 'EOF'
{
  # Direct string expression (instead of `generator = {}: "value"`)
  "direct-string.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = "my-direct-string-secret";
  };
  # Direct attrset expression with secret and public
  "direct-attrset.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = { secret = "direct-secret-part"; public = "direct-public-part"; };
  };
  # Direct builtins.sshKey call (instead of `generator = builtins.sshKey`)
  "direct-ssh-call.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = builtins.sshKey {};
  };
  # Direct builtins.randomString call (instead of `generator = {}: builtins.randomString 16`)
  "direct-random.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = builtins.randomString 16;
  };
  # Direct builtins.ageKey call
  "direct-age-key.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = builtins.ageKey {};
  };
  # Function-based generator still works (existing behavior)
  "func-based.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: "function-based-secret";
  };
  # No generator - should not be auto-generated (name doesn't match patterns)
  "no-generator.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

# Run generate command
agenix generate --secrets-nix "$TMPDIR/direct-expr-test/direct-expr-secrets.nix"

# Test 1: Direct string generator
if [ -f "direct-string.age" ]; then
  echo "✓ Direct string secret generated"
else
  echo "✗ Direct string secret not generated"
  exit 1
fi

decrypted=$(agenix decrypt direct-string.age --secrets-nix "$TMPDIR/direct-expr-test/direct-expr-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "my-direct-string-secret" ]; then
  echo "✓ Direct string secret decrypts correctly"
else
  echo "✗ Direct string secret decryption failed: got '$decrypted'"
  exit 1
fi

# Test 2: Direct attrset generator
if [ -f "direct-attrset.age" ] && [ -f "direct-attrset.age.pub" ]; then
  echo "✓ Direct attrset secret and public key generated"
else
  echo "✗ Direct attrset secret or public key not generated"
  exit 1
fi

decrypted=$(agenix decrypt direct-attrset.age --secrets-nix "$TMPDIR/direct-expr-test/direct-expr-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "direct-secret-part" ]; then
  echo "✓ Direct attrset secret decrypts correctly"
else
  echo "✗ Direct attrset secret decryption failed: got '$decrypted'"
  exit 1
fi

public_content=$(cat "direct-attrset.age.pub")
if [ "$public_content" = "direct-public-part" ]; then
  echo "✓ Direct attrset public key contains correct content"
else
  echo "✗ Direct attrset public key incorrect: got '$public_content'"
  exit 1
fi

# Test 3: Direct SSH key call
if [ -f "direct-ssh-call.age" ] && [ -f "direct-ssh-call.age.pub" ]; then
  echo "✓ Direct SSH key call generated with public key"
else
  echo "✗ Direct SSH key call not generated properly"
  exit 1
fi

decrypted=$(agenix decrypt direct-ssh-call.age --secrets-nix "$TMPDIR/direct-expr-test/direct-expr-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if echo "$decrypted" | grep -q "BEGIN PRIVATE KEY"; then
  echo "✓ Direct SSH key call produces valid private key"
else
  echo "✗ Direct SSH key call decryption failed"
  exit 1
fi

ssh_pub=$(cat "direct-ssh-call.age.pub")
if echo "$ssh_pub" | grep -q "^ssh-ed25519 "; then
  echo "✓ Direct SSH key call public key has correct format"
else
  echo "✗ Direct SSH key call public key format incorrect: got '$ssh_pub'"
  exit 1
fi

# Test 4: Direct random string call
if [ -f "direct-random.age" ]; then
  echo "✓ Direct random string secret generated"
else
  echo "✗ Direct random string secret not generated"
  exit 1
fi

decrypted=$(agenix decrypt direct-random.age --secrets-nix "$TMPDIR/direct-expr-test/direct-expr-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
decrypted_len=${#decrypted}
if [ "$decrypted_len" = "16" ]; then
  echo "✓ Direct random string has correct length (16 chars)"
else
  echo "✗ Direct random string has wrong length: got $decrypted_len chars"
  exit 1
fi

# Test 5: Direct age key call
if [ -f "direct-age-key.age" ] && [ -f "direct-age-key.age.pub" ]; then
  echo "✓ Direct age key call generated with public key"
else
  echo "✗ Direct age key call not generated properly"
  exit 1
fi

decrypted=$(agenix decrypt direct-age-key.age --secrets-nix "$TMPDIR/direct-expr-test/direct-expr-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if echo "$decrypted" | grep -q "^AGE-SECRET-KEY-"; then
  echo "✓ Direct age key call produces valid age secret key"
else
  echo "✗ Direct age key call decryption failed"
  exit 1
fi

age_pub=$(cat "direct-age-key.age.pub")
if echo "$age_pub" | grep -q "^age1"; then
  echo "✓ Direct age key call public key has correct format"
else
  echo "✗ Direct age key call public key format incorrect: got '$age_pub'"
  exit 1
fi

# Test 6: Function-based generator still works
if [ -f "func-based.age" ]; then
  echo "✓ Function-based secret generated"
else
  echo "✗ Function-based secret not generated"
  exit 1
fi

decrypted=$(agenix decrypt func-based.age --secrets-nix "$TMPDIR/direct-expr-test/direct-expr-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "function-based-secret" ]; then
  echo "✓ Function-based secret decrypts correctly"
else
  echo "✗ Function-based secret decryption failed: got '$decrypted'"
  exit 1
fi

# Test 7: No generator should not create file
if [ ! -f "no-generator.age" ]; then
  echo "✓ Secret without generator correctly not created"
else
  echo "✗ Secret without generator was incorrectly created"
  exit 1
fi

cd "$HOME/secrets"
