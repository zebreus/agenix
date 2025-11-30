#!/usr/bin/env bash
# Test 10: Encrypt with age CLI, decrypt with agenix

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 10: Encrypt with age CLI, decrypt with agenix ==="
# Test interoperability: encrypt with age CLI, decrypt with agenix
echo "age-interop-test" > "$TMPDIR/test-message.txt"
age --secrets-nix "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" \
    -o "$TMPDIR/interop-secret.age" \
    "$TMPDIR/test-message.txt"

# Create a minimal secrets.nix for this test
cat > "$TMPDIR/interop-secrets.nix" << 'EOF'
{
  "interop-secret.age" = { publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ]; };
}
EOF

cd "$TMPDIR"
# Use TEST_USER_KEY environment variable provided by the test runner
decrypted=$(agenix decrypt interop-secret.age --secrets-nix "$TMPDIR/interop-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if [ "$decrypted" = "age-interop-test" ]; then
  echo "✓ Age CLI -> agenix interop works"
else
  echo "✗ Age CLI -> agenix interop failed: expected 'age-interop-test', got '$decrypted'"
  exit 1
fi
cd "$HOME/secrets"
