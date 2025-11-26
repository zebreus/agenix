#!/usr/bin/env bash
# Test: Encrypt command basic functionality

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Encrypt command basic functionality ==="

# Test 1: Create a new secret with encrypt
NEW_SECRET="$TMPDIR/new-secret.age"

# Create a temporary rules file that includes our new secret using the test user's key
TEMP_RULES="$TMPDIR/temp-secrets.nix"
cat > "$TEMP_RULES" << EOF
{
  "$NEW_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

echo "new-secret-content" | agenix encrypt -r "$TEMP_RULES" "$NEW_SECRET"

if [ ! -f "$NEW_SECRET" ]; then
  echo "✗ Encrypt failed: file not created"
  exit 1
fi

# Decrypt and verify
decrypted=$(agenix decrypt -r "$TEMP_RULES" "$NEW_SECRET")
if [ "$decrypted" = "new-secret-content" ]; then
  echo "✓ Encrypt command works"
else
  echo "✗ Encrypt verification failed: expected 'new-secret-content', got '$decrypted'"
  exit 1
fi

# Test 2: Encrypt should fail if file exists without --force
if echo "overwrite-attempt" | agenix encrypt -r "$TEMP_RULES" "$NEW_SECRET" 2>/dev/null; then
  echo "✗ Encrypt should fail when file exists without --force"
  exit 1
else
  echo "✓ Encrypt correctly refuses to overwrite without --force"
fi

# Test 3: Encrypt with --force should overwrite
echo "forced-overwrite" | agenix encrypt -r "$TEMP_RULES" --force "$NEW_SECRET"
decrypted=$(agenix decrypt -r "$TEMP_RULES" "$NEW_SECRET")
if [ "$decrypted" = "forced-overwrite" ]; then
  echo "✓ Encrypt --force overwrites correctly"
else
  echo "✗ Encrypt --force verification failed: expected 'forced-overwrite', got '$decrypted'"
  exit 1
fi

echo "All encrypt tests passed!"
