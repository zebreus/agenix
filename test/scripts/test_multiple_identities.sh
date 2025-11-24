#!/usr/bin/env bash
# Test: Multiple identities with -i flag

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Multiple identities with -i flag ==="

# Test that multiple -i flags work (first matching identity is used)
# Create a temporary additional key
mkdir -p "$TMPDIR/extra-keys"
ssh-keygen -t ed25519 -f "$TMPDIR/extra-keys/extra_key" -N "" -q

# Use the correct key first - should succeed
decrypted=$(agenix decrypt secret1.age -i "$HOME/.ssh/id_ed25519" -i "$TMPDIR/extra-keys/extra_key" --no-system-identities)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Multiple identities with correct key first works"
else
  echo "✗ Multiple identities with correct key first failed"
  exit 1
fi

# Use wrong key first, correct key second - should still succeed
decrypted=$(agenix decrypt secret1.age -i "$TMPDIR/extra-keys/extra_key" -i "$HOME/.ssh/id_ed25519" --no-system-identities)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Multiple identities with correct key second works"
else
  echo "✗ Multiple identities with correct key second failed"
  exit 1
fi

# Clean up
rm -rf "$TMPDIR/extra-keys"

echo "✓ All multiple identities tests passed"
