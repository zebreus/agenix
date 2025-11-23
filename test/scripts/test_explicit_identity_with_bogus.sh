#!/usr/bin/env bash
# Test 9: Edit with explicit identity when bogus key present

source "$(dirname "$0")/common_setup.sh"

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
