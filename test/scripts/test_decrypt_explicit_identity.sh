#!/usr/bin/env bash
# Test 3: Decrypt with explicit identity

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 3: Decrypt with explicit identity ==="
decrypted=$(agenix -d secret1.age -i "$HOME/.ssh/id_ed25519")
if [ "$decrypted" = "hello" ]; then
  echo "✓ Decrypt with identity works"
else
  echo "✗ Decrypt with identity failed"
  exit 1
fi
