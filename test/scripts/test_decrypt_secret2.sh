#!/usr/bin/env bash
# Test 4: Decrypt secret2 (user-specific)

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 4: Decrypt secret2 (user-specific) ==="
decrypted=$(agenix -d secret2.age)
expected="world!"
if [ "$decrypted" = "$expected" ]; then
  echo "✓ Decrypt secret2 works"
else
  echo "✗ Decrypt secret2 failed: expected '$expected', got '$decrypted'"
  exit 1
fi
