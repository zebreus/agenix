#!/usr/bin/env bash
# Test 5: Encrypt via stdin (non-interactive)

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 5: Encrypt via stdin (non-interactive) ==="
echo "test-content-12345" | agenix encrypt --force secret1.age
decrypted=$(agenix decrypt secret1.age)
if [ "$decrypted" = "test-content-12345" ]; then
  echo "✓ Encrypt via stdin works"
else
  echo "✗ Encrypt via stdin failed: got '$decrypted'"
  exit 1
fi
