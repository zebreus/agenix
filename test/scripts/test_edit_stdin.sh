#!/usr/bin/env bash
# Test 5: Edit via stdin (non-interactive)

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 5: Edit via stdin (non-interactive) ==="
echo "test-content-12345" | agenix -e secret1.age
decrypted=$(agenix -d secret1.age)
if [ "$decrypted" = "test-content-12345" ]; then
  echo "✓ Edit via stdin works"
else
  echo "✗ Edit via stdin failed: got '$decrypted'"
  exit 1
fi
