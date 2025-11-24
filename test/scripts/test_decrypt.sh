#!/usr/bin/env bash
# Test 2: Decrypt command

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 2: Decrypt command ==="
decrypted=$(agenix decrypt secret1.age)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Decrypt command works"
else
  echo "✗ Decrypt failed: expected 'hello', got '$decrypted'"
  exit 1
fi
