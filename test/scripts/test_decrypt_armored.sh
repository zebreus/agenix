#!/usr/bin/env bash
# Test 7: Decrypt armored secret

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 7: Decrypt armored secret ==="
decrypted=$(agenix decrypt armored-secret.age)
expected="Hello World!"
if [ "$decrypted" = "$expected" ]; then
  echo "✓ Decrypt armored secret works"
else
  echo "✗ Decrypt armored secret failed: expected '$expected', got '$decrypted'"
  exit 1
fi
