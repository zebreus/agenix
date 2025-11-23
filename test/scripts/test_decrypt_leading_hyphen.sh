#!/usr/bin/env bash
# Test 8: Decrypt file with leading hyphen in name

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 8: Decrypt file with leading hyphen in name ==="
# -- is not supported, so we need to do it without.
# TODO: Add a test to verify that -- is not supported.
decrypted=$(agenix -d -leading-hyphen-filename.age)
expected="filename started with hyphen"
if [ "$decrypted" = "$expected" ]; then
  echo "✓ Decrypt file with leading hyphen works"
else
  echo "✗ Decrypt file with leading hyphen failed"
  exit 1
fi
